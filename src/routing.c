#include <mptcpd/plugin.h>
#include <mptcpd/network_monitor.h>

#include <ell/util.h>
#include <ell/log.h>

#include <libmnl/libmnl.h>

#include <linux/rtnetlink.h>

#include <assert.h>
#include <stdlib.h>

#include <routing/private/mnl_ops.h>
#include <routing/private/handler.h>

static struct l_queue *info;

// ----------------------------------------------------------------------

static bool index_match(void const *a, void const *b)
{
        assert(a);
        assert(b);

        struct if_rt_info const *const if_info = a;
        uint32_t const *const index = b;
        
        return if_info->index == *index;
}

static bool address_match(void const *a, void const *b)
{
        assert(a);
        assert(b);

        struct addr_info const *const addr = a;
        struct sockaddr const *const sa = b;

        bool match = addr->family == sa->sa_family;
        if (!match)
                return match;

        match = addr->family == AF_INET ?

                ((struct sockaddr_in *) sa)->sin_addr.s_addr ==
                        addr->addr.ipv4.s_addr :

                (memcmp(&addr->addr.ipv6,
                 &((struct sockaddr_in6 *) sa)->sin6_addr,
                 sizeof(struct in6_addr)) == 0);
        
        return match;
}

static inline bool is_link_local(struct in6_addr *addr)
{
       return (addr->__in6_u.__u6_addr8[0] & 0xc0) == 0x80 && 
               addr->__in6_u.__u6_addr8[1] == 0xfe;

}

static struct if_rt_info *if_rt_info_init(uint32_t index)
{
        struct if_rt_info *if_info = l_new(struct if_rt_info, 1);

        if_info->dst_ipv4 = l_queue_new();
        if_info->gw4 = NULL;

        if_info->dst_ipv6 = l_queue_new();
        if_info->gw6 = NULL;

        if_info->addrs = l_queue_new();
        if_info->index = index;

        l_queue_push_tail(info, if_info);

        return if_info;
}

static bool add_gw(struct if_rt_info *if_info, uint8_t family, void *gw)
{
        if (family == AF_INET) {

                uint32_t gw_value = *(uint32_t *) gw;
                if (!if_info->gw4)
                        if_info->gw4 = l_new(struct in_addr, 1);

                else if (if_info->gw4->s_addr == gw_value)
                        return false;

                if_info->gw4->s_addr =  gw_value;
        }
        else{
                if (!if_info->gw6)
                        if_info->gw6 = l_new(struct in6_addr, 1);

                else if (!memcmp(gw,
                                 if_info->gw6,
                                 sizeof(struct in6_addr)) ||
                         (is_link_local(if_info->gw6) &&
                         !is_link_local(gw)))
                        return false;

                memcpy(if_info->gw6, gw, sizeof(struct in6_addr));
        }         

        return true;
}

static bool compare_dst(void const *a, void const *b)
{
        assert(a);
        assert(b);
        return memcmp(a, b, sizeof(struct dst_info)) == 0;
}

static bool add_dst(struct if_rt_info *if_info,
                    uint8_t family,
                    void *dst, 
                    uint8_t prefix_len)
{
        struct dst_info *dst_info = l_new(struct dst_info, 1);
        dst_info->prefix_len = prefix_len;

        struct l_queue *queue;

        if (family == AF_INET) {
                queue = if_info->dst_ipv4;
                dst_info->dst.ipv4.s_addr = *(uint32_t *) dst;
        } else {
                queue = if_info->dst_ipv6;
                memcpy(&dst_info->dst.ipv6, dst, sizeof(struct in6_addr));
        }

        if (!l_queue_find(queue, compare_dst, dst_info)){
                l_queue_push_tail(queue, dst_info);
                return true;
        }

        return false;
}


static void add_route(uint8_t family, 
                      uint8_t prefix_len,
                      struct nlattr const **tb)
{
        uint32_t index = mnl_attr_get_u32(tb[RTA_OIF]);

        struct if_rt_info *if_info =
                l_queue_find(info, index_match, &index);

        if (!if_info)
                if_info = if_rt_info_init(index);

        struct user_data data = {
                .oif = index,
                .family = family,
                .prefix_len = prefix_len
        };

        if (tb[RTA_GATEWAY]) {
                data.pointer = 
                        mnl_attr_get_payload(tb[RTA_GATEWAY]);

                if (add_gw(if_info, family, data.pointer))
                        l_queue_foreach(if_info->addrs, conf_gw, &data);
        }

        if (tb[RTA_DST]) {
                data.pointer = 
                        mnl_attr_get_payload(tb[RTA_DST]);

                if (add_dst(if_info,
                            family,
                            data.pointer,
                            data.prefix_len))
                        l_queue_foreach(if_info->addrs, conf_dst, &data);
        }
}


static bool rm_gw(struct if_rt_info *if_info, uint8_t family, void *gw)
{
        if (family == AF_INET &&
            if_info->gw4 && 
            if_info->gw4->s_addr == *(uint32_t *) gw) {

                l_free(if_info->gw4);
                if_info->gw4 = NULL;
                return true;

        } else if (if_info->gw6 && 
                   !memcmp(gw, if_info->gw6, sizeof(struct in6_addr))){

                l_free(if_info->gw6);
                if_info->gw6 = NULL;
                return true;
        }

        return false;
}

static bool rm_dst(struct if_rt_info *if_info,
                   uint8_t family,
                   void *dst,
                   uint8_t prefix_len)
{
        struct dst_info dst_info = {
                .prefix_len = prefix_len
        };
        struct l_queue *queue;

        if (family == AF_INET) {
                queue = if_info->dst_ipv4;
                dst_info.dst.ipv4.s_addr = *(uint32_t *) dst;
        } else {
                queue = if_info->dst_ipv6;
                memcpy(&dst_info.dst.ipv6, dst, sizeof(struct in6_addr));
        }

        struct dst_info *elem =
                l_queue_find(queue, compare_dst, &dst_info);

        if (elem) {
                l_queue_remove(queue, elem);
                l_free(elem);
                return true;
        }

        return false;
}

static void rm_route(uint8_t family,
                     uint8_t dst_len,
                     struct nlattr const **tb)
{
        uint32_t index = mnl_attr_get_u32(tb[RTA_OIF]);

        struct if_rt_info *if_i =
                l_queue_find(info, index_match, &index);

        struct user_data data = {
                .oif = index,
                .family = family,
                .prefix_len = dst_len
        };

        if (tb[RTA_GATEWAY]) {
                data.pointer = mnl_attr_get_payload(tb[RTA_GATEWAY]);

                if (rm_gw(if_i, family, data.pointer))
                        l_queue_foreach(if_i->addrs, deconf_gw, &data);
        }

        if (tb[RTA_DST]){
                data.pointer = mnl_attr_get_payload(tb[RTA_DST]);

                if (rm_dst(if_i, family, data.pointer, dst_len))
                        l_queue_foreach(if_i->addrs, deconf_dst, &data);
        } 
}

static void apply_ipv4_ops(struct addr_info *addr_info,
                           struct if_rt_info *if_info,
                           l_queue_foreach_func_t gw_op,
                           l_queue_foreach_func_t dst_op)
{
        struct user_data req_data = {
                .family = addr_info->family,
                .oif = if_info->index,
                .prefix_len = 0
        };

        if (if_info->gw4) {
                req_data.pointer = if_info->gw4;
                gw_op(addr_info, &req_data);
        }

        if (!l_queue_isempty(if_info->dst_ipv4)) {

                struct l_queue_entry const *entry = 
                        l_queue_get_entries(if_info->dst_ipv4);

                while (entry) {
                        struct dst_info *dst = entry->data;

                        req_data.prefix_len = dst->prefix_len;
                        req_data.pointer = &dst->dst.ipv4;

                        dst_op(addr_info, &req_data);

                        entry = entry->next;
                }
        }

}

static void apply_ipv6_ops(struct addr_info *addr_info,
                           struct if_rt_info *if_info,
                           l_queue_foreach_func_t gw_op,
                           l_queue_foreach_func_t dst_op)
{
        struct user_data req_data = {
                .family = addr_info->family,
                .oif = if_info->index,
                .prefix_len = 0
        };

        if (if_info->gw6) {
                req_data.pointer = if_info->gw6;
                gw_op(addr_info, &req_data);
        }

        if (!l_queue_isempty(if_info->dst_ipv6)) {

                struct l_queue_entry const *entry = 
                        l_queue_get_entries(if_info->dst_ipv6);

                while (entry) {
                        struct dst_info *dst = entry->data;

                        req_data.prefix_len = dst->prefix_len;
                        req_data.pointer = &dst->dst.ipv6;

                        dst_op(addr_info, &req_data);

                        entry = entry->next;
                }
        }
}

bool deconf_all(void *data, void *user_data)
{
        struct addr_info *addr_info = data;
        struct if_rt_info *if_info = user_data;

        if (addr_info->table_id == 0)
                return true;

        if (addr_info->family == AF_INET)
                apply_ipv4_ops(addr_info, if_info, deconf_gw, deconf_dst);

        else
                apply_ipv6_ops(addr_info, if_info, deconf_gw, deconf_dst);

        return true;
}

static void clear_info(void *data) 
{
        struct if_rt_info *if_info = data;

        l_queue_foreach_remove(if_info->addrs, deconf_all, data);
        l_queue_destroy(if_info->addrs, NULL);

        if (if_info->gw6)
                l_free(if_info->gw6);

        l_queue_destroy(if_info->dst_ipv6, l_free);

        if (if_info->gw4)
                l_free(if_info->gw4);

        l_queue_destroy(if_info->dst_ipv4, l_free);

        l_free(if_info);
}

// ----------------------------------------------------------------------

static bool routing_new_interface(struct mptcpd_interface const *i,
                                 struct mptcpd_pm *pm)
{
        (void) pm;

        struct if_rt_info *if_info = l_queue_find(info,
                                                  index_match,
                                                  &i->index);

        if (!if_info)
                if_info = if_rt_info_init(i->index);

        return true;
}

static bool routing_delete_interface(struct mptcpd_interface const *i,
                                     struct mptcpd_pm *pm)
{
        (void) pm;

        struct if_rt_info *if_info = l_queue_find(info,
                                                  index_match,
                                                  &i->index);

        l_queue_remove(info, if_info);

        clear_info(if_info);

        return true;
}

static bool routing_new_local_address(struct mptcpd_interface const *i,
                                      struct sockaddr const *sa,
                                      struct mptcpd_pm *pm)
{
        (void) pm;

        struct if_rt_info *if_info = l_queue_find(info,
                                                  index_match,
                                                  &i->index);

        if(!l_queue_find(if_info->addrs, address_match, sa)) {

                struct addr_info *addr =
                        l_new(struct addr_info, 1);

                addr->family = sa->sa_family;
                addr->table_id = 0;

                if (addr->family == AF_INET){

                        struct sockaddr_in *sa_in =
                                (struct sockaddr_in *) sa;


                        addr->addr.ipv4.s_addr = sa_in->sin_addr.s_addr;

                        apply_ipv4_ops(addr, if_info, conf_gw, conf_dst);

                } else {

                        struct sockaddr_in6 *sa6_in =
                                (struct sockaddr_in6 *) sa;

                        memcpy(&addr->addr.ipv6,
                               &sa6_in->sin6_addr,
                               sizeof(struct in6_addr));

                        apply_ipv6_ops(addr, if_info, conf_gw, conf_dst);
                }

                l_queue_push_tail(if_info->addrs, addr);
        }

        return true;
}
 
static bool routing_delete_local_address(struct mptcpd_interface const *i,
                                         struct sockaddr const *sa,
                                         struct mptcpd_pm *pm)
{
        (void) pm;

        struct if_rt_info *if_info = l_queue_find(info,
                                                  index_match,
                                                  &i->index);

        struct addr_info *addr_info =
                l_queue_find(if_info->addrs, address_match, sa);

        if (addr_info) {
                deconf_all(addr_info, if_info);

                l_queue_remove(if_info->addrs, addr_info);
                l_free(addr_info);
        }
                
        return true;
}

static struct mptcpd_plugin_ops const pm_ops = {
        .new_interface = routing_new_interface,
        .delete_interface = routing_delete_interface,
        .new_local_address = routing_new_local_address,
        .delete_local_address = routing_delete_local_address
};

static struct route_ops const rt_ops = {
        .new_route = add_route,
        .del_route = rm_route
};

static int routing_init(struct mptcpd_pm *pm)
{
        (void) pm;

        if (!init_mnl_ops())
                return EXIT_FAILURE;

        info = l_queue_new();

        if (!init_handler(&rt_ops))
                return EXIT_FAILURE;

        if (dump_routes(AF_INET, &rt_ops) < 0) {
                l_error("failed to dump ipv4 routes");
                return EXIT_FAILURE;
        }

        if (dump_routes(AF_INET6, &rt_ops) < 0) {
                l_error("failed to dump ipv6 routes");
                return EXIT_FAILURE;
        }

        static char const name[] = "routing";
        if (!mptcpd_plugin_register_ops(name, &pm_ops)) {
                l_error("Failed to initialize plugin '%s'.", name);
                return EXIT_FAILURE;
        }
        
        l_info("MPTCP routing configuration plugin started.");
        
        return EXIT_SUCCESS;
}

static void routing_exit(struct mptcpd_pm *pm)
{
        (void) pm;

        l_queue_destroy(info, clear_info);

        l_info("MPTCP routing configuration plugin exited.");
}

MPTCPD_PLUGIN_DEFINE(routing,
                     "Routing configuration plugin",
                     MPTCPD_PLUGIN_PRIORITY_DEFAULT,
                     routing_init,
                     routing_exit)

