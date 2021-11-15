#include <mptcpd/plugin.h>
#include <mptcpd/network_monitor.h>

#include <ell/util.h>
#include <ell/log.h>
#include <ell/uintset.h>
#include <ell/queue.h>
#include <ell/io.h>

#include <libmnl/libmnl.h>

#include <linux/rtnetlink.h>
#include <linux/fib_rules.h>

#include <arpa/inet.h>

#include <limits.h>
#include <assert.h>

#define BUFFERSIZE 2048

typedef union{
        struct in_addr ipv4;
        struct in6_addr ipv6;
} address;

//sockaddr is too much
//simpler struct
struct dst_info{
        address dst;
        uint8_t prefix_len;        
};

//sockaddr is too much
//simpler struct
struct addr_info{
        address addr;
        uint16_t table_id; //table id
        uint8_t family;
};

struct if_rt_info{
        struct l_queue *dst_ipv4;
        struct in_addr *gw4;

        struct l_queue *dst_ipv6;
        struct in6_addr *gw6;

        struct l_queue *addrs;

        int index;
};

struct user_data{
        void *pointer;
        uint32_t oif;
        uint8_t family;
};

static struct l_uintset *ids;

static struct l_queue *info;

static struct mnl_socket *sock_routes;
static struct mnl_socket *sock_conf;

// ----------------------------------------------------------------------

static size_t add_uint32(struct rtattr *rta, uint16_t type, 
                         uint32_t value)
{

        rta->rta_len = RTA_LENGTH(sizeof(uint32_t));
        rta->rta_type = type;
        *((uint32_t *) RTA_DATA(rta)) = value;

        return RTA_SPACE(sizeof(uint32_t));
}

static size_t add_attr(struct rtattr *rta, uint16_t type, 
                       void *data, size_t data_len)
{

        rta->rta_len = RTA_LENGTH(data_len);
        rta->rta_type = type;
        memcpy(RTA_DATA(rta), data, data_len);

        return RTA_SPACE(data_len);
}

static ssize_t netlink_gw(uint16_t type, uint16_t flags, void *gw,
                       uint8_t family, uint32_t table, uint32_t oif)
{
        size_t size_gw = family == AF_INET ?
                         sizeof(struct in_addr) :
                         sizeof(struct in6_addr);

        size_t size = mnl_nlmsg_size(sizeof(struct rtmsg)) +
                      RTA_SPACE(sizeof(uint32_t)) +
                      RTA_SPACE(size_gw) +
                      RTA_SPACE(sizeof(uint32_t));

        L_AUTO_FREE_VAR(struct nlmsghdr *, nl) = 
                l_malloc(size);
        memset(nl, 0, size);

        nl->nlmsg_type = type;
        nl->nlmsg_flags = NLM_F_REQUEST | flags;
        nl->nlmsg_len = size;

        struct rtmsg *rt = mnl_nlmsg_get_payload(nl);
        rt->rtm_table = RT_TABLE_UNSPEC;
        rt->rtm_protocol = RTPROT_BOOT;
        rt->rtm_scope = RT_SCOPE_UNIVERSE;
        rt->rtm_type = RTN_UNICAST;
        rt->rtm_family = family;
        rt->rtm_dst_len = 0;

        void *pointer = mnl_nlmsg_get_payload_offset(nl, sizeof(struct rtmsg));
        pointer = (uint8_t *) pointer + add_uint32(pointer, RTA_TABLE, table);
        pointer = (uint8_t *) pointer + add_attr(pointer, RTA_GATEWAY, gw, size_gw);
        add_uint32(pointer, RTA_OIF, oif);

        return mnl_socket_sendto(sock_conf, nl, size);
}

static ssize_t netlink_dest(uint16_t type, uint16_t flags, 
                         struct dst_info *dst, uint8_t family, 
                         uint32_t table, uint32_t oif)
{
        size_t size_dst;
        void *dst_pointer;

        if (family == AF_INET) {

                dst_pointer = &dst->dst.ipv4;
                size_dst = sizeof(struct in_addr);

        } else {

                dst_pointer = &dst->dst.ipv6;
                size_dst = sizeof(struct in6_addr);
        }

        size_t size = mnl_nlmsg_size(sizeof(struct rtmsg)) +
                      RTA_SPACE(sizeof(uint32_t)) +
                      RTA_SPACE(size_dst) +
                      RTA_SPACE(sizeof(uint32_t));

        L_AUTO_FREE_VAR(struct nlmsghdr *, nl) = 
                l_malloc(size);
        memset(nl, 0, size);

        nl->nlmsg_type = type;
        nl->nlmsg_flags = NLM_F_REQUEST | flags;
        nl->nlmsg_len = size;

        struct rtmsg *rt = mnl_nlmsg_get_payload(nl);
        rt->rtm_table = RT_TABLE_UNSPEC;
        rt->rtm_protocol = RTPROT_BOOT;
        rt->rtm_scope = RT_SCOPE_LINK;
        rt->rtm_type = RTN_UNICAST;
        rt->rtm_family = family;
        rt->rtm_dst_len = dst->prefix_len;

        void *pointer = mnl_nlmsg_get_payload_offset(nl, sizeof(struct rtmsg));
        pointer = (uint8_t *) pointer + add_uint32(pointer, RTA_TABLE, table);
        pointer = (uint8_t *) pointer + add_attr(pointer, RTA_DST, dst_pointer, size_dst);
        add_uint32(pointer, RTA_OIF, oif);

        return mnl_socket_sendto(sock_conf, nl, size);
}

//fix this
static ssize_t netlink_rule(uint16_t type, uint16_t flags, address* src_addr,
                         uint8_t family, uint32_t table)
{
        size_t size_src;
        uint8_t bit_len;
        void *src;

        if (src_addr) {
                if (family == AF_INET) {

                        src = &src_addr->ipv4;
                        size_src = sizeof(struct in_addr);
                        bit_len = 32;

                } else {

                        src = &src_addr->ipv6;
                        size_src = sizeof(struct in6_addr);
                        bit_len = 128;


                }
        }

        size_t size = mnl_nlmsg_size(sizeof(struct fib_rule_hdr)) +
                      RTA_SPACE(sizeof(uint32_t));

        if (src_addr) 
                size += RTA_SPACE(size_src);

        L_AUTO_FREE_VAR(struct nlmsghdr *, nl) = 
                l_malloc(size);
        memset(nl, 0, size);

        nl->nlmsg_type = type;
        nl->nlmsg_flags = NLM_F_REQUEST | flags;
        nl->nlmsg_len = size;

        struct fib_rule_hdr *fib = mnl_nlmsg_get_payload(nl);
        fib->family = family;
        fib->action = FR_ACT_TO_TBL;

        void *pointer = mnl_nlmsg_get_payload_offset(nl, sizeof(struct fib_rule_hdr));

        if (src_addr) {
                fib->src_len = bit_len;
                pointer = (uint8_t *) pointer + add_attr(pointer, FRA_SRC, src, size_src);
        }

        add_uint32(pointer, FRA_TABLE, table);

        return mnl_socket_sendto(sock_conf, nl, size);
}

static bool index_match(void const *a, void const *b)
{
        assert(a);
        assert(b);

        struct if_rt_info const *const if_info = a;
        int const *const index = b;
        
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

static bool is_link_local(struct in6_addr *addr)
{
       return (addr->__in6_u.__u6_addr8[0] & 0xc0) == 0x80 && 
               addr->__in6_u.__u6_addr8[1] == 0xfe;

}

//ugly
static bool add_gw(struct if_rt_info *if_info, void *gw, 
                   uint8_t family)
{
        if (family == AF_INET){

                if (!if_info->gw4)
                        if_info->gw4 = l_new(struct in_addr, 1);

               if (if_info->gw4->s_addr != *(uint32_t *)gw) {

                        if_info->gw4->s_addr = *(uint32_t *) gw;
                        return true;

                }
        }
        else{
                if (!if_info->gw6) {
                        if_info->gw6 = l_new(struct in6_addr, 1);
                        memcpy(if_info->gw6, gw, sizeof(struct in6_addr));
                        return true;
                } else if (memcmp(gw, if_info->gw6, sizeof(struct in6_addr)) &&
                    (is_link_local(gw) ||
                     !is_link_local(if_info->gw6))) {

                        memcpy(if_info->gw6, gw, sizeof(struct in6_addr));
                        return true;
                }
        }         

        return false;
}

static bool compare_dst(void const *a, void const *b)
{
        assert(a);
        assert(b);
        return memcmp(a, b, sizeof(struct dst_info)) == 0;
}

static struct dst_info *add_dst(struct if_rt_info *if_info, void *dst, 
                                uint8_t family, uint8_t prefix_len)
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
                return dst_info;
        }

        return NULL;
}

//is there something to check
static void parse_id(struct nlmsghdr *nl)
{

        struct fib_rule_hdr *fib = mnl_nlmsg_get_payload(nl);

        uint32_t table_id = fib->table;

        size_t rta_len = nl->nlmsg_len - mnl_nlmsg_size(sizeof(*fib));
        for (struct rtattr const *rta = 
                        mnl_nlmsg_get_payload_offset(nl, sizeof(*fib));
             RTA_OK(rta, rta_len);
             rta = RTA_NEXT(rta, rta_len)){

                if (rta->rta_type == FRA_TABLE )
                        table_id = *(uint32_t *) RTA_DATA(rta);
        }

        l_uintset_put(ids, table_id);
}

static uint16_t get_table_id(void)
{
        size_t size = mnl_nlmsg_size(sizeof(struct fib_rule_hdr));

        struct nlmsghdr *nl = l_malloc(size);
        memset(nl, 0, size);

        nl->nlmsg_type = RTM_GETRULE;
        nl->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        nl->nlmsg_len = size;

        struct fib_rule_hdr *frh = mnl_nlmsg_get_payload(nl);
        frh->action = FR_ACT_TO_TBL;

        if (mnl_socket_sendto(sock_conf, nl, size) < 0)
                return 0;

        l_free(nl);
        uint8_t *buffer = l_malloc(BUFFERSIZE);

        while (true) {

                ssize_t len = mnl_socket_recvfrom(sock_conf, buffer, 
                                                  BUFFERSIZE);

                if (len <= 0) {
                        return 0;
                }

                for (nl = (struct nlmsghdr *) buffer; 
                     mnl_nlmsg_ok(nl, len); 
                     nl = mnl_nlmsg_next(nl, (int *) &len)) {

                        switch (nl->nlmsg_type) {
                        case RTM_NEWRULE:
                                parse_id(nl);
                                break;

                        case NLMSG_DONE:
                                l_free(buffer);
                                return l_uintset_find_unused_min(ids);
                                
                        case NLMSG_ERROR: //log?
                                l_free(buffer);
                                return 0;
                        }
                }
        }

        l_free(buffer);
        return 0;
}


static void conf_gw(void *data, void *user_data)
{
        struct addr_info *addr = data;
        struct user_data *conf_info = user_data;

        if (addr->family != conf_info->family)
                return;

        if (addr->table_id == 0) {
                uint32_t table_id = get_table_id();

                if(table_id == 0)
                        return;

                if (netlink_rule(RTM_NEWRULE, NLM_F_CREATE | NLM_F_EXCL,
                                 &addr->addr, addr->family, 
                                 table_id) <= 0)
                        return;

                l_uintset_put(ids, table_id);

                addr->table_id = table_id;
        }

        netlink_gw(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL,
                   conf_info->pointer, conf_info->family, 
                   addr->table_id, conf_info->oif);

}
static void conf_dst(void *data, void *user_data)
{
        struct addr_info *addr = data;
        struct user_data *conf_info = user_data;

        if (addr->family != conf_info->family)
                return;

        if (addr->table_id == 0) {
                uint32_t table_id = get_table_id();

                if(table_id == 0)
                        return;

                if (netlink_rule(RTM_NEWRULE, NLM_F_CREATE | NLM_F_EXCL,
                                 &addr->addr, addr->family, 
                                 table_id) <= 0)
                        return;

                l_uintset_put(ids, table_id);

                addr->table_id = table_id;
        }

        netlink_dest(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL,
                     conf_info->pointer, conf_info->family,
                     addr->table_id, conf_info->oif);

}

static void add_route(uint32_t index, uint8_t family, void *gw,
                      void *dst, uint8_t prefix_len)
{
        struct if_rt_info *if_info =
                l_queue_find(info, index_match, &index);

        if (!if_info) {

                if_info = l_new(struct if_rt_info, 1);

                if_info->dst_ipv4 = l_queue_new();
                if_info->gw4 = NULL;

                if_info->dst_ipv6 = l_queue_new();
                if_info->gw6 = NULL;

                if_info->addrs = l_queue_new();

                if_info->index = index;

                l_queue_push_tail(info, if_info);
        }

        if (gw && add_gw(if_info, gw, family)) {

                struct user_data data = { 
                        .pointer = gw,
                        .oif = index,
                        .family = family
                };
                l_queue_foreach(if_info->addrs, conf_gw, &data);
        }

        struct dst_info *dst_info;
        if (dst && 
            (dst_info = add_dst(if_info, dst, family, prefix_len))) {

                struct user_data data = {
                        .pointer = dst_info,
                        .oif = index,
                        .family = family
                };
                l_queue_foreach(if_info->addrs, conf_dst, &data);
        }
}

static void deconf_gw(void *data, void *user_data)
{
        struct addr_info *addr = data;
        struct user_data *conf_info = user_data;

        if (addr->family != conf_info->family)
                return;

        if (addr->table_id != 0) {

                netlink_gw(RTM_DELROUTE, 0, conf_info->pointer,
                           conf_info->family, addr->table_id, 
                           conf_info->oif);
        }
}

static void deconf_dst(void *data, void *user_data)
{
        struct addr_info *addr = data;
        struct user_data *conf_info = user_data;

        if (addr->family != conf_info->family)
                return;

        if (addr->table_id != 0) {

                netlink_dest(RTM_DELROUTE, 0, conf_info->pointer,
                             conf_info->family, addr->table_id, 
                             conf_info->oif);
        
        }
}

static bool rm_gw(struct if_rt_info *if_info, void *gw, 
                  uint8_t family)
{
        if (family == AF_INET ){

                if (if_info->gw4 && 
                    if_info->gw4->s_addr == *(uint32_t *)gw) {

                        l_free(if_info->gw4);
                        if_info->gw4 = NULL;
                        return true;

                }
        }
        else{
                if (if_info->gw6 && 
                    memcmp(gw, if_info->gw6, sizeof(struct in6_addr)) == 0){

                        l_free(if_info->gw6);
                        if_info->gw6 = NULL;
                        return true;
                }
        }         

        return false;
}

static struct dst_info *rm_dst(struct if_rt_info *if_info, void *dst, 
                               uint8_t family, uint8_t prefix_len)
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

        struct dst_info *elem =
                l_queue_find(queue, compare_dst, dst_info);

        if (elem) {
                l_queue_remove(queue, elem);
                l_free(elem);
                return dst_info;
        }

        return NULL;
}

static void rm_route(uint32_t index, uint8_t family, void *gw, 
                     void *dst, uint8_t prefix_len)
{
        struct if_rt_info *if_info =
                l_queue_find(info, index_match, &index);

        if (if_info) {

                if (gw && rm_gw(if_info, gw, family)){
                        
                        struct user_data data = { 
                                .pointer = gw,
                                .oif = index,
                                .family = family
                        };
                        l_queue_foreach(if_info->addrs, deconf_gw, &data);
                }

                struct dst_info *dst_info;
                if (dst &&
                    (dst_info = rm_dst(if_info, dst, family, prefix_len))) {

                        struct user_data data = {
                                .pointer = dst_info,
                                .oif = index,
                                .family = family
                        };
                        l_queue_foreach(if_info->addrs, deconf_dst, &data);

                        l_free(dst_info);
                }
                //if if_info empty rm it
        }
}

static void parse_route(struct nlmsghdr *nl)
{
        struct rtmsg *rt = mnl_nlmsg_get_payload(nl);
        
        //ignore non unicast routes
        if(rt->rtm_type != RTN_UNICAST)
                return;

        uint32_t table = RT_TABLE_UNSPEC;
        uint32_t index = 0;
        void *gw = NULL;
        void *dst = NULL;
        size_t attr_len = nl->nlmsg_len - mnl_nlmsg_size(sizeof(*rt));
        for (struct rtattr const *attr = 
                        mnl_nlmsg_get_payload_offset(nl, sizeof(*rt));
             RTA_OK(attr, attr_len);
             attr = RTA_NEXT(attr, attr_len)) {
                
                switch (attr->rta_type) {
                case RTA_TABLE:
                        table = *(uint32_t *) RTA_DATA(attr);
                        break;
                case RTA_OIF:
                        index = *(uint32_t *) RTA_DATA(attr);
                        break;
                case RTA_GATEWAY:
                        gw = RTA_DATA(attr);
                        break;
                case RTA_DST:
                        dst = RTA_DATA(attr);
                        break;
                }
        }

        //use assert
        if(table != RT_TABLE_MAIN)
                return;

        switch (nl->nlmsg_type) {
        case RTM_NEWROUTE:
                add_route(index, rt->rtm_family, gw, 
                          dst, rt->rtm_dst_len);
                break;

        case RTM_DELROUTE:
                rm_route(index, rt->rtm_family, gw, 
                         dst, rt->rtm_dst_len);
                break;
        }
}

static bool routing_handler(struct l_io *io, void *user_data)
{
        (void) user_data;
        (void) io;

        L_AUTO_FREE_VAR(struct nlmsghdr *, nl) =
                l_malloc(BUFFERSIZE);

        ssize_t len = 
                mnl_socket_recvfrom(sock_routes, nl, BUFFERSIZE);

        if (len <= 0) {
                l_error("[ERROR] Failed to receive from socket");
		//l_error("receive error %s (%d)\n",
                //        strerror(errno), errno);
                return false;
        }

        assert(mnl_nlmsg_ok(nl,len));
        assert(nl->nlmsg_len != 0);
        assert(nl->nlmsg_type == RTM_NEWROUTE || 
               nl->nlmsg_type == RTM_DELROUTE);

        parse_route(nl);

        return true;
}

static ssize_t dump_routes(uint8_t family)
{
        size_t size = mnl_nlmsg_size(sizeof(struct rtmsg));

        struct nlmsghdr *nl = l_malloc(size);
        memset(nl, 0, size);

        nl->nlmsg_type = RTM_GETROUTE;
        nl->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        nl->nlmsg_len = size;

        struct rtmsg *rt = mnl_nlmsg_get_payload(nl);
        rt->rtm_family = family;

        ssize_t status = mnl_socket_sendto(sock_conf, nl, size);
        if (status < 0)
                return status;

        l_free(nl);
        uint8_t *buffer = l_malloc(BUFFERSIZE);

        while (true) {

                status = mnl_socket_recvfrom(sock_conf, buffer, 
                                             BUFFERSIZE);

                if (status <= 0)
                        return status;

                for (nl = (struct nlmsghdr *) buffer; 
                     mnl_nlmsg_ok(nl, status); 
                     nl = mnl_nlmsg_next(nl, (int *) &status)) {

                        switch (nl->nlmsg_type) {
                        case RTM_NEWROUTE:
                                parse_route(nl);
                                break;

                        case NLMSG_DONE:
                                l_free(buffer);
                                return status;
                                
                        case NLMSG_ERROR: //log?
                                {
                                        struct nlmsgerr *error = mnl_nlmsg_get_payload(nl);
                                        int error_value = error->error;
                                        l_free(buffer);
                                        return error_value;
                                }
                        }
                }
        }

        l_free(buffer);
        return status;

}

static bool deconf_all(void *data, void *user_data)
{
        struct addr_info *addr_info = data;
        struct if_rt_info *if_info = user_data;

        if (addr_info->table_id == 0)
                return true;

        struct user_data req_data = {
                .family = addr_info->family,
                .oif = if_info->index
        };

        if (addr_info->family == AF_INET) {

                if (if_info->gw4) {
                        req_data.pointer = if_info->gw4;
                        deconf_gw(addr_info, &req_data);
                }

                if (!l_queue_isempty(if_info->dst_ipv4)) {

                        struct l_queue_entry const *entry = 
                                l_queue_get_entries(if_info->dst_ipv4);

                        while (entry) {
                                req_data.pointer = entry->data;
                                deconf_dst(addr_info, &req_data);
                                entry = entry->next;
                        }
                }

        } else {

                if (if_info->gw6) {
                        req_data.pointer = if_info->gw6;
                        deconf_gw(addr_info, &req_data);
                }

                if (!l_queue_isempty(if_info->dst_ipv6)) {

                        struct l_queue_entry const *entry = 
                                l_queue_get_entries(if_info->dst_ipv6);

                        while (entry) {
                                req_data.pointer = entry->data;
                                deconf_dst(addr_info, &req_data);
                                entry = entry->next;
                        }
                }
        }

        netlink_rule(RTM_DELRULE, 0, NULL, addr_info->family,
                     addr_info->table_id);

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

static bool routing_new_local_address(struct mptcpd_interface const *i,
                                      struct sockaddr const *sa,
                                      struct mptcpd_pm *pm)
{
        (void) pm;

        struct if_rt_info *if_info = l_queue_find(info,
                                                  index_match,
                                                  &i->index);

        if (!if_info) {

                if_info = l_new(struct if_rt_info, 1);

                if_info->dst_ipv4 = l_queue_new();
                if_info->gw4 = NULL;

                if_info->dst_ipv6 = l_queue_new();
                if_info->gw6 = NULL;

                if_info->addrs = l_queue_new();

                if_info->index = i->index;

                l_queue_push_tail(info, if_info);

        } 

        //simplify
        if(!l_queue_find(if_info->addrs, address_match, sa)) {

                struct addr_info *addr =
                        l_new(struct addr_info, 1);

                addr->family = sa->sa_family;
                addr->table_id = 0;

                struct user_data data = { 
                        .family = addr->family,
                        .oif = if_info->index
                };

                if (addr->family == AF_INET) {

                        addr->addr.ipv4.s_addr = 
                                ((struct sockaddr_in *) sa)->sin_addr.s_addr;

                        if (if_info->gw4) {
                                data.pointer = if_info->gw4;
                                conf_gw(addr, &data);
                        }

                        if (!l_queue_isempty(if_info->dst_ipv4)) {

                                struct l_queue_entry const *entry = 
                                        l_queue_get_entries(if_info->dst_ipv4);

                                while (entry) {
                                        data.pointer = entry->data;
                                        conf_dst(addr, &data);
                                        entry = entry->next;
                                }
                        }

                } else {

                        memcpy(&addr->addr.ipv6,
                               &((struct sockaddr_in6 *) sa)->sin6_addr,
                               sizeof(struct in6_addr));

                        if (if_info->gw6) {
                                data.pointer = if_info->gw6;
                                conf_gw(addr, &data);
                        }

                        if (!l_queue_isempty(if_info->dst_ipv6)) {

                                struct l_queue_entry const *entry = 
                                        l_queue_get_entries(if_info->dst_ipv6);

                                while (entry) {
                                        data.pointer = entry->data;
                                        conf_dst(addr, &data);
                                        entry = entry->next;
                                }
                        }
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

        struct addr_info *addr_info;

        if (if_info &&
            (addr_info = l_queue_find(if_info->addrs, address_match, sa))) {

                deconf_all(addr_info, if_info);

                l_queue_remove(if_info->addrs, addr_info);
                l_free(addr_info);
        } 

        return true;
}

static struct mptcpd_plugin_ops const pm_ops = {
        .new_local_address = routing_new_local_address,
        .delete_local_address = routing_delete_local_address
};

static int routing_init(struct mptcpd_pm *pm)
{
        (void) pm;

        ids = l_uintset_new(USHRT_MAX);

        sock_conf = mnl_socket_open2(NETLINK_ROUTE, SOCK_CLOEXEC);

        if (sock_conf == NULL){
                l_error("failed to open socket netlink");
                //clear
                return -1;
        }

        info = l_queue_new();

        sock_routes = mnl_socket_open2(NETLINK_ROUTE, SOCK_CLOEXEC);

        if (sock_routes == NULL){
                l_error("failed to open socket netlink");
                return -1;
        }

        uint32_t groups = (1 << (RTNLGRP_IPV4_ROUTE - 1)) |
                          (1 << (RTNLGRP_IPV6_ROUTE - 1));

        if (mnl_socket_bind(sock_routes, groups, 0) < 0) {
                l_error("failed to bind socket netlink");
                //clear
                return -1;
        }

        struct l_io *io = l_io_new(mnl_socket_get_fd(sock_routes));

        l_io_set_close_on_destroy(io, true);
        l_io_set_read_handler(io, routing_handler, NULL, NULL);

        if (dump_routes(AF_INET) <= 0) {
                l_error("failed to dump ipv4 routes");
                //clear
                return -1;
        }

        if (dump_routes(AF_INET6) <= 0) {
                l_error("failed to dump ipv6 routes");
                //clear
                return -1;
        }

        static char const name[] = "routing";
        
        if (!mptcpd_plugin_register_ops(name, &pm_ops)) {
                l_error("Failed to initialize plugin '%s'.", name);
        
                return -1;
        }
        
        l_info("MPTCP routing configuration plugin started.");
        
        return 0;
}

static void routing_exit(struct mptcpd_pm *pm)
{
        (void) pm;

        mnl_socket_close(sock_routes);

        l_queue_destroy(info, clear_info);

        mnl_socket_close(sock_conf);

        l_uintset_free(ids);

        l_info("MPTCP routing configuration plugin exited.");
}

MPTCPD_PLUGIN_DEFINE(routing,
                     "Routing configuration plugin",
                     MPTCPD_PLUGIN_PRIORITY_DEFAULT,
                     routing_init,
                     routing_exit)

