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
#include <time.h>
#include <stdlib.h>

#define IPV4_SIZE 32
#define IPV6_SIZE 128

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

        uint32_t index;
};

//convenience struct
struct user_data{
        void *pointer;
        uint32_t oif;
        uint8_t family;
        uint8_t prefix_len;
};

static struct l_uintset *ids;

static struct l_queue *info;

static struct mnl_socket *sock_routes;
static struct mnl_socket *sock_conf;

static uint32_t pid_routes;
static uint32_t pid_conf;

// ----------------------------------------------------------------------

static ssize_t netlink_route(uint16_t type,
                             uint16_t flags,
                             uint32_t table,
                             uint8_t scope,
                             uint8_t attr,
                             struct user_data *data)
{
        L_AUTO_FREE_VAR(uint8_t *, buf) = 
                l_malloc(MNL_SOCKET_BUFFER_SIZE);
        memset(buf, 0, MNL_SOCKET_BUFFER_SIZE);

        struct nlmsghdr *nl = mnl_nlmsg_put_header(buf);

        nl->nlmsg_type = type;
        nl->nlmsg_flags = NLM_F_REQUEST | flags;
        nl->nlmsg_seq = time(NULL);

        struct rtmsg *rt = 
                mnl_nlmsg_put_extra_header(nl, sizeof(struct rtmsg));

        rt->rtm_family = data->family;
        rt->rtm_dst_len = data->prefix_len;
        rt->rtm_scope = scope;
        rt->rtm_table = RT_TABLE_UNSPEC;
        rt->rtm_protocol = RTPROT_BOOT;
        rt->rtm_type = RTN_UNICAST;

        mnl_attr_put_u32(nl, RTA_TABLE, table);
        if (data->family == AF_INET)
                mnl_attr_put_u32(nl, attr, *(uint32_t *) data->pointer);
        else
                mnl_attr_put(nl,
                             attr,
                             sizeof(struct in6_addr),
                             data->pointer);

        mnl_attr_put_u32(nl, RTA_OIF, data->oif);

        //ask for ack e check for error
        //do something like libnftnl does
        return mnl_socket_sendto(sock_conf, nl, nl->nlmsg_len);
}

static ssize_t netlink_rule(uint16_t type, 
                            uint16_t flags, 
                            uint8_t family,
                            uint32_t table,
                            address* src_addr)
{
        L_AUTO_FREE_VAR(uint8_t *, buf) =
                l_malloc(MNL_SOCKET_BUFFER_SIZE);

        struct nlmsghdr *nl = mnl_nlmsg_put_header(buf);

        nl->nlmsg_type = type;
        nl->nlmsg_flags = NLM_F_REQUEST | flags;
        nl->nlmsg_seq = time(NULL);

        struct fib_rule_hdr *fib =
                mnl_nlmsg_put_extra_header(nl,
                                           sizeof(struct fib_rule_hdr));

        fib->family = family;
        fib->action = FR_ACT_TO_TBL;

        if (src_addr) {
                if (family == AF_INET) {
                        fib->src_len = IPV4_SIZE;
                        mnl_attr_put_u32(nl,
                                         FRA_SRC,
                                         src_addr->ipv4.s_addr);
                } else {
                        fib->src_len = IPV6_SIZE;
                        mnl_attr_put(nl,
                                     FRA_SRC,
                                     sizeof(struct in6_addr),
                                     &src_addr->ipv6);
                }
        }

        mnl_attr_put_u32(nl, FRA_TABLE, table);

        //ask for ack e check for error
        //do something like libnftnl does
        return mnl_socket_sendto(sock_conf, nl, nl->nlmsg_len);
}

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

static bool add_gw(struct if_rt_info *if_info,
                   uint8_t family,
                   void *gw)
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

static int table_id_cb(const struct nlattr *attr, void *user_data)
{
        if (mnl_attr_type_valid(attr, RTA_MAX) < 0)
                return MNL_CB_OK;

        uint32_t *table_id = user_data;

        uint16_t type = mnl_attr_get_type(attr);
        if (type == FRA_TABLE ) {
                if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
                        return MNL_CB_ERROR;

                *table_id = mnl_attr_get_u32(attr);
                return MNL_CB_STOP;
        }

        return MNL_CB_OK;
}

//is there something to check?
static int rule_cb(struct nlmsghdr const *nl, void *user_data)
{
        (void) user_data;

        struct fib_rule_hdr *fib = mnl_nlmsg_get_payload(nl);

        uint32_t table_id = fib->table;
        if (mnl_attr_parse(nl, sizeof(*fib), table_id_cb, &table_id) ==
            MNL_CB_ERROR)
            return MNL_CB_ERROR; //l_error

        l_uintset_put(ids, table_id);

        return MNL_CB_OK;
}

//maybe sint32_t for errors;
static uint16_t get_table_id(void)
{
        L_AUTO_FREE_VAR(uint8_t *, buf) =
                l_malloc(MNL_SOCKET_BUFFER_SIZE);

        struct nlmsghdr *nl = mnl_nlmsg_put_header(buf);
        nl->nlmsg_type = RTM_GETRULE;
        nl->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;

        uint32_t seq = time(NULL);
        nl->nlmsg_seq = seq;

        struct fib_rule_hdr *frh = 
                mnl_nlmsg_put_extra_header(nl,
                                           sizeof(struct fib_rule_hdr));

        frh->action = FR_ACT_TO_TBL;

        if (mnl_socket_sendto(sock_conf, nl, nl->nlmsg_len) < 0) {
                l_error("failed to send request");
                return 0;
        }

        ssize_t ret = mnl_socket_recvfrom(sock_conf,
                                          buf,
                                          MNL_SOCKET_BUFFER_SIZE);
        while (ret > 0) {
                ret = mnl_cb_run(buf, ret, seq, pid_conf, rule_cb, NULL);

                if (ret <= MNL_CB_STOP)
                        break;

                ret = mnl_socket_recvfrom(sock_conf,
                                          buf,
                                          MNL_SOCKET_BUFFER_SIZE);
        }

        if (ret == -1) {
                l_error("failed to retrieve tables ids");
                return 0;
        }

        return l_uintset_find_unused_min(ids);
}

static bool create_table(struct addr_info *addr)
{
        uint32_t table_id = get_table_id();

        if(table_id == 0) //l_error
                return false;

        if (netlink_rule(RTM_NEWRULE,
                         NLM_F_CREATE | NLM_F_EXCL,
                         addr->family, 
                         table_id,
                         &addr->addr) <= 0)
                return false; //l_error

        l_uintset_put(ids, table_id); //verify return

        addr->table_id = table_id;

        return true;
}


static void conf_gw(void *data, void *user_data)
{
        struct addr_info *addr = data;
        struct user_data *conf_info = user_data;

        if (addr->family != conf_info->family)
                return;

        if (addr->table_id == 0 && !create_table(addr))
                return;

        netlink_route(RTM_NEWROUTE,
                      NLM_F_CREATE | NLM_F_EXCL,
                      addr->table_id,
                      RT_SCOPE_UNIVERSE,
                      RTA_GATEWAY,
                      user_data);

}
static void conf_dst(void *data, void *user_data)
{
        struct addr_info *addr = data;
        struct user_data *conf_info = user_data;

        if (addr->family != conf_info->family)
                return;

        if (addr->table_id == 0 && !create_table(addr))
                return;

        netlink_route(RTM_NEWROUTE,
                      NLM_F_CREATE | NLM_F_EXCL,
                      addr->table_id,
                      RT_SCOPE_LINK,
                      RTA_DST,
                      user_data);
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

static void deconf_gw(void *data, void *user_data)
{
        struct addr_info *addr = data;
        struct user_data *conf_info = user_data;

        if (addr->family != conf_info->family)
                return;

        if (addr->table_id != 0)
                //check return
                netlink_route(RTM_DELROUTE,
                              0,
                              addr->table_id,
                              RT_SCOPE_UNIVERSE,
                              RTA_GATEWAY,
                              user_data);
}

static void deconf_dst(void *data, void *user_data)
{
        struct addr_info *addr = data;
        struct user_data *conf_info = user_data;

        if (addr->family != conf_info->family)
                return;

        if (addr->table_id != 0)
                netlink_route(RTM_DELROUTE,
                              0,
                              addr->table_id,
                              RT_SCOPE_LINK,
                              RTA_DST,
                              user_data);
}

static bool rm_gw(struct if_rt_info *if_info,
                  uint8_t family,
                  void *gw)
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

        if (if_i) {

                struct user_data data = {
                        .oif = index,
                        .family = family,
                        .prefix_len = dst_len
                };

                if (tb[RTA_GATEWAY]) {
                        data.pointer =
                                mnl_attr_get_payload(tb[RTA_GATEWAY]);

                        if (rm_gw(if_i, family, data.pointer))
                                l_queue_foreach(if_i->addrs, 
                                                deconf_gw, 
                                                &data);
                }

                if (tb[RTA_DST]){
                        data.pointer =
                                mnl_attr_get_payload(tb[RTA_DST]);

                        if (rm_dst(if_i, family, data.pointer, dst_len))
                                l_queue_foreach(if_i->addrs,
                                                deconf_dst,
                                                &data);
                } 
        } //if if_info empty rm it
}

static int data_attr_ipv4(struct nlattr const *attr, void *data)
{
        if (mnl_attr_type_valid(attr, RTA_MAX) < 0)
                return MNL_CB_OK;

        struct nlattr const **tb = data;
        uint16_t type = mnl_attr_get_type(attr);
        switch (type) {
        case RTA_TABLE:
        case RTA_OIF:
        case RTA_GATEWAY:
        case RTA_DST:
                if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) //l_error
                        return MNL_CB_ERROR;
                break;
        default:
                return MNL_CB_OK;
        }

        tb[type] = attr;
        return MNL_CB_OK;
}

static int data_attr_ipv6(struct nlattr const *attr, void *data)
{
        if (mnl_attr_type_valid(attr, RTA_MAX) < 0)
                return MNL_CB_OK;

        struct nlattr const **tb = data;
        uint16_t type = mnl_attr_get_type(attr);
        switch (type) {
        case RTA_TABLE:
        case RTA_OIF:
                if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) //l_error
                        return MNL_CB_ERROR;
                break;
        case RTA_GATEWAY:
        case RTA_DST:
                if (mnl_attr_validate2(attr,
                                       MNL_TYPE_BINARY,
                                       sizeof(struct in6_addr)) < 0) 
                        //l_error
                        return MNL_CB_ERROR;
                break;
        default:
                return MNL_CB_OK;
        }

        tb[type] = attr;
        return MNL_CB_OK;
}

static int data_cb(struct nlmsghdr const *nl, void *data)
{
        (void) data;
        
        struct rtmsg *rt = mnl_nlmsg_get_payload(nl);

        if (rt->rtm_type != RTN_UNICAST)
                return MNL_CB_OK;

        struct nlattr const *tb[RTA_MAX + 1] = {0};

        switch (rt->rtm_family) {
        case AF_INET:
                mnl_attr_parse(nl, sizeof(*rt), data_attr_ipv4, tb);
                break;
        case AF_INET6:
                mnl_attr_parse(nl, sizeof(*rt), data_attr_ipv6, tb);
                break;
        default:
                return MNL_CB_OK;
        }

        uint32_t table = tb[RTA_TABLE] ?
                         mnl_attr_get_u32(tb[RTA_TABLE]) :
                         rt->rtm_table;

        if (table != RT_TABLE_MAIN || !tb[RTA_OIF])
                return MNL_CB_OK;

        if (!tb[RTA_GATEWAY] && !tb[RTA_DST])
                return MNL_CB_OK;

        switch (nl->nlmsg_type) {
        case RTM_NEWROUTE:
                add_route(rt->rtm_family,
                          rt->rtm_dst_len,
                          tb);
                break;

        case RTM_DELROUTE:
                rm_route(rt->rtm_family,
                         rt->rtm_dst_len,
                         tb);
                break;
        }

        return MNL_CB_OK;
}

static ssize_t dump_routes(uint8_t family)
{
        L_AUTO_FREE_VAR(uint8_t *, buf) =
                l_malloc(MNL_SOCKET_BUFFER_SIZE);
        uint32_t seq;

        struct nlmsghdr *nl = mnl_nlmsg_put_header(buf);

        nl->nlmsg_type = RTM_GETROUTE;
        nl->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;

        seq = time(NULL);
        nl->nlmsg_seq = seq;

        struct rtmsg *rt = 
                mnl_nlmsg_put_extra_header(nl, sizeof(struct rtmsg));
        rt->rtm_family = family;

        if (mnl_socket_sendto(sock_conf, nl, nl->nlmsg_len) < 0) {
                //l_error
                return -1;
        }

        ssize_t ret = mnl_socket_recvfrom(sock_conf, buf, MNL_SOCKET_BUFFER_SIZE);
        while (ret > 0) {
                ret = mnl_cb_run(buf, ret, seq, pid_conf, data_cb, NULL);

                if (ret <= MNL_CB_STOP)
                        break;

                ret = mnl_socket_recvfrom(sock_conf, buf, MNL_SOCKET_BUFFER_SIZE);
        }

        return ret;
}

static bool routing_handler(struct l_io *io, void *user_data)
{
        (void) user_data;
        (void) io;

        L_AUTO_FREE_VAR(uint8_t *, buf) =
                l_malloc(MNL_SOCKET_BUFFER_SIZE);

        ssize_t ret = 
                mnl_socket_recvfrom(sock_routes,
                                    buf,
                                    MNL_SOCKET_BUFFER_SIZE);

        if(ret > 0)
                ret = mnl_cb_run(buf, ret, 0, pid_routes, data_cb, NULL);

        return ret > 0;
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

static bool deconf_all(void *data, void *user_data)
{
        struct addr_info *addr_info = data;
        struct if_rt_info *if_info = user_data;

        if (addr_info->table_id == 0)
                return true;


        if (addr_info->family == AF_INET)
                apply_ipv4_ops(addr_info, if_info, deconf_gw, deconf_dst);

        else
                apply_ipv6_ops(addr_info, if_info, deconf_gw, deconf_dst);


        netlink_rule(RTM_DELRULE,
                     0,
                     addr_info->family,
                     addr_info->table_id,
                     NULL);

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

static struct mnl_socket *init_socket(uint32_t groups, uint32_t *pid)
{
        struct mnl_socket *sock =
                mnl_socket_open2(NETLINK_ROUTE, SOCK_CLOEXEC);

        if (sock == NULL){
                l_error("failed to open socket netlink");
                return NULL;
        }

        if (mnl_socket_bind(sock, groups , MNL_SOCKET_AUTOPID) < 0) {
                l_error("failed to bind socket netlink");
                mnl_socket_close(sock);
                return NULL;
        }

        *pid = mnl_socket_get_portid(sock);

        return sock;
}

// ----------------------------------------------------------------------

static bool routing_new_interface(struct mptcpd_interface const *i,
                                 struct mptcpd_pm *pm)
{
        (void) i;
        (void) pm;
        return true;
}

static bool routing_delete_interface(struct mptcpd_interface const *i,
                                     struct mptcpd_pm *pm)
{
        (void) i;
        (void) pm;
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

        if (!if_info)
                if_info = if_rt_info_init(i->index);

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

        if (if_info) {
                struct addr_info *addr_info =
                        l_queue_find(if_info->addrs, address_match, sa);

                if (addr_info) {
                        deconf_all(addr_info, if_info);

                        l_queue_remove(if_info->addrs, addr_info);
                        l_free(addr_info);
                }
        }
                
        return true;
}

static struct mptcpd_plugin_ops const pm_ops = {
        .new_interface = routing_new_interface,
        .delete_interface = routing_delete_interface,
        .new_local_address = routing_new_local_address,
        .delete_local_address = routing_delete_local_address
};

static int routing_init(struct mptcpd_pm *pm)
{
        (void) pm;

        ids = l_uintset_new(USHRT_MAX);

        sock_conf = init_socket(0, &pid_conf);

        if (sock_conf == NULL)
                return EXIT_FAILURE;

        info = l_queue_new();

        sock_routes = init_socket(RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE,
                                  &pid_routes);

        if (sock_routes == NULL)
                return EXIT_FAILURE;

        //verify errors
        struct l_io *io = l_io_new(mnl_socket_get_fd(sock_routes));
        l_io_set_close_on_destroy(io, true);
        l_io_set_read_handler(io, routing_handler, NULL, NULL);

        if (dump_routes(AF_INET) < 0) {
                l_error("failed to dump ipv4 routes");
                return EXIT_FAILURE;
        }

        if (dump_routes(AF_INET6) < 0) {
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

