#include <time.h>
#include <limits.h>

#include <linux/fib_rules.h>

#include <ell/util.h>
#include <ell/uintset.h>
#include <ell/log.h>

#include <routing/private/mnl_ops.h>
#include <routing/private/mnl_misc.h>

static struct mnl_socket *sock = NULL;
static uint32_t pid;

static struct l_uintset *ids;

bool init_mnl_ops(void)
{
        ids = l_uintset_new(USHRT_MAX);

        sock = init_socket(0, &pid);

        if (sock == NULL)
                return false;

        return true;
}

void destroy_mnl_ops(void)
{
        if (sock != NULL) {
                mnl_socket_close(sock);

                l_uintset_free(ids);
        }
}

static ssize_t nlm_comm(void *buf,
                        size_t len,
                        uint32_t seq,
                        mnl_cb_t fun,
                        void *user_data)
{
        if (mnl_socket_sendto(sock, buf, len) < 0) {
                l_error("failed to send");
                return -1; //maybe return error
        }

        ssize_t ret = mnl_socket_recvfrom(sock,
                                          buf,
                                          MNL_SOCKET_BUFFER_SIZE);

        while (ret > 0) {
                ret = mnl_cb_run(buf, ret, seq, pid, fun, user_data);

                if (ret <= MNL_CB_STOP)
                        break;

                ret = mnl_socket_recvfrom(sock,
                                          buf,
                                          MNL_SOCKET_BUFFER_SIZE);
        }

        return ret;
}

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
        nl->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;

        uint32_t seq = time(NULL);
        nl->nlmsg_seq = seq;

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
        return nlm_comm(buf, nl->nlmsg_len, seq, NULL, NULL);
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
        nl->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;

        uint32_t seq = time(NULL);
        nl->nlmsg_seq = seq;

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

        return nlm_comm(buf, nl->nlmsg_len, seq, NULL, NULL);
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

        ssize_t ret = nlm_comm(buf, nl->nlmsg_len, seq, rule_cb, NULL);

        if (ret == -1) {
                l_error("failed to retrieve tables ids");
                return 0;
        }

        return l_uintset_find_unused_min(ids);
}

bool create_table(struct addr_info *addr)
{
        uint32_t table_id = get_table_id();

        if(table_id == 0) //l_error
                return false;

        if (netlink_rule(RTM_NEWRULE,
                         NLM_F_CREATE | NLM_F_EXCL,
                         addr->family, 
                         table_id,
                         &addr->addr) < 0)
                return false; //l_error

        l_uintset_put(ids, table_id); //verify return

        addr->table_id = table_id;

        return true;
}

void conf_gw(void *data, void *user_data)
{
        struct addr_info *addr = data;
        struct user_data *conf_info = user_data;

        if (addr->family != conf_info->family)
                return;

        if (addr->table_id == 0 && !create_table(addr))
                return;

        //check return
        netlink_route(RTM_NEWROUTE,
                      NLM_F_CREATE | NLM_F_EXCL,
                      addr->table_id,
                      RT_SCOPE_UNIVERSE,
                      RTA_GATEWAY,
                      user_data);

}

void conf_dst(void *data, void *user_data)
{
        struct addr_info *addr = data;
        struct user_data *conf_info = user_data;

        if (addr->family != conf_info->family)
                return;

        if (addr->table_id == 0 && !create_table(addr))
                return;

        //check return
        netlink_route(RTM_NEWROUTE,
                      NLM_F_CREATE | NLM_F_EXCL,
                      addr->table_id,
                      RT_SCOPE_LINK,
                      RTA_DST,
                      user_data);
}

bool delete_table(uint8_t family, uint32_t table_id)
{
        if(table_id == 0) //l_error
                return false;

        return netlink_rule(RTM_DELRULE,
                            0,
                            family,
                            table_id,
                            NULL) >= 0;
}

void deconf_gw(void *data, void *user_data)
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

void deconf_dst(void *data, void *user_data)
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
                              RT_SCOPE_LINK,
                              RTA_DST,
                              user_data);
}


ssize_t dump_routes(uint8_t family, struct route_ops const *const ops)
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

        return nlm_comm(buf, nl->nlmsg_len, seq, data_cb, (void *) ops);
}
