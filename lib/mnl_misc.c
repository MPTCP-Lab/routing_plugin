#include <ell/util.h>
#include <ell/log.h>

#include <linux/rtnetlink.h>

#include <routing/private/mnl_misc>
#include <routing/private/types>

struct mnl_socket *init_socket(uint32_t groups, uint32_t *pid)
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

int data_cb(struct nlmsghdr const *nl, void *data)
{
        struct route_ops const *const ops = data;
        
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
                ops->new_route(rt->rtm_family,
                               rt->rtm_dst_len,
                               tb);
                break;

        case RTM_DELROUTE:
                ops->del_route(rt->rtm_family,
                               rt->rtm_dst_len,
                               tb);
                break;
        }

        return MNL_CB_OK;
}
