#ifndef ___ROUTING_TYPES_H___
#define ___ROUTING_TYPES_H___

#include <stdint.h>
#include <arpa/inet.h>
#include <ell/queue.h>

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

typedef void (* route_op) (uint8_t family,
                           uint8_t prefix_len,
                           struct nlattr const **tb);
//convenience struct
struct route_ops {
        route_op new_route;
        route_op del_route;
};

#endif
