#ifndef ___ROUTING_MNL_MISC___
#define ___ROUTING_MNL_MISC___

#include <stdint.h>
#include <libmnl/libmnl.h>

struct mnl_socket *init_socket(uint32_t groups, uint32_t *pid);

int data_cb(struct nlmsghdr const *nl, void *data);

#endif
