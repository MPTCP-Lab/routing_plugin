#ifndef ___ROUTING_MNL_OPS___
#define ___ROUTING_MNL_OPS___

#include <stdbool.h>
#include "types.h"

bool init_mnl_ops(void);

void destroy_mnl_ops(void);

bool create_table(struct addr_info *addr);

void conf_gw(void *data, void *user_data);

void conf_dst(void *data, void *user_data);

bool delete_table(uint8_t family, uint32_t table_id);

void deconf_gw(void *data, void *user_data);

void deconf_dst(void *data, void *user_data);

ssize_t dump_routes(uint8_t family, struct route_ops const *const ops);

#endif
