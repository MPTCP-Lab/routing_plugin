#ifndef ___ROUTING_HANDLER___
#define ___ROUTING_HANDLER___

#include <stdbool.h>
#include "types.h"

bool init_handler(struct route_ops const *const ops);

void destroy_handler(void);

#endif
