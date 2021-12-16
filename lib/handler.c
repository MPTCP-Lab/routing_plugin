#include <ell/util.h>
#include <ell/io.h>

#include <linux/rtnetlink.h>

#include <routing/private/handler.h>
#include <routing/private/mnl_misc.h>

static struct mnl_socket *sock;
static uint32_t pid;

static struct l_io *io;

static bool routing_handler(struct l_io *io, void *user_data)
{
        (void) io;

        L_AUTO_FREE_VAR(uint8_t *, buf) =
                l_malloc(MNL_SOCKET_BUFFER_SIZE);

        ssize_t ret = 
                mnl_socket_recvfrom(sock,
                                    buf,
                                    MNL_SOCKET_BUFFER_SIZE);

        if(ret > 0)
                ret = mnl_cb_run(buf, ret, 0, pid, data_cb, user_data);

        return ret >= 0;
}

bool init_handler(struct route_ops const *const ops)
{
        sock = init_socket(RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE, &pid);

        if (sock == NULL)
                return false;
        //verify errors
        io = l_io_new(mnl_socket_get_fd(sock));

        return l_io_set_read_handler(io, routing_handler,(void *) ops, NULL);
}

void destroy_handler(void)
{
        l_io_destroy(io);

        mnl_socket_close(sock);
}
