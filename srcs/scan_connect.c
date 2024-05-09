#include "ft_nmap.h"

extern volatile sig_atomic_t run;

static void set_port_and_host_state(t_thread_info* th_info, port_state port_state, uint16_t port) {
    th_info->host->is_up = true;
    set_port_state(th_info, port_state, port);
}

void scan_connect(t_thread_info* th_info, uint16_t* loop_port_array) {
    uint16_t port_count = th_info->nmap->port_count;
    struct pollfd fds[port_count];
    struct sockaddr_in targets[port_count];

    for (int port_index = 0; port_index < port_count && run; ++port_index) {
        int port = loop_port_array[port_index];
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) error("Connect socket creation failed");

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1) error("fcntl F_GETFL failed");
        if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) error("fcntl F_SETFL failed");

        struct sockaddr_in target = {
            .sin_family = AF_INET,
            .sin_port = htons(port),
            .sin_addr = th_info->hostaddr.sin_addr};
        targets[port_index] = target;
        fds[port_index].fd = fd;
        fds[port_index].events = POLLOUT;

        if (connect(fd, (struct sockaddr*)&targets[port_index], sizeof(target)) == -1 && errno != EINPROGRESS) {
            set_port_and_host_state(th_info, PORT_CLOSED, port);
        }
    }

    int timeout = 2000 + 8 * port_count; // TODO: better timeout

    while (run) {
        int res = poll(fds, port_count, timeout);
        if (res == 0 || errno == EINTR) break;
        if (res < 0) error("poll failed");

        for (int i = 0; i < port_count; ++i) {
            // TODO: POLLOUT = PORT_OPEN, POLLERR = PORT_CLOSED
            if (fds[i].revents & POLLOUT || fds[i].revents & POLLERR) {
                int so_error;
                getsockopt(fds[i].fd, SOL_SOCKET, SO_ERROR, &so_error, &(socklen_t){sizeof(so_error)});

                if (so_error == 0) {
                    set_port_and_host_state(th_info, PORT_OPEN, loop_port_array[i]);
                } else if (so_error == ECONNREFUSED) {
                    set_port_and_host_state(th_info, PORT_CLOSED, loop_port_array[i]);
                }

                close(fds[i].fd);
                fds[i].fd = -1;
            }
        }

        if (th_info->host->undefined_count[th_info->current_scan] == 0) break;
    }

    for (int i = 0; i < port_count; ++i) {
        if (fds[i].fd != -1) {
            close(fds[i].fd);
        }
    }
    set_default_port_states(th_info);
}
