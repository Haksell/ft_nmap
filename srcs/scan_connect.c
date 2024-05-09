#include "ft_nmap.h"

#define MAX_CONCURRENT_CONNECT 512
// TODO: fix with multithreading

extern volatile sig_atomic_t run;

static void set_port_and_host_state(t_thread_info* th_info, port_state port_state, uint16_t port) {
    th_info->host->is_up = true;
    set_port_state(th_info, port_state, port);
}

// TODO: same code for UDP?

static void scan_connect_range(t_thread_info* th_info, uint16_t* loop_port_array, int start, int end) {
    struct pollfd fds[end - start];
    int nfds = 0;

    struct sockaddr_in targets[end - start];

    for (int port_index = start; port_index < end && run; ++port_index) {
        int port = loop_port_array[port_index];
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) error("Connect socket creation failed");

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1) error("fcntl F_GETFL failed");
        if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) error("fcntl F_SETFL failed");

        struct sockaddr_in target = {
            .sin_family = AF_INET,
            .sin_port = htons(port),
            .sin_addr = th_info->hostaddr.sin_addr
        };
        targets[port_index - start] = target;
        fds[nfds].fd = fd;
        fds[nfds].events = POLLOUT;
        nfds++;

        if (connect(fd, (struct sockaddr*)&targets[port_index - start], sizeof(target)) == -1 && errno != EINPROGRESS) {
            set_port_and_host_state(th_info, PORT_CLOSED, port);
        }
    }

    int timeout = 2000 + 8 * (end - start); // Timeout in milliseconds

    while (run) {
        int res = poll(fds, nfds, timeout);
        if (res == 0 || errno == EINTR) break;
        if (res < 0) error("poll failed");

        for (int i = 0; i < nfds; ++i) {
            if (fds[i].revents & POLLOUT || fds[i].revents & POLLERR) {
                int so_error;
                socklen_t len = sizeof(so_error);

                getsockopt(fds[i].fd, SOL_SOCKET, SO_ERROR, &so_error, &len);

                if (so_error == 0) {
                    set_port_and_host_state(th_info, PORT_OPEN, loop_port_array[start + i]);
                } else if (so_error == ECONNREFUSED) {
                    set_port_and_host_state(th_info, PORT_CLOSED, loop_port_array[start + i]);
                }

                close(fds[i].fd);
                fds[i].fd = -1; // Mark as closed
            }
        }

        if (th_info->host->undefined_count[th_info->current_scan] == 0) break;
    }

    for (int i = 0; i < nfds; ++i) {
        if (fds[i].fd != -1) {
            close(fds[i].fd);
        }
    }
}

void scan_connect(t_thread_info* th_info, uint16_t* loop_port_array) {
    for (uint16_t start = 0; start < th_info->nmap->port_count; start += MAX_CONCURRENT_CONNECT) {
        scan_connect_range(
            th_info,
            loop_port_array,
            start,
            MIN(start + MAX_CONCURRENT_CONNECT, th_info->nmap->port_count)
        );
    }
    set_default_port_states(th_info);
}
