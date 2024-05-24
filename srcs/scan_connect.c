#include "ft_nmap.h"

extern volatile sig_atomic_t run;

static void set_port_and_host_state(t_thread_info* th_info, t_port_state port_state, uint16_t port) {
    th_info->host->is_up = true;
    set_port_state(th_info, port_state, port);
}

void scan_connect(t_thread_info* th_info) {
    t_nmap* nmap = th_info->nmap;
    uint16_t port_count = th_info->nmap->port_count;
    struct pollfd fds[port_count];
    struct sockaddr_in targets[port_count];

    for (int i = 0; i < port_count && run; ++i) {
        uint16_t actual_index = nmap->opt & OPT_NO_RANDOMIZE ? i : nmap->random_indices[i];
        int port = nmap->port_array[actual_index];
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) error("SCAN_CONN socket creation failed");
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
            error("setsockopt SO_REUSEADDR failed");

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1) error("fcntl F_GETFL failed");
        if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) error("fcntl F_SETFL failed");

        struct sockaddr_in target = {
            .sin_family = AF_INET,
            .sin_port = htons(port),
            .sin_addr = th_info->hostaddr.sin_addr,
        };
        targets[i] = target;
        fds[i].fd = fd;
        fds[i].events = POLLOUT;

        if (connect(fd, (struct sockaddr*)&targets[i], sizeof(target)) == -1 && errno != EINPROGRESS) {
            set_port_and_host_state(th_info, PORT_CLOSED, port);
        }
    }

    uint64_t full_timeout = th_info->latency == 0 ? 3000000 : 2 * th_info->latency + 1000000;
    uint64_t start_time = get_microseconds();

    while (run) {
        uint64_t us_since_start = get_microseconds() - start_time;
        uint64_t remaining_timeout = full_timeout - us_since_start;
        uint64_t timeout_us = us_since_start >= full_timeout || remaining_timeout <= 200000 ? 200000
                                                                                            : remaining_timeout;

        int res = poll(fds, port_count, timeout_us / 1000);
        if (res == 0 || errno == EINTR) break;
        if (res < 0) error("poll failed");

        for (int i = 0; i < port_count; ++i) {
            if (fds[i].revents & POLLOUT || fds[i].revents & POLLERR) {
                uint16_t actual_index = nmap->opt & OPT_NO_RANDOMIZE ? i : nmap->random_indices[i];
                int so_error;
                if (getsockopt(fds[i].fd, SOL_SOCKET, SO_ERROR, &so_error, &(socklen_t){sizeof(so_error)}) == -1)
                    error("getsockopt failed");
                if (so_error == 0) set_port_and_host_state(th_info, PORT_OPEN, nmap->port_array[actual_index]);
                else if (so_error == ECONNREFUSED)
                    set_port_and_host_state(th_info, PORT_CLOSED, nmap->port_array[actual_index]);

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
