#include "ft_nmap.h"

#define MAX_CONCURRENT_CONNECT 512
// TODO: fix with multithreading

extern volatile sig_atomic_t run;

static void set_port_and_host_state(t_thread_info* th_info, port_state port_state, uint16_t port) {
    th_info->nmap->hosts[th_info->h_index].is_up = true;
    set_port_state(th_info, port_state, port);
}

// TODO: same code for UDP?

static void scan_connect_range(t_thread_info* th_info, uint16_t* loop_port_array, int start, int end) {
    t_nmap* nmap = th_info->nmap;
    fd_set fd_read, fd_all;
    int max_fd = 0;

    FD_ZERO(&fd_all);

    struct sockaddr_in targets[end - start];
    int fds[end - start];

    for (int port_index = start; port_index < end && run; ++port_index) {
        int port = loop_port_array[port_index];
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)); // TODO: remove?
        if (fd < 0) {
            error("Connect socket creation failed");
            continue;
        }

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1) error("fcntl F_GETFL failed");
        if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) error("fcntl F_SETFL failed");

        struct sockaddr_in target = {
            .sin_family = AF_INET,
            .sin_port = htons(port),
            .sin_addr = th_info->hostaddr.sin_addr};
        targets[port_index - start] = target;
        fds[port_index - start] = fd;

        if (connect(fd, (struct sockaddr*)&targets[port_index - start], sizeof(target)) == -1 && errno != EINPROGRESS) {
            set_port_and_host_state(th_info, PORT_CLOSED, port);
        } else {
            FD_SET(fd, &fd_all);
            if (fd > max_fd) {
                max_fd = fd;
            }
        }
    }

    long microseconds = 2000000 + 8000 * (end - start);
    struct timeval tv = {.tv_sec = microseconds / 1000000, .tv_usec = microseconds % 1000000};

    while (run) {
        fd_read = fd_all;

        int res = select(max_fd + 1, NULL, &fd_read, NULL, &tv);
        if (res < 0) error("select failed");
        if (res == 0) break;

        for (int port_index = start; port_index < end; ++port_index) {
            if (fds[port_index - start] > 0 && FD_ISSET(fds[port_index - start], &fd_read)) {
                int so_error;
                socklen_t len = sizeof so_error;

                getsockopt(fds[port_index - start], SOL_SOCKET, SO_ERROR, &so_error, &len);

                if (so_error == 0) {
                    set_port_and_host_state(th_info, PORT_OPEN, loop_port_array[port_index]);
                } else if (so_error == ECONNREFUSED) {
                    set_port_and_host_state(th_info, PORT_CLOSED, loop_port_array[port_index]);
                }

                FD_CLR(fds[port_index - start], &fd_all);
                close(fds[port_index - start]);
                fds[port_index - start] = -1;
            }
        }
        if (nmap->hosts[th_info->h_index].undefined_count[th_info->current_scan] == 0) break;
    }
    for (int port_index = start; port_index < end; ++port_index) close(fds[port_index - start]);
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
