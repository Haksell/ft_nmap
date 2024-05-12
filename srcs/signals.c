#include "ft_nmap.h"

extern t_thread_globals thread_globals[MAX_HOSTNAMES];

void handle_sigint(__attribute__((unused)) int sig) {
    stop();
}

void set_signals() {
    struct sigaction sa_int;

    sa_int.sa_handler = handle_sigint;
    sigemptyset(&sa_int.sa_mask);
    sa_int.sa_flags = 0;
    sigaction(SIGINT, &sa_int, NULL);
}
