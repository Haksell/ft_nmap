#include "ft_nmap.h"

extern volatile sig_atomic_t run;
extern pthread_mutex_t mutex_run;
extern t_thread_globals thread_globals[MAX_HOSTNAMES];

void handle_sigint(__attribute__((unused)) int sig) {
    pthread_mutex_lock(&mutex_run);
    run = false;
    pthread_mutex_unlock(&mutex_run);
    for (int i = 0; i < MAX_HOSTNAMES; ++i) {
        if (thread_globals[i].handle_net) pcap_breakloop(thread_globals[i].handle_net);
        if (thread_globals[i].handle_lo) pcap_breakloop(thread_globals[i].handle_lo);
    }
}

void set_signals() {
    struct sigaction sa_int;

    sa_int.sa_handler = handle_sigint;
    sigemptyset(&sa_int.sa_mask);
    sa_int.sa_flags = 0;
    sigaction(SIGINT, &sa_int, NULL);
}
