#include "ft_nmap.h"
#include <bits/pthreadtypes.h>

extern volatile sig_atomic_t run;
extern pcap_t* handle_lo[MAX_HOSTNAMES];
extern pcap_t* handle_net[MAX_HOSTNAMES];
extern pthread_mutex_t mutex_run;

void handle_sigint(__attribute__((unused)) int sig) {
    pthread_mutex_lock(&mutex_run);
    run = false;
    pthread_mutex_unlock(&mutex_run);
    for (int i = 0; i < MAX_HOSTNAMES; ++i) {
        if (handle_net[i]) pcap_breakloop(handle_net[i]);
        if (handle_lo[i]) pcap_breakloop(handle_lo[i]);
    }
}

void set_signals() {
    struct sigaction sa_int;

    sa_int.sa_handler = handle_sigint;
    sigemptyset(&sa_int.sa_mask);
    sa_int.sa_flags = 0;
    sigaction(SIGINT, &sa_int, NULL);
}
