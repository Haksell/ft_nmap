#include "ft_nmap.h"

extern volatile sig_atomic_t run;
extern pcap_t* handle_lo[MAX_HOSTNAMES];
extern pcap_t* handle_net[MAX_HOSTNAMES];
extern pcap_t* current_handle[MAX_HOSTNAMES];

void handle_sigint(__attribute__((unused)) int sig) {
    run = false;
    for (int i = 0; i < MAX_HOSTNAMES; ++i) {
        if (handle_net[i]) pcap_breakloop(handle_net[i]);
        if (handle_lo[i]) pcap_breakloop(handle_lo[i]);
    }
}

static void handle_sigalrm(__attribute__((unused)) int sig) {
    // TODO: last multithreading problem
    if (current_handle[0]) pcap_breakloop(current_handle[0]);
}

void set_signals() {
    struct sigaction sa_int, sa_alrm;

    sa_int.sa_handler = handle_sigint;
    sigemptyset(&sa_int.sa_mask);
    sa_int.sa_flags = 0;
    sigaction(SIGINT, &sa_int, NULL);

    sa_alrm.sa_handler = handle_sigalrm;
    sigemptyset(&sa_alrm.sa_mask);
    sa_alrm.sa_flags = 0;
    sigaction(SIGALRM, &sa_alrm, NULL);
}

/*
0369
147
258
*/
