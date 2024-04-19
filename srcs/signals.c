#include "ft_nmap.h"

extern volatile sig_atomic_t run;
extern pcap_t *handle_net, *handle_lo, *current_handle;

void handle_sigint(__attribute__((unused)) int sig) {
    run = false;
    if (handle_net) pcap_breakloop(handle_net);
    if (handle_lo) pcap_breakloop(handle_lo);
}

static void handle_sigalrm(__attribute__((unused)) int sig) {
    if (current_handle) pcap_breakloop(current_handle);
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
