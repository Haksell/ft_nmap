#include "ft_nmap.h"

extern volatile sig_atomic_t run;
extern pcap_t* handle;

void handle_sigint(int sig) {
    (void)sig;
    run = false;
    if (handle) pcap_breakloop(handle);
}

static void handle_sigalrm(int sig) {
    (void)sig;
    if (handle) pcap_breakloop(handle);
}

// TODO: sigaction instead of signal
void set_signals() {
    signal(SIGINT, handle_sigint);
    signal(SIGALRM, handle_sigalrm);
}
