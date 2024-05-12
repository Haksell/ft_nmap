#include "ft_nmap.h"

extern volatile sig_atomic_t run;
extern pthread_mutex_t mutex_run;
extern t_thread_globals thread_globals[MAX_HOSTNAMES];

void cleanup(t_nmap* nmap) {
    for (size_t i = 0; nmap->mutexes[i]; ++i) pthread_mutex_destroy(nmap->mutexes[i]);
    if (nmap->devs) pcap_freealldevs(nmap->devs);
    for (uint16_t i = 0; i < nmap->num_handles; ++i) {
        if (thread_globals[i].handle_net) pcap_close(thread_globals[i].handle_net);
        if (thread_globals[i].handle_lo) pcap_close(thread_globals[i].handle_lo);
    }
    if (nmap->tcp_fd > 2) close(nmap->tcp_fd);
    if (nmap->udp_fd > 2) close(nmap->udp_fd);
    if (nmap->icmp_fd > 2) close(nmap->icmp_fd);
}

void error(char* message) { panic("nmap: %s: %s\n", message, strerror(errno)); }

void stop() {
    pthread_mutex_lock(&mutex_run);
    run = false;
    pthread_mutex_unlock(&mutex_run);
    for (int i = 0; i < MAX_HOSTNAMES; ++i) {
        if (thread_globals[i].handle_net) pcap_breakloop(thread_globals[i].handle_net);
        if (thread_globals[i].handle_lo) pcap_breakloop(thread_globals[i].handle_lo);
    }
}

void panic(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    stop();
}
