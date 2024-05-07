#include "ft_nmap.h"

extern t_thread_globals thread_globals[MAX_HOSTNAMES];

void cleanup(t_nmap* nmap) {
    for (int i = 0; nmap->mutexes[i]; ++i) pthread_mutex_destroy(nmap->mutexes[i]);
    if (nmap->devs) pcap_freealldevs(nmap->devs);
    for (int i = 0; i < nmap->num_handles; ++i) {
        if (thread_globals[i].handle_net) pcap_close(thread_globals[i].handle_net);
        if (thread_globals[i].handle_lo) pcap_close(thread_globals[i].handle_lo);
    }
    if (nmap->tcp_fd > 2) close(nmap->tcp_fd);
    if (nmap->udp_fd > 2) close(nmap->udp_fd);
    if (nmap->icmp_fd > 2) close(nmap->icmp_fd);
}

void error(char* message) { panic("nmap: %s: %s\n", message, strerror(errno)); }

void panic(const char* format, ...) {
    // TODO: free everything
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    exit(EXIT_FAILURE);
}
