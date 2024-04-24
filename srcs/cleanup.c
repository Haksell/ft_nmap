#include "ft_nmap.h"

extern pcap_t* handle_lo[MAX_HOSTNAMES];
extern pcap_t* handle_net[MAX_HOSTNAMES];

void cleanup(t_nmap* nmap) {
    // TODO close mutex's
    if (nmap->devs) pcap_freealldevs(nmap->devs);
    for (int i = 0; i < nmap->num_handles; ++i) {
        if (handle_net[i]) pcap_close(handle_net[i]);
        if (handle_lo[i]) pcap_close(handle_lo[i]);
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
