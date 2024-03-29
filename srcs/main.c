#include "ft_nmap.h"

volatile sig_atomic_t run = true;
volatile sig_atomic_t sender_finished = false;
pcap_t* handle = NULL;

static void init(t_nmap* nmap) {
    if (geteuid() != 0) {
        fprintf(stderr, "This program requires root privileges for raw socket creation.\n");
        exit(EXIT_FAILURE);
    }

    nmap->tcp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (nmap->tcp_fd < 0) error("TCP socket creation failed");
    nmap->udp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (nmap->udp_fd < 0) error("UDP socket creation failed"); // look next comment
    nmap->icmp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (nmap->icmp_fd < 0) error("ICMP socket creation failed"); // open fd leaks -> error -> exit -> cleanup

    if (setsockopt(nmap->tcp_fd, IPPROTO_IP, IP_HDRINCL, &(int){1}, sizeof(int)) < 0)
        error("setsockopt IP_HDRINCL failed");
    if (setsockopt(nmap->udp_fd, IPPROTO_IP, IP_HDRINCL, &(int){1}, sizeof(int)) < 0)
        error("setsockopt IP_HDRINCL failed");

    get_start_time(nmap);

    if (nmap->opt & OPT_VERBOSE) {
        print_hostnames(nmap);
        print_ports(nmap);
        print_scans(nmap->scans);
    }
}

int main(int argc, char* argv[]) {
    t_nmap nmap = {0};

    verify_arguments(argc, argv, &nmap);
    init(&nmap);
    set_signals();
    init_pcap(&nmap);

    pthread_t capture_thread, sender_thread;
    if (pthread_create(&capture_thread, NULL, capture_packets, &nmap) != 0)
        panic("Failed to create the capture thread");
    if (pthread_create(&sender_thread, NULL, send_packets, &nmap) != 0) panic("Failed to create the sender thread");
    pthread_join(capture_thread, NULL);
    pthread_join(sender_thread, NULL);

    print_stats(&nmap);
    cleanup(&nmap);
    return EXIT_SUCCESS;
}
