#include "ft_nmap.h"
#include "pcap/pcap.h"

volatile sig_atomic_t run = true;
volatile sig_atomic_t sender_finished = false;
pcap_t* handle_lo = NULL;
pcap_t* handle_net = NULL;
pcap_t* current_handle = NULL;

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

    struct timeval tv = {.tv_sec = 3};
    if (setsockopt(nmap->icmp_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv) < 0)
        perror("setsockopt SO_RCVTIMEO failed");

    get_start_time(nmap);

    if (nmap->opt & OPT_VERBOSE) {
        print_hostnames(nmap);
        print_ports(nmap, "Sequential ports", nmap->port_array);
        if (!(nmap->opt & OPT_RANDOMIZE)) print_ports(nmap, "    Random ports", nmap->random_port_array);
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
    capture_args args_lo = {.nmap = &nmap, .handle = handle_lo};
    capture_args args_net = {.nmap = &nmap, .handle = handle_net};
    if (pthread_create(&capture_thread, NULL, capture_packets, &args_lo))
        panic("Failed to create the capture lo thread");
    if (pthread_create(&capture_thread, NULL, capture_packets, &args_net))
        panic("Failed to create the capture lo thread");
    if (pthread_create(&sender_thread, NULL, send_packets, &nmap) != 0) panic("Failed to create the sender thread");
    pthread_join(capture_thread, NULL);
    pthread_join(sender_thread, NULL);

    print_stats(&nmap);
    cleanup(&nmap);
    return EXIT_SUCCESS;
}
