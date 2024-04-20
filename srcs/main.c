#include "ft_nmap.h"
#include "pcap/pcap.h"

volatile sig_atomic_t run = true;

// TODO: t_thread_globals
volatile sig_atomic_t sender_finished[MAX_HOSTNAMES];
volatile sig_atomic_t hostname_finished[MAX_HOSTNAMES];
pcap_t* handle_lo[MAX_HOSTNAMES];
pcap_t* handle_net[MAX_HOSTNAMES];
pcap_t* current_handle[MAX_HOSTNAMES];

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

    if (setsockopt(nmap->tcp_fd, IPPROTO_IP, IP_HDRINCL, &(int){1}, sizeof(int)) < 0) error("setsockopt IP_HDRINCL failed");
    if (setsockopt(nmap->udp_fd, IPPROTO_IP, IP_HDRINCL, &(int){1}, sizeof(int)) < 0) error("setsockopt IP_HDRINCL failed");

    struct timeval tv = {.tv_sec = 3};
    if (setsockopt(nmap->icmp_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv) < 0) perror("setsockopt SO_RCVTIMEO failed");

    get_start_time(nmap);

    if (nmap->opt & OPT_VERBOSE) {
        print_hostnames(nmap);
        print_ports(nmap, "Sequential ports", nmap->port_array);
        if (!(nmap->opt & OPT_NO_RANDOMIZE)) print_ports(nmap, "    Random ports", nmap->random_port_array);
        print_scans(nmap->scans);
    }
}

int main(int argc, char* argv[]) {
    t_nmap nmap = {0};

    verify_arguments(argc, argv, &nmap);
    init(&nmap);
    set_signals();
    init_pcap(&nmap);

    // TODO: init_mutexes
    pthread_mutex_init(&nmap.mutex_print_report, NULL);
    pthread_mutex_init(&nmap.mutex_up_count, NULL);
    pthread_mutex_init(&nmap.mutex_scanned_count, NULL);

    if (nmap.num_threads == 0) send_packets(&(t_thread_info){.nmap = &nmap, .t_index = 0});
    for (int i = 0; i < nmap.num_threads; ++i) {
        nmap.threads[i] = (t_thread_info){.nmap = &nmap, .t_index = i};
        if (pthread_create(&nmap.threads[i].thread_id, NULL, send_packets, nmap.threads + i)) panic("Failed to create the sender thread");
    }

    // maybe detach instead
    for (int i = 0; i < nmap.num_threads; ++i) pthread_join(nmap.threads[i].thread_id, NULL);

    // TODO close mutex's
    print_stats(&nmap);
    cleanup(&nmap);
    return EXIT_SUCCESS;
}
