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
        if (!(nmap->opt & OPT_NO_RANDOMIZE)) print_ports(nmap, "    Random ports", nmap->random_port_array);
        print_scans(nmap->scans);
    }
}

static pthread_t create_capture_thread(t_capture_args* args) {
    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, capture_packets, args)) panic("Failed to create the capture thread");
    return thread_id;
}

int main(int argc, char* argv[]) {
    t_nmap nmap = {0};

    verify_arguments(argc, argv, &nmap);
    init(&nmap);
    set_signals();
    init_pcap(&nmap);

    pthread_t capture_thread_lo = create_capture_thread(&(t_capture_args){.nmap = &nmap, .handle = handle_lo});
    pthread_t capture_thread_net = create_capture_thread(&(t_capture_args){.nmap = &nmap, .handle = handle_net});

    if (nmap.threads == 0) send_packets(&(t_send_args){.nmap = &nmap, .thread_id = 0});
    for (int i = 0; i < nmap.threads; ++i) {
        if (pthread_create(nmap.sender_threads + i, NULL, send_packets, &(t_send_args){.nmap = &nmap, .thread_id = i}))
            panic("Failed to create the sender thread");
    }

    for (int i = 0; i < nmap.threads; ++i) pthread_join(nmap.sender_threads[i], NULL);
    pthread_join(capture_thread_lo, NULL);
    pthread_join(capture_thread_net, NULL);

    print_stats(&nmap);
    cleanup(&nmap);
    return EXIT_SUCCESS;
}
