#include "ft_nmap.h"
#include "pcap/pcap.h"
#include <bits/pthreadtypes.h>

volatile sig_atomic_t run = true;
pthread_mutex_t mutex_run;
// TODO: t_thread_globals
volatile sig_atomic_t sender_finished[MAX_HOSTNAMES];
volatile sig_atomic_t hostname_finished[MAX_HOSTNAMES];
pcap_t* handle_lo[MAX_HOSTNAMES];
pcap_t* handle_net[MAX_HOSTNAMES];
pcap_t* current_handle[MAX_HOSTNAMES];

static void init_mutex(t_nmap* nmap, pthread_mutex_t* mutex) {
    static int mutex_initialized = 0;

    if (pthread_mutex_init(mutex, NULL) == -1) error("failed to initialize mutex");
    nmap->mutexes[mutex_initialized] = mutex;
    ++mutex_initialized;
}

static void init(t_nmap* nmap) {
    if (geteuid() != 0) {
        // TODO: connect
        panic("This program requires root privileges for raw socket creation.\n");
    }

    nmap->source_address = get_source_address();

    nmap->tcp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (nmap->tcp_fd < 0) error("TCP socket creation failed");
    nmap->udp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (nmap->udp_fd < 0) error("UDP socket creation failed");
    nmap->icmp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (nmap->icmp_fd < 0) error("ICMP socket creation failed");

    if (setsockopt(nmap->tcp_fd, IPPROTO_IP, IP_HDRINCL, &(int){1}, sizeof(int)) < 0) error("setsockopt IP_HDRINCL failed");
    if (setsockopt(nmap->udp_fd, IPPROTO_IP, IP_HDRINCL, &(int){1}, sizeof(int)) < 0) error("setsockopt IP_HDRINCL failed");

    struct timeval tv = {.tv_sec = 3};
    if (setsockopt(nmap->icmp_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv) < 0) perror("setsockopt SO_RCVTIMEO failed");

    print_start_time(nmap);

    if (nmap->hostname_count == 0) fprintf(stderr, "WARNING: No targets were specified, so 0 hosts scanned.\n");

    if (nmap->opt & OPT_VERBOSE) {
        print_hostnames(nmap);
        print_ports(nmap, "Sequential ports", nmap->port_array);
        if (!(nmap->opt & OPT_NO_RANDOMIZE)) print_ports(nmap, "    Random ports", nmap->random_port_array);
        print_scans(nmap->scans);
    }

    set_signals();
    init_pcap(nmap);

    init_mutex(nmap, &nmap->mutex_print_report);
    init_mutex(nmap, &nmap->mutex_undefined_count);
    init_mutex(nmap, &nmap->mutex_hostname_finished);
    init_mutex(nmap, &nmap->mutex_unset_filters);
    init_mutex(nmap, &mutex_run);
}

static void final_credits(t_nmap* nmap) {
    int hosts_up = 0;
    for (int i = 0; i < nmap->hostname_count; ++i) hosts_up += nmap->hosts[i].is_up;
    printf("\nnmap done: %d IP addresses (%d hosts up) scanned in %.2f seconds\n", nmap->hostname_count, hosts_up, (get_microseconds() - nmap->start_time) / 1000000.0);
}

int main(int argc, char* argv[]) {
    t_nmap nmap = {0};
    verify_arguments(argc, argv, &nmap);
    init(&nmap);

    if (nmap.num_threads == 0) send_packets(&(t_thread_info){.nmap = &nmap, .t_index = 0});
    for (int i = 0; i < nmap.num_threads; ++i) {
        nmap.threads[i] = (t_thread_info){.nmap = &nmap, .t_index = i};
        if (pthread_create(&nmap.threads[i].thread_id, NULL, send_packets, nmap.threads + i)) panic("Failed to create the sender thread");
    }

    // maybe detach instead
    for (int i = 0; i < nmap.num_threads; ++i) pthread_join(nmap.threads[i].thread_id, NULL);

    final_credits(&nmap);
    cleanup(&nmap);
    return EXIT_SUCCESS;
}
