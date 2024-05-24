#include "ft_nmap.h"

volatile sig_atomic_t run = true;
pthread_mutex_t mutex_run;
t_thread_globals thread_globals[MAX_HOSTNAMES];

static void error_init(t_nmap* nmap, char* message) {
    error(message);
    cleanup(nmap);
}

static void init_mutex(t_nmap* nmap, pthread_mutex_t* mutex) {
    static size_t mutex_initialized = 0;

    if (pthread_mutex_init(mutex, NULL) == -1) error("failed to initialize mutex");
    nmap->mutexes[mutex_initialized] = mutex;
    ++mutex_initialized;
}

static void init(t_nmap* nmap) {
    get_service_names(nmap);
    if (!(nmap->opt & OPT_SPOOF_ADDRESS)) nmap->source_address = get_source_address();

    if (nmap->is_sudo) {
        nmap->tcp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (nmap->tcp_fd < 0) error_init(nmap, "TCP socket creation failed");
        nmap->udp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if (nmap->udp_fd < 0) error_init(nmap, "UDP socket creation failed");
        nmap->icmp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (nmap->icmp_fd < 0) error_init(nmap, "ICMP socket creation failed");
        if (setsockopt(nmap->tcp_fd, IPPROTO_IP, IP_HDRINCL, &(int){1}, sizeof(int)) < 0)
            error_init(nmap, "setsockopt IP_HDRINCL failed");
        if (setsockopt(nmap->udp_fd, IPPROTO_IP, IP_HDRINCL, &(int){1}, sizeof(int)) < 0)
            error_init(nmap, "setsockopt IP_HDRINCL failed");
        if (setsockopt(nmap->icmp_fd, SOL_SOCKET, SO_BROADCAST, &(int){1}, sizeof(int)) < 0)
            error_init(nmap, "setsockopt SO_BROADCAST failed");
    }

    print_start_time(nmap);

    if (nmap->hostname_count == 0) fprintf(stderr, "WARNING: No targets were specified, so 0 hosts scanned.\n");

    if (nmap->opt & OPT_VERBOSE) {
        print_hostnames(nmap);
        print_ports(nmap, "Sequential ports", nmap->port_array);
        if (!(nmap->opt & OPT_NO_RANDOMIZE)) print_ports(nmap, "Random indices", nmap->random_indices);
        print_scans(nmap->scans);
    }

    set_signals();
    if (nmap->is_sudo) init_pcap(nmap);

    init_mutex(nmap, &nmap->mutex_print);
    init_mutex(nmap, &nmap->mutex_undefined_count);
    init_mutex(nmap, &nmap->mutex_pcap_filter);
    init_mutex(nmap, &mutex_run);
}

static void final_credits(t_nmap* nmap) {
    uint16_t hosts_up = 0;
    for (uint16_t i = 0; i < nmap->hostname_count; ++i) hosts_up += nmap->hosts[i].is_up;
    printf(
        "\nnmap done: %d IP addresses (%d hosts up) scanned in %.2f seconds\n",
        nmap->hostname_count,
        hosts_up,
        (get_microseconds() - nmap->start_time) / 1000000.0
    );
}

int main(int argc, char* argv[]) {
    t_nmap nmap = {0};
    verify_arguments(argc, argv, &nmap);
    init(&nmap);

    if (nmap.num_threads == 0)
        send_packets(&(t_thread_info){
            .nmap = &nmap,
            .globals = thread_globals[0],
            .t_index = 0,
        });
    for (nmap.started_threads = 0; nmap.started_threads < nmap.num_threads && run; ++nmap.started_threads) {
        nmap.threads[nmap.started_threads] = (t_thread_info){
            .nmap = &nmap,
            .globals = thread_globals[nmap.started_threads],
            .t_index = nmap.started_threads,
        };
        if (pthread_create(
                &nmap.threads[nmap.started_threads].thread_id,
                NULL,
                send_packets,
                nmap.threads + nmap.started_threads
            ))
            panic("Failed to create the sender thread");
    }

    for (int i = 0; i < nmap.num_threads; ++i) pthread_join(nmap.threads[i].thread_id, NULL);
    if (run) final_credits(&nmap);
    cleanup(&nmap);
    return EXIT_SUCCESS;
}
