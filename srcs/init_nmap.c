#include "ft_nmap.h"

extern pthread_mutex_t mutex_run;

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

static void print_start_time(t_nmap* nmap) {
    nmap->start_time = get_microseconds();
    time_t epoch_secs = nmap->start_time / 1000000;
    struct tm* tm = localtime(&epoch_secs);

    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M %Z", tm);
    printf("Starting nmap %s at %s\n", VERSION, timestamp);
}

void init_nmap(t_nmap* nmap) {
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
