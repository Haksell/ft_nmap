#include "ft_nmap.h"

extern pthread_mutex_t mutex_run;

extern t_thread_globals thread_globals[MAX_HOSTNAMES];

static void handle_sigint(__attribute__((unused)) int sig) { stop(); }

static void set_signals() {
    struct sigaction sa_int;

    sa_int.sa_handler = handle_sigint;
    sigemptyset(&sa_int.sa_mask);
    sa_int.sa_flags = 0;
    sigaction(SIGINT, &sa_int, NULL);
}

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
    printf("Starting nmap %s", VERSION);
    nmap->start_time = get_microseconds();
    time_t epoch_secs = nmap->start_time / 1000000;
    struct tm* tm = localtime(&epoch_secs);

    if (tm) {
        char timestamp[32];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M %Z", tm);
        printf(" at %s\n", timestamp);
    } else printf("\n");
}

static in_addr_t get_source_address() {
    struct ifaddrs *ifaddr, *ifa;
    in_addr_t source_address = 0;

    if (getifaddrs(&ifaddr) == -1) error("getifaddrs failed");

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_INET) {
            if (strcmp(ifa->ifa_name, "lo") == 0) continue;
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)ifa->ifa_addr;
            source_address = ipv4->sin_addr.s_addr;
            break;
        }
    }

    freeifaddrs(ifaddr);
    return source_address;
}

static void get_service_name(uint16_t port, const char* proto, char buffer[MAX_SERVICE_LEN + 1]) {
    struct servent* service = getservbyport(htons(port), proto);
    char* service_name = service ? service->s_name : "unknown";
    strncpy(buffer, service_name, MAX_SERVICE_LEN);
    buffer[MAX_SERVICE_LEN] = '\0';
}

static void get_service_names(t_nmap* nmap) {
    for (uint16_t port_index = 0; port_index < nmap->port_count; ++port_index) {
        uint16_t port = nmap->port_array[port_index];
        get_service_name(port, "tcp", nmap->tcp_services[port_index]);
        get_service_name(port, "udp", nmap->udp_services[port_index]);
    }
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

    set_signals();
    if (nmap->is_sudo) init_pcap(nmap);

    init_mutex(nmap, &nmap->mutex_print);
    init_mutex(nmap, &nmap->mutex_undefined_count);
    init_mutex(nmap, &nmap->mutex_pcap_filter);
    init_mutex(nmap, &mutex_run);

    if (nmap->opt & OPT_VERBOSE) print_init_verbose(nmap);
}
