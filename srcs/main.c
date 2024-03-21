#include "ft_nmap.h"

volatile sig_atomic_t run = true;
pcap_t* handle = NULL;

static void handle_sigint(int sig) {
    (void)sig;
    run = false;
    if (handle) pcap_breakloop(handle);
}

static void create_socket(t_nmap* nmap) {
    if (geteuid() != 0) {
        fprintf(stderr, "This program requires root privileges for raw socket creation.\n");
        exit(EXIT_FAILURE);
    }

    nmap->fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (nmap->fd < 0) error("TCP socket creation failed");

    if (setsockopt(nmap->fd, IPPROTO_IP, IP_HDRINCL, &(int){1}, sizeof(int)) < 0) error("setsockopt IP_HDRINCL failed");

    gettimeofday(&nmap->start_time, NULL);
    struct tm* tm = localtime(&nmap->start_time.tv_sec);
    char timestamp[21];
    strftime(timestamp, 21, "%Y-%m-%d %H:%M CET", tm);
    printf("Starting Nmap %s at %s\n", VERSION, timestamp);

    if (nmap->opt & OPT_VERBOSE) {
        print_hostnames(nmap);
        print_ports(nmap);
        print_scans(nmap->scans);
        printf("Host: %s (%s)\n", nmap->hostnames[0], nmap->hostip);
    }
}

static void* send_packets(void* arg) {
    t_nmap* nmap = (t_nmap*)arg;
    for (; nmap->hostname_index < nmap->hostname_count; ++nmap->hostname_index) {
        hostname_to_ip(nmap);
        // TODO: local hostaddr
        nmap->hostaddr = (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = inet_addr(nmap->hostip)};
        nmap->port_source = random_u32_range(1 << 15, UINT16_MAX);
        // TODO: shuffle
        for (int j = 0; j <= nmap->port_count && run; ++j) {
            uint16_t port = nmap->port_array[j];
            uint8_t packet[NMAP_PACKET_SIZE /*+data eventuellement*/];
            fill_packet(packet, nmap, port);
            sendto(nmap->fd, packet, NMAP_PACKET_SIZE, 0, (struct sockaddr*)&nmap->hostaddr, sizeof(nmap->hostaddr));
        }
        printf("Nmap scan report for %s (%s)\n", nmap->hostnames[nmap->hostname_index], nmap->hostip);
        printf("Host is up (0.0019s latency).\n"); // TODO LORENZO PING
        printf(
            "rDNS record for %s: fra15s10-in-f14.1e100.net\n", nmap->hostnames[nmap->hostname_index]
        ); // TODO LORENZO DNS uniquement s'il a trouve le dns

        // if (0)
        //     printf("Not shown: 58 filtered tcp ports (no-response)\n");

        printf("\nPORT   STATE SERVICE\n"); // TODO align styleeeeee'

        for (int j = 0; j < nmap->port_count; ++j)
            printf(
                "%d/tcp %s  http\n", nmap->port_array[j], port_state_str[nmap->port_states[nmap->hostname_index][j]]
            );
    }
    return NULL;
}

int main(int argc, char* argv[]) {
    t_nmap nmap = {0};

    verify_arguments(argc, argv, &nmap);
    create_socket(&nmap);
    signal(SIGINT, handle_sigint); // TODO: sigaction instead of signal

    init_pcap(&nmap.devs);

    pthread_t capture_thread, sender_thread;
    if (pthread_create(&capture_thread, NULL, capture_packets, &nmap) != 0)
        panic("Failed to create the capture thread");
    // TODO: multiple sender threads
    if (pthread_create(&sender_thread, NULL, send_packets, &nmap) != 0) panic("Failed to create the sender thread");
    pthread_join(capture_thread, NULL);
    pthread_join(sender_thread, NULL);

    // TODO: print results

    if (nmap.devs) pcap_freealldevs(nmap.devs);
    if (handle) pcap_close(handle);

    close(nmap.fd);
    return EXIT_SUCCESS;
}
