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

    if (!(nmap->opt & OPT_PORTS)) {
        for (int i = 0; i < 16; ++i) nmap->port_set[i] = ~0;
        nmap->port_set[0] ^= 1;
        nmap->port_set[16] = 1;
    }
    if (!(nmap->opt & OPT_SCAN)) nmap->scans = ~0;

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
    for (int i = 0; i < nmap->hostname_count; ++i) {
        hostname_to_ip(nmap);
        // TODO: local hostaddr
        nmap->hostaddr = (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = inet_addr(nmap->hostip)};
        // TODO: ports array instead of bitset
        for (int port = 0; port <= UINT16_MAX && run; port++) {
            if (get_port(nmap->port_set, port)) {
                uint8_t packet[NMAP_PACKET_SIZE /*+data eventuellement*/];
                fill_packet(packet, nmap->hostaddr, port);
                sendto(
                    nmap->fd, packet, NMAP_PACKET_SIZE, 0, (struct sockaddr*)&nmap->hostaddr, sizeof(nmap->hostaddr)
                );
            }
        }
        // printf(
        //     "Nmap scan report for %s (%s)\n"
        //     "Host is up (0.0019s latency).\n" // TODO LORENZO PING
        //     "rDNS record for %s: fra15s10-in-f14.1e100.net\n", // TODO LORENZO DNS
        //     nmap->hostnames[i], nmap->hostip, nmap->hostnames[i]
        // );

        // if (0)
        //     printf("Not shown: 58 filtered tcp ports (no-response)\n");

        // printf("PORT   STATE SERVICE\n");

        // for (int i = 0; int < tota)
        //     "80/tcp open  http"
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
    if (pthread_create(&capture_thread, NULL, capture_packets, NULL) != 0) panic("Failed to create the capture thread");
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
