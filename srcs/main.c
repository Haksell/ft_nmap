#include "ft_nmap.h"
#include "pcap/pcap.h"
#include <netinet/in.h>

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
        for (int i = 0; i < 16; ++i) nmap->ports[i] = ~0;
        nmap->ports[0] ^= 1;
        nmap->ports[16] = 1;
    }
    if (!(nmap->opt & OPT_SCAN)) nmap->scans = ~0;

    gettimeofday(&nmap->start_time, NULL);
    struct tm* tm = localtime(&nmap->start_time.tv_sec);
    char timestamp[21];
    strftime(timestamp, 21, "%Y-%m-%d %H:%M CET", tm);
    printf("Starting Nmap %s at %s\n", VERSION, timestamp);

    if (nmap->opt & OPT_VERBOSE) {
        print_ports(nmap->ports);
        print_scans(nmap->scans);
        printf("Host: %s (%s)\n", nmap->hostname, nmap->hostip);
    }
}

static void* send_packets(void* arg) {
    t_nmap* nmap = (t_nmap*)arg;
    for (int port = 0; port < UINT16_MAX && run; port++) {
        if (get_port(nmap->ports, port)) {
            uint8_t packet[NMAP_PACKET_SIZE /*+data eventuellement*/];
            fill_packet(packet, nmap->hostaddr, port);
            sendto(nmap->fd, packet, NMAP_PACKET_SIZE, 0, (struct sockaddr*)&nmap->hostaddr, sizeof(nmap->hostaddr));
        }
    }
    return NULL;
}

int main(int argc, char* argv[]) {
    t_nmap nmap = {0};

    verify_arguments(argc, argv, &nmap);
    hostname_to_ip(&nmap);
    create_socket(&nmap);
    signal(SIGINT, handle_sigint); // TODO: sigaction instead of signal
    nmap.hostaddr = (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = inet_addr(nmap.hostip)};

    capture_args_t capture_args = {.devs = NULL, .handle = NULL};
    init_pcap(&capture_args);

    pthread_t capture_thread, sender_thread;
    if (pthread_create(&capture_thread, NULL, capture_packets, (void*)&capture_args) != 0)
        panic("Failed to create the capture thread");
    if (pthread_create(&sender_thread, NULL, send_packets, &nmap) != 0) panic("Failed to create the sender thread");
    pthread_join(capture_thread, NULL);
    pthread_join(sender_thread, NULL);

    if (capture_args.devs) pcap_freealldevs(capture_args.devs);
    if (capture_args.handle) pcap_close(capture_args.handle);

    close(nmap.fd);
    return EXIT_SUCCESS;
}
