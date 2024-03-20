#include "ft_nmap.h"

volatile sig_atomic_t run = true;

static void handle_sigint(int sig) {
    (void)sig;
    run = false;
}

static void create_socket(nmap* nmap) {
    if (geteuid() != 0) {
        fprintf(stderr, "This program requires root privileges for raw socket creation.\n");
        exit(EXIT_FAILURE);
    }

    nmap->fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (nmap->fd < 0) error("TCP socket creation failed");

    if (setsockopt(nmap->fd, IPPROTO_IP, IP_HDRINCL, &(int){1}, sizeof(int)) < 0)
        error("setsockopt IP_HDRINCL failed");

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
    nmap* nmap = (nmap*)arg;
    for (int port = 0; port < UINT16_MAX && run; port++) {
        if (!get_port(nmap->ports, port)) continue;

        uint8_t packet[NMAP_PACKET_SIZE /*+data eventuellement*/];
        fill_packet(packet, target, port);
        sendto(nmap.fd, packet, NMAP_PACKET_SIZE, 0, (struct sockaddr*)&target, sizeof(target));
    }
}

int main(int argc, char* argv[]) {
    nmap nmap = {0};

    verify_arguments(argc, argv, &nmap);
    hostname_to_ip(&nmap);
    create_socket(&nmap);

    signal(SIGINT, handle_sigint); // TODO: sigaction instead of signal

    struct sockaddr_in target = {.sin_family = AF_INET, .sin_addr.s_addr = inet_addr(nmap.hostip)};

    close(nmap.fd);
    return EXIT_SUCCESS;
}
