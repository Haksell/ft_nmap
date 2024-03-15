#include "ft_nmap.h"
#include <sys/types.h>

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

enum PortState { OPEN, CLOSED, FILTERED, UNDETERMINED };

enum PortState get_port_state(const uint8_t* packet, ssize_t len) {
    struct iphdr* ip_header = (struct iphdr*)packet;
    int ip_header_len = ip_header->ihl * 4;

    if (ip_header->protocol == IPPROTO_TCP) {
        if (len < (ssize_t)(ip_header_len + sizeof(struct tcphdr))) {
            return UNDETERMINED; // Packet is too short to contain a complete TCP header ??
        }

        struct tcphdr* tcp_header = (struct tcphdr*)(packet + ip_header_len);

        if (tcp_header->syn && tcp_header->ack) {
            printf("%d open\n", ntohs(tcp_header->source));
        } else if (tcp_header->rst) {
            return CLOSED;
        }
    } else if (ip_header->protocol == IPPROTO_ICMP) {
        printf("ICMP\n");
    }

    return UNDETERMINED; // Unable to determine the state from the packet
}

void process_received_packet(const uint8_t* packet, ssize_t len) { get_port_state(packet, len); }

int main(int argc, char* argv[]) {
    nmap nmap = {0};

    verify_arguments(argc, argv, &nmap);
    hostname_to_ip(&nmap);
    create_socket(&nmap);

    signal(SIGINT, handle_sigint); // TODO: sigaction instead of signal

    struct sockaddr_in target = {.sin_family = AF_INET, .sin_addr.s_addr = inet_addr(nmap.hostip)};
    struct pollfd fds[1] = {
        {.fd = nmap.fd, .events = POLLIN}
    };

    for (int port = 0; port < UINT16_MAX && run; port++) {
        if (!get_port(nmap.ports, port)) continue;

        uint8_t packet[NMAP_PACKET_SIZE /*+data eventuellement*/];
        fill_packet(packet, target, port);
        sendto(nmap.fd, packet, NMAP_PACKET_SIZE, 0, (struct sockaddr*)&target, sizeof(target));

        int ret = poll(fds, 1, 1000); // 1 second, a voir
        if (ret > 0) {
            if (fds[0].revents & POLLIN) {
                struct sockaddr_in source;
                socklen_t source_len = sizeof(source);
                uint8_t reply[1024]; // macro

                ssize_t bytes_recv = recvfrom(
                    nmap.fd, reply, sizeof(reply), 0, (struct sockaddr*)&source, &source_len
                );
                // if (source.sin_addr.s_addr != target.sin_addr.s_addr) continue; TOOD: more checks
                if (bytes_recv < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        printf("Request timed out.\n"); // changer ca TODO je dois lire la doc
                    }
                    if (errno == EINTR && !run) continue; /// ????
                } else if (bytes_recv > 0) {
                    process_received_packet(reply, bytes_recv);
                }
            }
        } else if (ret == 0) {
            printf("Timeout\n");
        } else {
            error("poll failed");
        }
    }

    close(nmap.fd);
    return EXIT_SUCCESS;
}
