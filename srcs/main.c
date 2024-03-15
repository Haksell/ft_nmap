#include "ft_nmap.h"
#include <sys/types.h>

volatile sig_atomic_t run = true;

// http://www.tcpipguide.com/free/t_TCPChecksumCalculationandtheTCPPseudoHeader-2.htm
// https://www.tenouk.com/Module43.html << top
// struct pseudo_header { // pour calculer le checksum TODO
//     uint32_t source_address;
//     uint32_t dest_address;
//     uint8_t placeholder; // doit rester a 0
//     uint8_t protocol;
//     uint16_t tcp_length;
// };

static void handle_sigint(int sig) {
    (void)sig;
    run = false;
}

// static void set_tcp_flags(struct tcphdr* tcph, int type) {
//     tcph->urg = 0, tcph->ack = 0, tcph->psh = 0, tcph->rst = 0, tcph->syn = 0, tcph->fin = 0;

//     switch (type) {
//         case SCAN_SYN: tcph->syn = 1; break;
//         case SCAN_NULL: break;
//         case SCANdoff_ACK: tcph->ack = 1; break;
//         case SCAN_FIN: tcph->fin = 1; break;
//         case SCAN_XMAS:
//             tcph->fin = 1;
//             tcph->urg = 1;
//             tcph->psh = 1;
//             break;
//     }
// }

static void create_socket(nmap* nmap) {
    if (geteuid() != 0) {
        fprintf(stderr, "This program requires root privileges for raw socket creation.\n");
        exit(EXIT_FAILURE);
    }

    nmap->fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (nmap->fd < 0) error("Socket creation failed");

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
}

uint16_t tcp_checksum(struct pseudohdr* pseudohdr, struct tcphdr* tcphdr) {
    int packet_size = sizeof(struct pseudohdr) + sizeof(struct tcphdr);

    uint8_t checksum_packet[packet_size];
    memcpy(checksum_packet, pseudohdr, sizeof(struct pseudohdr));
    memcpy(checksum_packet + sizeof(struct pseudohdr), tcphdr, sizeof(struct tcphdr));

    uint16_t p_checksum_packet[packet_size / 2];

    for (int i = 0; i < packet_size / 2; i++) {
        p_checksum_packet[i] = (checksum_packet[i * 2] << 8) + checksum_packet[i * 2 + 1];
    }

    uint32_t sum = 0;
    for (int i = 0; i < packet_size / 2; i++) {
        sum += p_checksum_packet[i];
    }

    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)~sum;
}

uint16_t ip_checksum(void* vdata, size_t length) {
    char* data = vdata;
    uint32_t acc = 0xffff;

    for (size_t i = 0; i + 1 < length; i += 2) {
        uint16_t word;
        memcpy(&word, data + i, 2);
        acc += ntohs(word);
        if (acc > 0xffff) acc -= 0xffff;
    }

    if (length & 1) {
        uint16_t word = 0;
        memcpy(&word, data + length - 1, 1);
        acc += ntohs(word);
        if (acc > 0xffff) acc -= 0xffff;
    }

    return htons(~acc);
}

void fill_packet(uint8_t* packet, struct sockaddr_in target, short port) {
    struct tcphdr tcphdr = {
        .source = htons(37216), // TODO! randomize
        .dest = htons(port),
        .seq = 0, // TODO! randomize peut etre
        .ack_seq = 0, // a voir apres pour ACK
        .doff = 5, // 5 * 32 bits = 160 bits = 20 bytes || sur nmap Header Length: 24 bytes (6)
        .fin = 0,
        .syn = 1,
        .rst = 0,
        .psh = 0,
        .ack = 0,
        .urg = 0,
        .window = htons(1024), // pas sur
        .check = 0,
        .urg_ptr = 0,
    };

    struct iphdr iphdr = {
        .version = 4,
        .ihl = 5,
        .tos = 0,
        .tot_len = htons(sizeof(iphdr) + sizeof(tcphdr)),
        .id = htons(random_u32_range(0, UINT16_MAX)),
        .frag_off = 0,
        .ttl = random_u32_range(33, 63),
        .protocol = IPPROTO_TCP,
        .check = 0,
        .saddr = get_source_address(), // spoof possible?
        .daddr = target.sin_addr.s_addr,
    };

    iphdr.check = ip_checksum(&iphdr, sizeof(iphdr));

    struct pseudohdr pseudohdr = {
        .saddr = iphdr.saddr,
        .daddr = iphdr.daddr,
        .reserved = 0,
        .protocol = iphdr.protocol,
        .tcp_length = htons(sizeof(tcphdr)),
    };

    tcphdr.check = htons(tcp_checksum(&pseudohdr, &tcphdr));

    memcpy(packet, &iphdr, sizeof(iphdr));
    memcpy(packet + sizeof(iphdr), &tcphdr, sizeof(tcphdr));
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

void process_received_packet(const uint8_t* packet, ssize_t len) {
    get_port_state(packet, len);
}

int main(int argc, char* argv[]) {
    nmap nmap = {0};

    verify_arguments(argc, argv, &nmap);
    hostname_to_ip(&nmap);
    create_socket(&nmap);

    // print_ports(nmap.ports);
    // print_scans(nmap.scans);
    // printf("hostname: %s\n", nmap.hostname);
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