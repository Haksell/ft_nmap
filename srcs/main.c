#include "ft_nmap.h"

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
//         case SCAN_ACK: tcph->ack = 1; break;
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

    nmap->fd = socket(
        AF_INET, SOCK_RAW, IPPROTO_TCP
    ); // faudra un deuxieme socket pour les paquets UDP //  a reflechir dans l'avenir si on cree un
       // socket pour chaque type de scan. en multi-threading avec 255 threads, on peut faire 255
       // scans en meme temps, mais donc faut-il 255 sockets en meme temps ? Ou poll va
       // automatiquement gerer ca ? sur ping meme avec flood ça passe, donc bon
    if (nmap->fd < 0) error("Socket creation failed");

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

int main(int argc, char* argv[]) {
    nmap nmap = {0};

    verify_arguments(argc, argv, &nmap);
    hostname_to_ip(&nmap);
    create_socket(&nmap);

    print_ports(nmap.ports);
    print_scans(nmap.scans);

    printf("hostname: %s\n", nmap.hostname);

    signal(SIGINT, handle_sigint); // TODO: sigaction instead of signal

    // struct sockaddr_in target = {.sin_family = AF_INET, .sin_addr.s_addr =
    // inet_addr(nmap.hostip)};

    // struct iphdr iphdr = {
    //     .version  = 4,
    //     .ihl      = 5,
    //     .tos      = 0,
    //     .tot_len  = sizeof(struct iphdr) + sizeof(struct tcphdr), // peut etre Options: (4
    //     bytes), Maximum segment size .id       = htons(getpid()), // thread id? Random pour
    //     l'instant .frag_off = 0, .ttl      = 64, // randint(28, 63) .protocol = IPPROTO_TCP,
    //     .check    = 0,
    //     .saddr    = inet_addr("192.168.0.1"), // TODO! spoof
    //     .daddr    = target.sin_addr.s_addr,
    // };

    // struct tcphdr tcphdr = {
    //     .source = htons(1234), // TODO! randomize
    //     .dest   = htons(80), // TODO! randomize
    //     .seq    = 0, // TODO! randomize peut etre
    //     .ack_seq = 0,  // a voir apres pour ACK
    //     .doff   = 5, // 5 * 32 bits = 160 bits = 20 bytes
    //     .fin    = 0,
    //     .syn    = 1,
    //     .rst    = 0,
    //     .psh    = 0,
    //     .ack    = 0,
    //     .urg    = 0,
    //     .window = htons(5840),
    //     .check  = 0,
    //     .urg_ptr = 0,
    // };

    for (int port = 0; port < UINT16_MAX && run; port++) {
        if (!get_port(nmap.ports, port)) continue;
    }

    close(nmap.fd);
    return EXIT_SUCCESS;
}
