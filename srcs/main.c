#include "ft_nmap.h"

volatile sig_atomic_t run = true;

void handle_sigint(int sig) {
    (void)sig;
    run = false;
}

struct pseudo_header { // pour calculer le checksum TODO
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder; // doit rester a 0
    uint8_t protocol;
    uint16_t tcp_length;
}; // http://www.tcpipguide.com/free/t_TCPChecksumCalculationandtheTCPPseudoHeader-2.htm
// https://www.tenouk.com/Module43.html << top

void set_tcp_flags(struct tcphdr* tcph, int type) {
    tcph->urg = 0, tcph->ack = 0, tcph->psh = 0, tcph->rst = 0, tcph->syn = 0, tcph->fin = 0;

    switch (type) {
        case SCAN_SYN: tcph->syn = 1; break;
        case SCAN_NULL: break;
        case SCAN_ACK: tcph->ack = 1; break;
        case SCAN_FIN: tcph->fin = 1; break;
        case SCAN_XMAS:
            tcph->fin = 1;
            tcph->urg = 1;
            tcph->psh = 1;
            break;
    }
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

    // struct tcphdr* tcph;
    // memset(&tcph, 0, sizeof(tcph));
    // set_tcp_flags(tcph, SCAN_SYN);

    for (int port = 0; port < UINT16_MAX && run; port++) {
        if (!get_port(nmap.ports, port)) continue;

        // pro: randomize source port for no detection -> sequentielle et on est detecté
        // randomize type of scan -> de facon random on change de type de scan (multi-threading?)
        /* pseudocode qui est illogique
            port = rand() % remaning_ports
            type = rand() % remaning_types
            if (!get_port(namp.ports, port, SCAN_FIN) set_port(nmap.ports, port, SCAN_FIN) -> on a
           scanné ce port avec FIN, donc on va pas le refaire if (setport a set tout a 0)
           remaning_ports-- (i know ca marche pas comme ça, mais le concept est de raccourcir la
           liste de ports a scanner a chaque fois qu'on en a fully scanné un) if (type.count ==
           total_ports) remaning_types-- (meme concept que pour les ports, mais pour les types de
           scan) if (remaning_ports == 0) break; (si on a scanné tous les ports, on sort de la
           boucle)

            print results (que il faudra donc stocker dans une structure. a diffrence de ping, nmap
           a besoin de stocker les resultats pour les afficher a la fin). justement parce-que il
           randomize les ports et les types de scan, il pourra pas afficher les resultats dans
           l'ordre.

        */

        // TODO creer un header TCP (regarder ping.c pour exemple de header IP
        // TODO creer un pseudo header
        // TODO calculer le checksum
        // TODO envoyer le paquet
    }

    close(nmap.fd);
    return EXIT_SUCCESS;
}