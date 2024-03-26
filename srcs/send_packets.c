#include "ft_nmap.h"

extern bool run;

void* send_packets(void* arg) {
    t_nmap* nmap = (t_nmap*)arg;
    for (; nmap->hostname_index < nmap->hostname_count; ++nmap->hostname_index) {
        hostname_to_ip(nmap);
        nmap->hostaddr = (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = inet_addr(nmap->hostip)};
        // TODO: local hostaddr. ça veut dire quoi?
        send_ping(nmap);

        // je suis fatigue, donc c'est pas ouf, mais la logique est la.
        // si t'arrives à faire un truc plus elegant, go
        int old_hostname_up_count = nmap->hostname_up_count;
        struct timeval countdown = {.tv_usec = 300000}; // 3s -> MACRO
        while (nmap->hostname_up_count == old_hostname_up_count && countdown.tv_usec > 0 && run) {
            usleep(1000); // 1ms
            countdown.tv_usec -= 1000; // 1ms
        }
        if (countdown.tv_usec <= 0) { // si apres 3s, le hostname_up_count (qui augmente sur ping handle_echo_reply) n'a
                                      // pas change, alors le host est down
            printf(
                "Host %s is down.\n",
                nmap->hostnames[nmap->hostname_index]
            ); // a print uniquement si le seul host est down, donc pas ici // Lorenzo
            continue;
        }

        for (int i = 0; i < SCAN_MAX; ++i) {
            nmap->current_scan = i;
            if ((nmap->scans & (1 << i)) == 0) continue;

            nmap->port_source = random_u32_range(1 << 15, UINT16_MAX);
            set_filter(nmap);
            // TODO: shuffle
            for (int j = 0; j < nmap->port_count && run; ++j) {
                uint16_t port = nmap->port_array[j];
                uint8_t packet[NMAP_PACKET_SIZE /*+data eventuellement*/];
                fill_packet(packet, nmap, port);
                sendto(
                    nmap->fd,
                    packet,
                    NMAP_PACKET_SIZE,
                    0,
                    (struct sockaddr*)&nmap->hostaddr,
                    sizeof(nmap->hostaddr)
                );
            }

            alarm(1);
            while (nmap->undefined_count[nmap->hostname_index][nmap->current_scan] > 0)
                usleep(1000); // TODO: no forbidden functions
            alarm(0);
        }
        print_scan_report(nmap);
    }
    handle_sigint(SIGINT);
    return NULL;
}
