#include "ft_nmap.h"

static uint16_t calculate_checksum(uint16_t* packet, int length) {
    uint32_t sum = 0;

    while (length > 1) {
        sum += *packet++;
        length -= 2;
    }

    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)~sum;
}

void send_ping(t_thread_info* th_info) {
    struct icmphdr icmphdr = {
        .type = ICMP_ECHO,
        .code = 0,
        .checksum = 0,
        .un.echo.id = htons(getpid() & 0xFFFF),
        .un.echo.sequence = 0,
    };

    int icmp_packet_size = ICMP_HDR_SIZE + sizeof(struct timeval);
    uint8_t packet[icmp_packet_size];

    memcpy(packet, &icmphdr, ICMP_HDR_SIZE);

    struct timeval ping_time;
    if (gettimeofday(&ping_time, NULL) == -1) error("gettimeofday failed");
    memcpy(packet + ICMP_HDR_SIZE, &ping_time, sizeof(struct timeval));

    icmphdr.checksum = calculate_checksum((uint16_t*)packet, icmp_packet_size);
    memcpy(packet, &icmphdr, ICMP_HDR_SIZE);

    sendto(
        th_info->nmap->icmp_fd,
        packet,
        icmp_packet_size,
        0,
        (struct sockaddr*)&th_info->hostaddr,
        sizeof(struct sockaddr_in)
    );
}
