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

void send_ping(t_nmap* nmap) {
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
    gettimeofday(&ping_time, NULL);
    memcpy(packet + ICMP_HDR_SIZE, &ping_time, sizeof(struct timeval));

    icmphdr.checksum = calculate_checksum((uint16_t*)packet, icmp_packet_size);
    memcpy(packet, &icmphdr, ICMP_HDR_SIZE);

    int bytes_sent = sendto(
        nmap->icmp_fd,
        packet,
        icmp_packet_size,
        0,
        (struct sockaddr*)&nmap->hostaddr,
        sizeof(struct sockaddr_in)
    );
    if (bytes_sent < 0) error("Sending ping failed");
}

void handle_echo_reply(t_nmap* nmap, uint8_t* reply_packet) {
    struct timeval now;

    gettimeofday(&now, NULL);
    nmap->latency = timeval_subtract(*(struct timeval*)reply_packet, now);
    nmap->hostname_up_count++;
}
