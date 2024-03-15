#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// Pseudo header needed for TCP checksum calculation
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

// Generic checksum calculation function
unsigned short checksum(void* b, int len) {
    unsigned short* buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <target IP> <target port>\n", argv[0]);
        exit(1);
    }

    int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (s < 0) {
        perror("Failed to create socket");
        exit(1);
    }

    char datagram[4096], source_ip[32];
    struct iphdr* iph = (struct iphdr*)datagram;
    struct tcphdr* tcph = (struct tcphdr*)(datagram + sizeof(struct ip));
    struct sockaddr_in dest;
    struct pseudo_header psh;

    strcpy(source_ip, "192.168.1.1"); // Source IP, change accordingly
    dest.sin_family = AF_INET;
    dest.sin_port = htons(atoi(argv[2]));
    dest.sin_addr.s_addr = inet_addr(argv[1]);

    memset(datagram, 0, 4096);

    // Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
    iph->id = htonl(54321); // Id of this packet
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;                    // Set to 0 before calculating checksum
    iph->saddr = inet_addr(source_ip); // Spoof the source ip address
    iph->daddr = dest.sin_addr.s_addr;

    // IP checksum
    iph->check = checksum((unsigned short*)datagram, iph->tot_len);

    // TCP Header
    tcph->source = htons(12345);
    tcph->dest = htons(atoi(argv[2]));
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5; // tcp header size
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(5840); /* maximum allowed window size */
    tcph->check = 0;            // leave checksum 0 now, filled later by pseudo header
    tcph->urg_ptr = 0;

    // Now the TCP checksum
    psh.source_address = inet_addr(source_ip);
    psh.dest_address = dest.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    static const int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char pseudogram[psize];

    memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

    tcph->check = checksum((unsigned short*)pseudogram, psize);

    // IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int* val = &one;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("Error setting IP_HDRINCL");
        exit(1);
    }

    // Send the packet
    if (sendto(s, datagram, iph->tot_len, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        perror("sendto failed");
    } else {
        printf("Packet Sent\n");
    }

    return 0;
}
