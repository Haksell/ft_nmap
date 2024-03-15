#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

char* stringify(bpf_u_int32 maskp) {
    struct in_addr addr;
    addr.s_addr = maskp;
    char* mask = inet_ntoa(addr);
    if (mask == NULL) {
        perror("inet_ntoa");
        exit(1);
    }
    return mask;
}

int main(int argc, char** argv) {
    char errbuf[PCAP_ERRBUF_SIZE];

    char* dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("DEV: %s\n", dev);
    bpf_u_int32 netp, maskp;
    if (pcap_lookupnet(dev, &netp, &maskp, errbuf) == -1) {
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("NET: %s\n", stringify(netp));
    printf("MASK: %s\n", stringify(maskp));
    return EXIT_SUCCESS;
}
