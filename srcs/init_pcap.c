#include "ft_nmap.h"
#include <stdio.h>

extern pcap_t* handle;

// #define FILTER_EXP "src host 45.33.32.156 and tcp[tcpflags] & (tcp-syn|tcp-ack) =
// (tcp-syn|tcp-ack)"

void set_filter(t_nmap* nmap) {
    struct bpf_program fp;

    char filter_exp[64] = {0};
    // TODO: UDP and exact flags
    sprintf(filter_exp, "src host %s and dst port %d", nmap->hostip, nmap->port_source);

    if (pcap_compile(handle, &fp, filter_exp, 0, nmap->net_device) == PCAP_ERROR)
        panic("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    if (pcap_setfilter(handle, &fp) == PCAP_ERROR)
        panic("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    pcap_freecode(&fp);
}

void init_pcap(t_nmap* nmap) {
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&nmap->devs, errbuf) == PCAP_ERROR) panic("Couldn't find all devices: %s\n", errbuf);
    char* dev = nmap->devs->name;

    bpf_u_int32 _;
    if (pcap_lookupnet(dev, &nmap->net_device, &_, errbuf) == PCAP_ERROR)
        panic("Couldn't get netmask for device %s: %s\n", dev, errbuf);

    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) panic("Couldn't open device %s: %s\n", dev, errbuf);
    if (pcap_datalink(handle) != DLT_EN10MB) panic("%s is not an Ethernet\n", dev);
}
