#include "ft_nmap.h"

extern pcap_t* handle;

// #define FILTER_EXP "src host 45.33.32.156 and tcp[tcpflags] & (tcp-syn|tcp-ack) =
// (tcp-syn|tcp-ack)"

void set_filter(t_nmap* nmap) {
    struct bpf_program fp;

    char filter_exp[128] = {0};
    // TODO: UDP and exact flags

    sprintf(
        filter_exp,
        "(icmp) or (%s and src host %s and dst port %d)", // a changer
        nmap->current_scan == SCAN_UDP ? "udp" : "tcp",
        nmap->hostip,
        nmap->port_source
    );

    if (pcap_compile(handle, &fp, filter_exp, 0, nmap->net_device) == PCAP_ERROR)
        panic("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    if (pcap_setfilter(handle, &fp) == PCAP_ERROR)
        panic("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    pcap_freecode(&fp);
}

void init_pcap(t_nmap* nmap) {
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&nmap->devs, errbuf) == PCAP_ERROR)
        panic("Couldn't find all devices: %s\n", errbuf); // TODO error
    char* dev = nmap->devs->name;

    // NULL, XMAS et FIN marchent uniquement sur localhost, j'ai pas trouve d'autres sites... donc on doit
    // changer le device a lo. C'est pas propre mais c'est pour tester.
    if (strcmp(nmap->hosts[0].name, "localhost") == 0) strncpy(dev, "lo\0", 3);

    bpf_u_int32 _;
    if (pcap_lookupnet(dev, &nmap->net_device, &_, errbuf) == PCAP_ERROR)
        panic("Couldn't get netmask for device %s: %s\n", dev, errbuf);

    handle = pcap_open_live(dev, SNAP_LEN, 1, 1, errbuf);
    if (handle == NULL) panic("Couldn't open device %s: %s\n", dev, errbuf);
    if (pcap_datalink(handle) != DLT_EN10MB) panic("%s is not an Ethernet\n", dev);
}
