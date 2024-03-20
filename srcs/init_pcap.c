#include "ft_nmap.h"

extern pcap_t* handle;

void init_pcap(pcap_if_t** devs) {
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(devs, errbuf) == PCAP_ERROR) panic("Couldn't find all devices: %s\n", errbuf);
    char* dev = (*devs)->name;

    bpf_u_int32 _, net;
    if (pcap_lookupnet(dev, &net, &_, errbuf) == PCAP_ERROR)
        panic("Couldn't get netmask for device %s: %s\n", dev, errbuf);

    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) panic("Couldn't open device %s: %s\n", dev, errbuf);
    if (pcap_datalink(handle) != DLT_EN10MB) panic("%s is not an Ethernet\n", dev);
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, FILTER_EXP, 0, net) == PCAP_ERROR)
        panic("Couldn't parse filter %s: %s\n", FILTER_EXP, pcap_geterr(handle));
    if (pcap_setfilter(handle, &fp) == PCAP_ERROR)
        panic("Couldn't install filter %s: %s\n", FILTER_EXP, pcap_geterr(handle));
    pcap_freecode(&fp);
}
