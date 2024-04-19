#include "ft_nmap.h"

extern pcap_t *handle_lo, *handle_net, *current_handle;

static void set_device_filter(pcap_t* handle, bpf_u_int32 device, char* filter_exp) {
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp, 0, device) == PCAP_ERROR)
        panic("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    if (pcap_setfilter(handle, &fp) == PCAP_ERROR)
        panic("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    pcap_freecode(&fp);
}

void unset_filters(t_nmap* nmap) {
    static char filter_none[] = "src host 0.0.0.0";
    set_device_filter(handle_lo, nmap->device_lo, filter_none);
    set_device_filter(handle_net, nmap->device_net, filter_none);
}

void set_filter(t_nmap* nmap) {
    char filter_exp[128] = {0};

    sprintf(
        filter_exp,
        "(icmp) or (%s and src host %s and dst port %d)",
        nmap->current_scan == SCAN_UDP ? "udp" : "tcp",
        nmap->hostip,
        nmap->port_source
    );
    set_device_filter(current_handle, current_handle == handle_lo ? nmap->device_lo : nmap->device_net, filter_exp);
}

static pcap_t* set_handle(char* dev, bpf_u_int32* device) {
    char errbuf[PCAP_ERRBUF_SIZE];

    bpf_u_int32 _;
    if (pcap_lookupnet(dev, device, &_, errbuf) == PCAP_ERROR)
        panic("Couldn't get netmask for device %s: %s\n", dev, errbuf);

    pcap_t* handle = pcap_open_live(dev, SNAP_LEN, 1, 1, errbuf);
    if (handle == NULL) panic("Couldn't open device %s: %s\n", dev, errbuf);
    if (pcap_datalink(handle) != DLT_EN10MB) panic("%s is not an Ethernet\n", dev);
    return handle;
}

void init_pcap(t_nmap* nmap) {
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&nmap->devs, errbuf) == PCAP_ERROR)
        panic("Couldn't find all devices: %s\n", errbuf); // TODO error

    handle_lo = set_handle("lo", &nmap->device_lo);
    handle_net = set_handle(nmap->devs->name, &nmap->device_net);

    unset_filters(nmap);
}
