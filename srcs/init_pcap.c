#include "ft_nmap.h"

#define SNAP_LEN 1518 // maximum size of ethernet packet

extern t_thread_globals thread_globals[MAX_HOSTNAMES];

static void panic_init_pcap(t_nmap* nmap, const char* format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    cleanup(nmap);
    exit(EXIT_FAILURE);
}

static pcap_t* set_handle(t_nmap* nmap, char* dev) {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(dev, SNAP_LEN, 1, 1, errbuf);
    if (handle == NULL) panic_init_pcap(nmap, "Couldn't open device %s: %s\n", dev, errbuf);
    if (pcap_datalink(handle) != DLT_EN10MB) {
        pcap_close(handle);
        panic_init_pcap(nmap, "%s is not an Ethernet\n", dev);
    }
    return handle;
}

static void lookup_net(t_nmap* nmap, char* name, bpf_u_int32* device) {
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_lookupnet(name, device, &(bpf_u_int32){0}, errbuf) == PCAP_ERROR) {
        panic_init_pcap(nmap, "Couldn't get netmask for device %s: %s\n", name, errbuf);
    }
}

void init_pcap(t_nmap* nmap) {
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&nmap->devs, errbuf) == PCAP_ERROR) {
        panic_init_pcap(nmap, "nmap: couldn't find all devices", errbuf);
    }
    lookup_net(nmap, "lo", &nmap->device_lo);
    lookup_net(nmap, nmap->devs->name, &nmap->device_net);

    for (uint16_t i = 0; i < nmap->num_handles; ++i) {
        thread_globals[i].handle_lo = set_handle(nmap, "lo");
        thread_globals[i].handle_net = set_handle(nmap, nmap->devs->name);
        unset_filters(nmap, i);
    }
}
