#include "ft_nmap.h"

extern pcap_t* handle_lo[MAX_HOSTNAMES];
extern pcap_t* handle_net[MAX_HOSTNAMES];
extern pcap_t* current_handle[MAX_HOSTNAMES];

static void set_device_filter(pcap_t* handle, bpf_u_int32 device, char* filter_exp) {
    struct bpf_program fp;

    if (pcap_compile(handle, &fp, filter_exp, 0, device) == PCAP_ERROR) panic("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    if (pcap_setfilter(handle, &fp) == PCAP_ERROR) panic("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    pcap_freecode(&fp);
}

void unset_filters(t_nmap* nmap, int t_index) {
    static char filter_none[] = "tcp and not ip";
    pthread_mutex_lock(&nmap->mutex_unset_filters);
    set_device_filter(handle_lo[t_index], nmap->device_lo, filter_none);
    set_device_filter(handle_net[t_index], nmap->device_net, filter_none);
    pthread_mutex_unlock(&nmap->mutex_unset_filters);
}

void set_filter(t_thread_info* th_info, bool ping) {
    char filter_exp[256] = {0};

    if (ping) sprintf(filter_exp, "icmp and src %s", th_info->hostip);
    else if (th_info->current_scan == SCAN_UDP) sprintf(filter_exp, "(src host %s and udp) or (icmp and src %s)", th_info->hostip, th_info->hostip);
    else sprintf(filter_exp, "(src host %s and tcp and dst port %d) or (icmp and src %s)", th_info->hostip, th_info->port_source, th_info->hostip);

    set_device_filter(current_handle[th_info->t_index], current_handle[th_info->t_index] == handle_lo[th_info->t_index] ? th_info->nmap->device_lo : th_info->nmap->device_net, filter_exp);
}

static pcap_t* set_handle(char* dev) {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(dev, SNAP_LEN, 1, 1, errbuf);
    if (handle == NULL) panic("Couldn't open device %s: %s\n", dev, errbuf);
    if (pcap_datalink(handle) != DLT_EN10MB) panic("%s is not an Ethernet\n", dev);
    return handle;
}

static void lookup_net(char* name, bpf_u_int32* device) {
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_lookupnet(name, device, &(bpf_u_int32){0}, errbuf) == PCAP_ERROR) {
        panic("Couldn't get netmask for device %s: %s\n", name, errbuf);
    }
}

void init_pcap(t_nmap* nmap) {
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&nmap->devs, errbuf) == PCAP_ERROR) panic("Couldn't find all devices: %s\n", errbuf); // TODO error
    lookup_net("lo", &nmap->device_lo);
    lookup_net(nmap->devs->name, &nmap->device_net);

    for (int i = 0; i < nmap->num_handles; ++i) {
        handle_lo[i] = set_handle("lo");
        handle_net[i] = set_handle(nmap->devs->name);
        unset_filters(nmap, i);
    }
}
