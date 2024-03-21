#include "ft_nmap.h"

volatile sig_atomic_t run = true;
pcap_t* handle = NULL;

static void create_socket(t_nmap* nmap) {
    if (geteuid() != 0) {
        fprintf(stderr, "This program requires root privileges for raw socket creation.\n");
        exit(EXIT_FAILURE);
    }

    nmap->fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (nmap->fd < 0) error("TCP socket creation failed");

    if (setsockopt(nmap->fd, IPPROTO_IP, IP_HDRINCL, &(int){1}, sizeof(int)) < 0) error("setsockopt IP_HDRINCL failed");

    gettimeofday(&nmap->start_time, NULL);
    struct tm* tm = localtime(&nmap->start_time.tv_sec);
    char timestamp[21];
    strftime(timestamp, 21, "%Y-%m-%d %H:%M CET", tm);
    printf("Starting Nmap %s at %s\n", VERSION, timestamp);

    if (nmap->opt & OPT_VERBOSE) {
        print_hostnames(nmap);
        print_ports(nmap);
        print_scans(nmap->scans);
        printf("Host: %s (%s)\n", nmap->hostnames[nmap->hostname_index], nmap->hostip);
    }
}

int main(int argc, char* argv[]) {
    t_nmap nmap = {0};

    verify_arguments(argc, argv, &nmap);
    create_socket(&nmap);
    set_signals();

    init_pcap(&nmap.devs);

    pthread_t capture_thread, sender_thread;
    if (pthread_create(&capture_thread, NULL, capture_packets, &nmap) != 0)
        panic("Failed to create the capture thread");
    // TODO: multiple sender threads
    if (pthread_create(&sender_thread, NULL, send_packets, &nmap) != 0) panic("Failed to create the sender thread");
    pthread_join(capture_thread, NULL);
    pthread_join(sender_thread, NULL);

    printf(
        "\nNmap done: %d IP addresses (%d hosts up) scanned in %.2f seconds\n", nmap.hostname_count,
        nmap.hostname_count, // TODO: up
        3.01
    );

    if (nmap.devs) pcap_freealldevs(nmap.devs);
    if (handle) pcap_close(handle);
    close(nmap.fd);
    return EXIT_SUCCESS;
}
