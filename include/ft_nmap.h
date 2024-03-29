#pragma once

// TODO: bring back to root if it is only header file? (stp Lorenzo)

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <limits.h>
#include <linux/if_ether.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define RED "\x1b[31m"
#define GREEN "\x1b[32m"
#define YELLOW "\x1b[33m"
#define BLUE "\x1b[34m"
#define MAGENTA "\x1b[35m"
#define CYAN "\x1b[36m"
#define WHITE "\x1b[37m"
#define RESET "\x1b[0m"

#define EXIT_ARGS 0xff
#define VERSION "0.4.2"

#define MAX_PORTS 1024
#define MAX_HOSTNAMES 256

#define TCP_HEADER_SIZE sizeof(struct tcphdr)
#define IP_HEADER_SIZE sizeof(struct iphdr)
#define PSEUDO_HEADER_SIZE sizeof(struct pseudohdr)
#define NMAP_PACKET_SIZE (IP_HEADER_SIZE + TCP_HEADER_SIZE)
#define ICMP_HDR_SIZE sizeof(struct icmphdr)
#define SIZE_ETHERNET sizeof(struct ethhdr)

#define SNAP_LEN 1518 // maximum size of ethernet packet

typedef enum {
    OPT_FILE = 1 << 0,
    OPT_HELP = 1 << 1,
    OPT_PORTS = 1 << 2,
    OPT_SCAN = 1 << 3,
    OPT_THREADS = 1 << 4,
    OPT_VERSION = 1 << 5,
    OPT_VERBOSE = 1 << 6,
} option_value;

typedef struct {
    option_value opt;
    char short_opt;
    char* long_opt;
    bool has_arg;
} option;

static const option valid_opt[] = {
    {OPT_FILE,    'f', "file",    true },
    {OPT_HELP,    'h', "help",    false},
    {OPT_PORTS,   'p', "ports",   true },
    {OPT_SCAN,    's', "scans",   true },
    {OPT_THREADS, 't', "threads", true },
    {OPT_VERBOSE, 'v', "verbose", false},
    {OPT_VERSION, 'V', "version", false},
    {0,           0,   NULL,      false}
};

typedef enum {
    PORT_UNDEFINED,
    PORT_OPEN,
    PORT_CLOSED,
    PORT_FILTERED,
    PORT_UNFILTERED,
    PORT_OPEN_FILTERED,
    PORT_UNEXPECTED
} __attribute__((packed)) port_state;

typedef struct {
    char str[14];
    char color[8];
    size_t strlen;
} t_port_state_info;

#define STR_PORT_UNDEFINED "undefined"
#define STR_PORT_OPEN "open"
#define STR_PORT_CLOSED "closed"
#define STR_PORT_FILTERED "filtered"
#define STR_PORT_UNFILTERED "unfiltered"
#define STR_PORT_OPEN_FILTERED "open|filtered"
#define STR_PORT_UNEXPECTED "unexpected"

static const t_port_state_info port_state_info[] = {
    {STR_PORT_UNDEFINED,     WHITE,   sizeof(STR_PORT_UNDEFINED) - 1    },
    {STR_PORT_OPEN,          GREEN,   sizeof(STR_PORT_OPEN) - 1         },
    {STR_PORT_CLOSED,        RED,     sizeof(STR_PORT_CLOSED) - 1       },
    {STR_PORT_FILTERED,      YELLOW,  sizeof(STR_PORT_FILTERED) - 1     },
    {STR_PORT_UNFILTERED,    BLUE,    sizeof(STR_PORT_UNFILTERED) - 1   },
    {STR_PORT_OPEN_FILTERED, MAGENTA, sizeof(STR_PORT_OPEN_FILTERED) - 1},
    {STR_PORT_UNEXPECTED,    WHITE,   sizeof(STR_PORT_UNEXPECTED) - 1   },
};

typedef enum {
    SCAN_SYN,
    SCAN_ACK,
    SCAN_FIN,
    SCAN_NULL,
    SCAN_XMAS,
    SCAN_UDP,
    SCAN_MAX,
} scan_type;

typedef struct {
    scan_type type;
    char name[5];
} scan;

static const port_state default_port_state[SCAN_MAX] = {
    PORT_FILTERED,
    PORT_FILTERED,
    PORT_OPEN_FILTERED,
    PORT_OPEN_FILTERED,
    PORT_OPEN_FILTERED,
    PORT_OPEN_FILTERED,
};

static const char scans_str[][5] = {"SYN", "ACK", "FIN", "NULL", "XMAS", "UDP"};

// TODO: host struct with name, port_states, undefined_count...

typedef struct {
    int tcp_fd;
    int udp_fd;
    int icmp_fd;
    uint8_t* packet;
    int hostname_count;
    int hostname_up_count;
    char hostnames[MAX_HOSTNAMES][HOST_NAME_MAX + 1];
    char hostip[INET_ADDRSTRLEN + 1]; // one for each hostname
    int hostname_index;
    struct sockaddr_in hostaddr; // TODO: remove

    uint32_t opt;
    uint16_t port_count;
    uint64_t port_set[1024];
    uint16_t port_array[MAX_PORTS];
    uint16_t port_dictionary[1 << 16];
    port_state port_states[MAX_HOSTNAMES][SCAN_MAX][MAX_PORTS];
    uint16_t undefined_count[MAX_HOSTNAMES][SCAN_MAX];
    uint8_t scans; // TODO: maybe uint16_t
    uint8_t current_scan;
    uint8_t threads;

    bool is_responsive[MAX_HOSTNAMES][MAX_PORTS];
    uint16_t responsive_count[MAX_HOSTNAMES];

    struct timeval start_time;
    struct timeval end_time;
    struct timeval latency;

    uint16_t port_source;

    pcap_if_t* devs;
    bpf_u_int32 net_device;
} t_nmap;

// capture_packets.c
void* capture_packets(__attribute__((unused)) void* arg);

// info.c
void handle_info_args(option_value new_opt, uint8_t nmap_opts);

// packet.c
void fill_packet(t_nmap* nmap, uint8_t* packet, uint16_t port, uint8_t* payload, size_t payload_size);

// parsing.c
void verify_arguments(int argc, char* argv[], t_nmap* nmap);

// pcap.c
void set_filter(t_nmap* nmap);
void init_pcap(t_nmap* nmap);

// ping.c
void send_ping(t_nmap* nmap);
void handle_echo_reply(t_nmap* nmap, uint8_t* reply_packet);

// ports.c
bool get_port(uint64_t* ports, uint16_t port);
void set_port(t_nmap* nmap, uint16_t port);

// print_payload.c
void print_payload(const u_char* payload, int size_payload);

// print_scan_report.c
void print_scan_report(t_nmap* nmap);

// random.c
uint32_t random_u32_range(uint32_t a, uint32_t b);

// send_packets.c
void* send_packets(void* arg);

// signals.c
void handle_sigint(int sig);
void set_signals();

// utils.c
void error(char* message);
void g_error(char* message, int status);
void hostname_to_ip(t_nmap* nmap);
bool ip_to_hostname(struct in_addr ip_address, char* host, size_t hostlen);
in_addr_t get_source_address();
void panic(const char* format, ...);
struct timeval timeval_subtract(struct timeval start, struct timeval end);
void get_start_time(t_nmap* nmap);
void print_stats(t_nmap* nmap);
void cleanup(t_nmap* nmap);

// verbose.c
void print_hostnames(t_nmap* nmap);
void print_ports(t_nmap* nmap);
void print_scans(uint8_t scans);
