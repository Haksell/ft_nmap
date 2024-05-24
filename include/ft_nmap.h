#pragma once

#include <arpa/inet.h>
#include <bits/pthreadtypes.h>
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
#define VERSION "42.0"

#define MAX_PORTS 1024
#define MAX_HOSTNAMES 250
#define MAX_SERVICE_LEN 20

#define MAX_MAX_RETRIES 10
#define DEFAULT_MAX_RETRIES 1

#define ICMP_HDR_SIZE sizeof(struct icmphdr)
#define SIZE_ETHERNET sizeof(struct ethhdr)

typedef enum {
    OPT_FILE = 1 << 0,
    OPT_HELP = 1 << 1,
    OPT_NO_PING = 1 << 2,
    OPT_NO_RANDOMIZE = 1 << 3,
    OPT_PORTS = 1 << 4,
    OPT_MAX_RETRIES = 1 << 5,
    OPT_SCAN = 1 << 6,
    OPT_SPOOF_ADDRESS = 1 << 7,
    OPT_THREADS = 1 << 8,
    OPT_TOP_PORTS = 1 << 9,
    OPT_UDP_RATE = 1 << 10,
    OPT_VERSION = 1 << 11,
    OPT_VERBOSE = 1 << 12,
} t_option_value;

typedef struct {
    t_option_value opt;
    char short_opt;
    char* long_opt;
    bool has_arg;
    char* description;
} t_option;

static const t_option valid_opt[] = {
    {OPT_FILE,          'f',  "file",          true,  "filename containing addresses to scan"              },
    {OPT_HELP,          'h',  "help",          false, "print this help screen"                             },
    {OPT_MAX_RETRIES,   '\0', "max-retries",   true,  "caps number of port scan probe retransmissions"     },
    {OPT_NO_PING,       '\0', "no-ping",       false, "skip host discovery"                                },
    {OPT_NO_RANDOMIZE,  '\0', "no-randomize",  false, "scan ports sequentially"                            },
    {OPT_PORTS,         'p',  "ports",         true,  "ports to scan (e.g. 1-10 or 1,2,3 or 1,5-15)"       },
    {OPT_SCAN,          's',  "scans",         true,  "ACK/CONN/FIN/NULL/SYN/UDP/WIN/XMAS"                 },
    {OPT_SPOOF_ADDRESS, '\0', "spoof-address", true,  "spoof source address"                               },
    {OPT_THREADS,       't',  "threads",       true,  "use <number> parallel threads (0-250)"              },
    {OPT_TOP_PORTS,     '\0', "top-ports",     true,  "scan <number> most common ports"                    },
    {OPT_UDP_RATE,      'u',  "udp-rate",      true,  "send UDP packets no faster than <number> per second"},
    {OPT_VERBOSE,       'v',  "verbose",       false, "increase verbosity level"                           },
    {OPT_VERSION,       'V',  "version",       false, "print version number"                               },
    {0,                 0,    NULL,            false, NULL                                                 }
};

typedef enum {
    PORT_UNDEFINED,
    PORT_OPEN,
    PORT_CLOSED,
    PORT_FILTERED,
    PORT_UNFILTERED,
    PORT_OPEN_FILTERED,
    PORT_UNEXPECTED
} __attribute__((packed)) t_port_state;

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
    {STR_PORT_UNFILTERED,    MAGENTA, sizeof(STR_PORT_UNFILTERED) - 1   },
    {STR_PORT_OPEN_FILTERED, BLUE,    sizeof(STR_PORT_OPEN_FILTERED) - 1},
    {STR_PORT_UNEXPECTED,    WHITE,   sizeof(STR_PORT_UNEXPECTED) - 1   },
};

typedef enum {
    SCAN_SYN,
    SCAN_ACK,
    SCAN_WIN,
    SCAN_FIN,
    SCAN_NULL,
    SCAN_XMAS,
    SCAN_UDP,
    SCAN_CONN,
    SCAN_MAX,
} t_scan_type;

static const t_port_state default_port_state[SCAN_MAX] = {
    PORT_FILTERED,
    PORT_FILTERED,
    PORT_FILTERED,
    PORT_OPEN_FILTERED,
    PORT_OPEN_FILTERED,
    PORT_OPEN_FILTERED,
    PORT_OPEN_FILTERED,
    PORT_FILTERED,
};

static const char scans_str[][5] = {"SYN", "ACK", "WIN", "FIN", "NULL", "XMAS", "UDP", "CONN"};

struct t_thread_info;

typedef struct {
    struct t_thread_info* th_info;
    pcap_t* handle;
} t_capture_args;

typedef struct {
    char name[HOST_NAME_MAX + 1];
    char hostip[INET_ADDRSTRLEN + 1];
    t_port_state port_states[SCAN_MAX][MAX_PORTS];
    uint16_t undefined_count[SCAN_MAX];
    bool is_up;
} t_host;

typedef struct {
    sig_atomic_t sender_finished;
    pcap_t* handle_lo;
    pcap_t* handle_net;
    pcap_t* current_handle;
} t_thread_globals;

typedef struct t_thread_info {
    struct t_nmap* nmap;
    t_thread_globals globals;
    uint16_t t_index;
    uint64_t latency;
    uint16_t port_source;
    uint8_t current_scan;
    struct sockaddr_in hostaddr;
    pthread_t thread_id;
    t_host* host;
} t_thread_info;

typedef struct t_nmap {
    bool is_sudo;

    int tcp_fd;
    int udp_fd;
    int icmp_fd;

    uint16_t hostname_count;
    t_thread_info threads[MAX_HOSTNAMES];
    t_host hosts[MAX_HOSTNAMES];

    uint32_t opt;
    uint16_t port_count;
    uint64_t port_set[1024];
    uint16_t port_array[MAX_PORTS];
    uint16_t random_indices[MAX_PORTS];
    uint16_t port_dictionary[1 << 16];
    uint16_t scans;
    uint8_t scan_count;
    uint16_t started_threads;
    uint16_t num_threads;
    uint16_t num_handles;
    uint64_t start_time;
    uint16_t top_ports;
    uint8_t max_retries;
    uint32_t udp_sleep_us;

    char tcp_services[MAX_PORTS][MAX_SERVICE_LEN + 1];
    char udp_services[MAX_PORTS][MAX_SERVICE_LEN + 1];

    pcap_if_t* devs;
    bpf_u_int32 device_lo;
    bpf_u_int32 device_net;

    char spoof_hostname[HOST_NAME_MAX + 1];
    in_addr_t source_address;

    pthread_mutex_t mutex_print;
    pthread_mutex_t mutex_undefined_count;
    pthread_mutex_t mutex_pcap_filter;
    pthread_mutex_t* mutexes[5]; // only used to free the mutexes
} t_nmap;

// capture_packets.c
void* capture_packets(__attribute__((unused)) void* arg);

// cleanup.c
void cleanup(t_nmap* nmap);
void error(char* message);
void panic(const char* format, ...);
void stop();

// fill_packet.c
void fill_packet(t_thread_info* th_info, uint8_t* packet, uint16_t port, const uint8_t* payload, size_t payload_size);

// filters.c
void set_filter(t_thread_info* th_info, t_scan_type scan_type);
void unset_filters(t_nmap* nmap, uint16_t t_index);

// init_nmap.h
void init_nmap(t_nmap* nmap);

// init_pcap.c
void init_pcap(t_nmap* nmap);

// parse_args.c
void parse_args(int argc, char* argv[], t_nmap* nmap);

// ports.c
bool get_port(uint64_t* ports, uint16_t port);
void set_port(t_nmap* nmap, uint16_t port);
void set_port_state(t_thread_info* th_info, t_port_state port_state, uint16_t port);
void set_default_port_states(t_thread_info* th_info);

// print_info.c
void print_info(t_option_value new_opt, uint32_t nmap_opts);

// print_scan_report.c
void print_scan_report(t_thread_info* th_info);

// random.c
uint32_t random_u32_range(uint32_t a, uint32_t b);

// scan_connect.c
void scan_connect(t_thread_info* th_info);

// send_packets.c
void* send_packets(void* arg);

// send_ping.c
void send_ping(t_thread_info* th_info);

// utils.c
bool hostname_to_ip(char hostname[HOST_NAME_MAX + 1], char hostip[INET_ADDRSTRLEN + 1]);
bool ip_to_hostname(struct in_addr ip_address, char* host, size_t hostlen);
uint64_t get_microseconds();

// verbose.c
void print_payload(const u_char* payload, uint32_t size_payload);
void print_init_verbose(t_nmap* nmap);
