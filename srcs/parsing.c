#include "ft_nmap.h"
#include "top_ports.h"

static void args_error() {
    fprintf(stderr, "See the output of nmap -h for a summary of options.\n");
    exit(EXIT_ARGS);
}

static int atoi_check(char* s, int min, int max, char* opt_name) {
    if (!s[0]) panic("nmap: empty %s value\n", opt_name);

    for (int i = 0; s[i]; ++i) {
        if (!isdigit(s[i])) {
            panic("nmap: invalid %s value: `%s'\n", opt_name, s);
        }
    }

    int modulo = max % 10;
    int limit = max / 10;
    int n = 0;
    for (int i = 0; s[i]; ++i) {
        if ((n == limit && s[i] > modulo + '0') || n > limit) panic("nmap: %s value too big: `%s'\n", opt_name, s);
        n = n * 10 + s[i] - '0';
    }

    if (n < min) panic("nmap: %s value too small: `%s'\n", opt_name, s);
    return n;
}

static void handle_info_args(option_value new_opt, uint32_t nmap_opts) {
    if (nmap_opts & new_opt) return;
    if (new_opt == OPT_VERSION) printf("ft_nmap version " VERSION "\n");
    else if (new_opt == OPT_HELP) {
        printf("ft_nmap <ip/hostname/file> [options]\n");
        printf("--help      Print this help screen\n");
        printf("--ports     Ports to scan (e.g. 1-10 or 1,2,3 or 1,5-15)\n");
        printf("--scans     ACK/CONN/FIN/NULL/SYN/UDP/WIN/XMAS\n");
        printf("--threads   Number of parallel threads to use (0-255)\n");
        printf("--version   Print version number\n");
    }
}

static void parse_ports(char* value, t_nmap* nmap) {
    char* end = strchr(value, '\0');
    char* comma = end;

    while (comma) {
        comma = strchr(value, ',');
        if (comma) *comma = '\0';

        char* hyphen = strchr(value, '-');
        if (value == hyphen || hyphen == end - 1) atoi_check(value, 0, UINT16_MAX, "port");

        if (hyphen) {
            *hyphen = '\0';
            int left = atoi_check(value, 0, UINT16_MAX, "port");
            int right = atoi_check(hyphen + 1, 0, UINT16_MAX, "port");
            if (left > right)
                panic("Your port range %d-%d is backwards. Did you mean %d-%d?\nQUITTING!\n", left, right, right, left);
            for (int i = left; i <= right; ++i) set_port(nmap, i);
        } else set_port(nmap, atoi_check(value, 0, UINT16_MAX, "port"));

        value = comma + 1;
    }
}

static void parse_scan(char* value, uint16_t* scans) {
    char* end = strchr(value, '\0');
    char* comma = end;

    while (comma) {
        comma = strchr(value, ',');
        if (value == comma || comma == end - 1) panic("nmap: invalid scan value (`%s')\n", comma);
        if (comma) *comma = '\0';

        bool valid_scan = false;
        for (scan_type scan_type = 0; scan_type < SCAN_MAX; ++scan_type) {
            if (!strcmp(value, scans_str[scan_type]) || (value[0] == scans_str[scan_type][0] && value[1] == '\0')) {
                *scans |= 1 << scan_type;
                valid_scan = true;
                break;
            }
        }
        if (!valid_scan) panic("nmap: invalid scan value (`%s')\n", value);

        value = comma + 1;
    }
}

static void add_hostname(t_nmap* nmap, char* hostname, char* hostip) {
    if (nmap->hostname_count == MAX_HOSTNAMES) {
        fprintf(stderr, "nmap: too many hostnames\n");
        args_error();
    }
    strncpy(nmap->hosts[nmap->hostname_count].name, hostname, HOST_NAME_MAX);
    nmap->hosts[nmap->hostname_count].name[HOST_NAME_MAX] = '\0';
    strncpy(nmap->hosts[nmap->hostname_count].hostip, hostip, INET_ADDRSTRLEN);
    nmap->hosts[nmap->hostname_count].hostip[INET_ADDRSTRLEN] = '\0';
    nmap->hostname_count++;
}

static void add_hostname_or_cidr(t_nmap* nmap, char* hostname) {
    if (hostname[0] == '\0') return;
    char* slash = strchr(hostname, '/');
    char hostip[INET_ADDRSTRLEN + 1];
    if (slash) {
        *slash = '\0';
        int cidr = atoi_check(slash + 1, 25, 32, "CIDR");
        int shift = 32 - cidr;
        if (hostname_to_ip(hostname, hostip)) {
            char* last_part = strrchr(hostip, '.') + 1;
            int last_val = atoi_check(last_part, 0, 255, "CIDR IP");
            int start_range = last_val >> shift << shift;
            int end_range = start_range + (1 << shift);
            // TODO: fix broadcast address
            for (int i = start_range; i < end_range; ++i) {
                if (i == last_val) add_hostname(nmap, hostname, hostip);
                else {
                    sprintf(last_part, "%d", i);
                    add_hostname(nmap, hostip, hostip);
                }
            }
        }
    } else if (hostname_to_ip(hostname, hostip)) add_hostname(nmap, hostname, hostip);
}

static void parse_file(char* filename, t_nmap* nmap) {
    char buffer[1024];
    size_t bytesRead;

    FILE* file = fopen(filename, "r");
    if (!file) panic("nmap: failed to open hosts file \"%s\": %s\n", filename, strerror(errno));
    char hostname[HOST_NAME_MAX + 1];
    size_t hostname_idx = 0;
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        for (size_t i = 0; i < bytesRead; ++i) {
            if (isspace(buffer[i])) {
                hostname[hostname_idx] = '\0';
                add_hostname_or_cidr(nmap, hostname);
                hostname_idx = 0;
            } else {
                if (hostname_idx == HOST_NAME_MAX) {
                    fclose(file);
                    hostname[HOST_NAME_MAX] = '\0';
                    panic("nmap: hostname too long in \"%s\": %s...\n", filename, hostname);
                } else {
                    hostname[hostname_idx] = buffer[i];
                    ++hostname_idx;
                }
            }
        }
    }
    bool read_failed = !!ferror(file); // forbidden function
    fclose(file);
    if (read_failed) panic("nmap: failed to read hosts file \"%s\": %s\n", filename, strerror(errno));
    hostname[hostname_idx] = '\0';
    add_hostname_or_cidr(nmap, hostname);
}

static in_addr_t parse_spoof_address(char* value, char* long_opt) {
    if (strlen(value) > HOST_NAME_MAX) panic("nmap: hostname too long in \"%s\": %s...\n", long_opt, value);

    struct addrinfo hints = {.ai_family = AF_INET};
    struct addrinfo* res = NULL;

    int status = getaddrinfo(value, NULL, &hints, &res);
    if (status < 0 || res == NULL) panic("\nnmap: getaddrinfo failed: %s\n", gai_strerror(status));
    in_addr_t addr = ((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);
    return addr;
}

static bool handle_arg(int opt, char* value, char short_opt, char* long_opt, t_nmap* nmap) {
    if (value == NULL) {
        if (long_opt) fprintf(stderr, "nmap: option '--%s' requires an argument\n", long_opt);
        else fprintf(stderr, "nmap: option requires an argument -- '%c'\n", short_opt);
        args_error();
    }

    nmap->opt |= opt;
    switch (opt) {
        case OPT_FILE: parse_file(value, nmap); break;
        case OPT_PORTS: parse_ports(value, nmap); break;
        case OPT_RETRANSMISSIONS:
            nmap->retransmissions = atoi_check(value, 0, MAX_RETRANSMISSIONS, "retransmissions");
            break;
        case OPT_SCAN: parse_scan(value, &nmap->scans); break;
        case OPT_SPOOF_ADDRESS: nmap->source_address = parse_spoof_address(value, long_opt); break;
        case OPT_THREADS: nmap->num_threads = atoi_check(value, 0, MAX_HOSTNAMES, "threads"); break;
        case OPT_TOP_PORTS: nmap->top_ports = MAX(nmap->top_ports, atoi_check(value, 1, MAX_PORTS, "top-ports")); break;
        // TODO: specify in --help that no udp-rate is fastest
        case OPT_UDP_RATE: nmap->udp_sleep_us = 1000000 / atoi_check(value, 1, 1000000, "udp-rate"); break;
    }
    return true;
}

static bool handle_long_opt(char* opt, int i, int* index, char** argv, t_nmap* nmap) {
    char* equal_sign = strchr(opt, '=');
    size_t len = equal_sign != NULL ? (size_t)(equal_sign - opt) : strlen(opt);
    bool ambiguous = false;

    if (strncmp(opt, valid_opt[i].long_opt, len) == 0) {
        for (int j = i + 1; valid_opt[j].opt; ++j)
            if (strncmp(opt, valid_opt[j].long_opt, len) == 0) {
                if (!ambiguous) {
                    fprintf(
                        stderr,
                        "nmap: option '--%s' is ambiguous; possibilities: '--%s'",
                        opt,
                        valid_opt[i].long_opt
                    );
                    ambiguous = true;
                }
                fprintf(stderr, " '--%s'", valid_opt[j].long_opt);
            }
        if (ambiguous) fprintf(stderr, "\n"), args_error();

        if (valid_opt[i].has_arg == false) {
            if (equal_sign) {
                fprintf(stderr, "nmap: option '--%s' doesn't allow an argument\n", valid_opt[i].long_opt);
                args_error();
            }
            handle_info_args(valid_opt[i].opt, nmap->opt);
            nmap->opt |= valid_opt[i].opt;
        } else {
            if (equal_sign == NULL) (*index)++;
            handle_arg(valid_opt[i].opt, equal_sign ? equal_sign + 1 : *(++argv), 0, valid_opt[i].long_opt, nmap);
        }
        return true;
    }
    return false;
}

static bool is_valid_opt(char** arg, int* index, t_nmap* nmap) {
    bool is_long_opt = *(*arg + 1) == '-';
    bool valid = true;
    bool found_long_opt = false;

    do
        for (int i = 0; valid_opt[i].opt; i++) {
            if (is_long_opt)
                if ((found_long_opt = handle_long_opt(*arg + 2, i, index, arg, nmap)) == true) return true;
            if (!is_long_opt && *(*arg + 1) == valid_opt[i].short_opt) {
                if (!valid_opt[i].has_arg) {
                    handle_info_args(valid_opt[i].opt, nmap->opt);
                    nmap->opt |= valid_opt[i].opt;
                } else {
                    if (*(*arg + 2) == '\0') (*index)++;
                    return handle_arg(
                        valid_opt[i].opt,
                        *(*arg + 2) ? *arg + 2 : *(++arg),
                        valid_opt[i].short_opt,
                        NULL,
                        nmap
                    );
                }
                break;
            }
            if (valid_opt[i + 1].opt == 0) valid = false;
        }
    while (*(*arg + 2) && valid && (*arg)++);

    return valid;
}

static void handle_unrecognized_opt(char* arg) {
    if (*arg == '-') fprintf(stderr, "nmap: unrecognized option '%s'\n", arg);
    else fprintf(stderr, "nmap: invalid option -- '%c'\n", *(arg + 1));
    args_error();
}

static void set_top_ports(t_nmap* nmap) {
    bool has_tcp = nmap->scans & ~(1 << SCAN_UDP);
    bool has_udp = nmap->scans & (1 << SCAN_UDP);
    const uint16_t* top_ports = has_tcp && !has_udp   ? top_ports_tcp
                                : has_udp && !has_tcp ? top_ports_udp
                                                      : top_ports_mixed;
    for (uint16_t i = 0; i < nmap->top_ports; ++i) set_port(nmap, top_ports[i]);
}

static void set_default_ports(t_nmap* nmap) {
    if (nmap->port_count == 0) {
        for (int i = 0; i < 16; ++i) nmap->port_set[i] = ~0;
        nmap->port_set[0] ^= 1;
        nmap->port_set[16] = 1;
        nmap->port_count = MAX_PORTS;
    }
}

static void set_port_mappings(t_nmap* nmap) {
    int port_index = 0;
    for (int port = 0; port <= UINT16_MAX; port++) {
        if (get_port(nmap->port_set, port)) {
            nmap->port_array[port_index] = port;
            nmap->port_dictionary[port] = port_index;
            ++port_index;
        } else {
            nmap->port_dictionary[port] = MAX_PORTS;
        }
    }
}

static void set_undefined_count(t_nmap* nmap) {
    for (int i = 0; i < nmap->hostname_count; ++i) {
        for (int j = 0; j < SCAN_MAX; ++j) {
            nmap->hosts[i].undefined_count[j] = nmap->port_count;
        }
    }
}

static void set_scan_count(t_nmap* nmap) {
    for (scan_type scan = 0; scan < SCAN_MAX; ++scan) {
        nmap->scan_count += (nmap->scans >> scan) & 1;
    }
}

static void randomize_ports(t_nmap* nmap) {
    for (int i = 0; i < nmap->port_count; ++i) nmap->random_indices[i] = i;
    for (int i = 0; i < nmap->port_count; ++i) {
        uint32_t rd = random_u32_range(i, nmap->port_count);
        uint16_t tmp = nmap->random_indices[rd];
        nmap->random_indices[rd] = nmap->random_indices[i];
        nmap->random_indices[i] = tmp;
    }
}

void verify_arguments(int argc, char* argv[], t_nmap* nmap) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            for (int j = i + 1; j < argc; ++j) add_hostname_or_cidr(nmap, argv[j]);
            break;
        } else if (argv[i][0] == '-' && argv[i][1]) {
            if (!is_valid_opt(&argv[i], &i, nmap)) handle_unrecognized_opt(argv[i]);
        } else {
            add_hostname_or_cidr(nmap, argv[i]);
        }
    }

    if (nmap->opt & (OPT_HELP | OPT_VERSION)) exit(EXIT_SUCCESS);

    nmap->is_sudo = geteuid() == 0;
    if (nmap->scans == 0) {
        nmap->scans = nmap->is_sudo ? ~(1 << SCAN_CONN | 1 << SCAN_WIN) : (1 << SCAN_CONN);
    } else if (!nmap->is_sudo && nmap->scans != (1 << SCAN_CONN)) {
        panic("This program requires root privileges for raw socket creation.\n");
    }
    if (!nmap->is_sudo) nmap->opt |= OPT_NO_PING;

    if (!(nmap->opt & OPT_RETRANSMISSIONS)) nmap->retransmissions = DEFAULT_RETRANSMISSIONS;
    set_top_ports(nmap);
    set_default_ports(nmap);
    set_port_mappings(nmap);
    set_undefined_count(nmap);
    set_scan_count(nmap);
    if (!(nmap->opt & OPT_NO_RANDOMIZE)) randomize_ports(nmap);
    if (nmap->num_threads > nmap->hostname_count) nmap->num_threads = nmap->hostname_count;
    nmap->num_handles = nmap->num_threads == 0 ? 1 : nmap->num_threads;
}
