#include "ft_nmap.h"
#include "top_ports.h"

static void panic_parsing(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    exit(EXIT_FAILURE);
}

static void args_error() {
    fprintf(stderr, "See the output of nmap -h for a summary of options.\n");
    exit(EXIT_ARGS);
}

static uint32_t atou_check(char* s, uint32_t min, uint32_t max, char* opt_name) {
    if (!s[0]) panic_parsing("nmap: empty %s value\n", opt_name);

    for (size_t i = 0; s[i]; ++i) {
        if (!isdigit(s[i])) {
            panic_parsing("nmap: invalid %s value: `%s'\n", opt_name, s);
        }
    }

    uint32_t modulo = max % 10;
    uint32_t limit = max / 10;
    uint32_t n = 0;
    for (size_t i = 0; s[i]; ++i) {
        if ((n == limit && (uint32_t)(s[i] - 48) > modulo) || n > limit)
            panic_parsing("nmap: %s value too big: `%s'\n", opt_name, s);
        n = n * 10 + s[i] - '0';
    }

    if (n < min) panic_parsing("nmap: %s value too small: `%s'\n", opt_name, s);
    return n;
}

static void parse_ports(char* value, t_nmap* nmap) {
    char* end = strchr(value, '\0');
    char* comma = end;

    while (comma) {
        comma = strchr(value, ',');
        if (comma) *comma = '\0';

        char* hyphen = strchr(value, '-');
        if (value == hyphen || hyphen == end - 1) atou_check(value, 0, UINT16_MAX, "port");

        if (hyphen) {
            *hyphen = '\0';
            uint16_t left = atou_check(value, 0, UINT16_MAX, "port");
            uint16_t right = atou_check(hyphen + 1, 0, UINT16_MAX, "port");
            if (left > right)
                panic_parsing(
                    "Your port range %d-%d is backwards. Did you mean %d-%d?\nQUITTING!\n",
                    left,
                    right,
                    right,
                    left
                );
            for (uint16_t i = left; i <= right; ++i) set_port(nmap, i);
        } else set_port(nmap, atou_check(value, 0, UINT16_MAX, "port"));

        value = comma + 1;
    }
}

static void parse_scan(char* value, uint16_t* scans) {
    char* end = strchr(value, '\0');
    char* comma = end;

    while (comma) {
        comma = strchr(value, ',');
        if (value == comma || comma == end - 1) panic_parsing("nmap: invalid scan value (`%s')\n", comma);
        if (comma) *comma = '\0';

        bool valid_scan = false;
        for (t_scan_type scan_type = 0; scan_type < SCAN_MAX; ++scan_type) {
            if (!strcmp(value, scans_str[scan_type]) || (value[0] == scans_str[scan_type][0] && value[1] == '\0')) {
                *scans |= 1 << scan_type;
                valid_scan = true;
                break;
            }
        }
        if (!valid_scan) panic_parsing("nmap: invalid scan value (`%s')\n", value);

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
        uint8_t cidr = atou_check(slash + 1, 25, 32, "CIDR");
        uint8_t shift = 32 - cidr;
        if (hostname_to_ip(hostname, hostip)) {
            char* last_part = strrchr(hostip, '.') + 1;
            uint8_t last_val = atou_check(last_part, 0, 255, "CIDR IP");
            uint8_t start_range = last_val >> shift << shift;
            uint8_t end_range = start_range + (1 << shift);
            for (uint8_t i = start_range; i < end_range; ++i) {
                if (i == last_val) add_hostname(nmap, hostname, hostip);
                else {
                    sprintf(last_part, "%u", i);
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
    if (!file) panic_parsing("nmap: failed to open hosts file \"%s\": %s\n", filename, strerror(errno));
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
                    panic_parsing("nmap: hostname too long in \"%s\": %s...\n", filename, hostname);
                } else {
                    hostname[hostname_idx] = buffer[i];
                    ++hostname_idx;
                }
            }
        }
    }
    bool read_failed = !!ferror(file);
    fclose(file);
    if (read_failed) panic_parsing("nmap: failed to read hosts file \"%s\": %s\n", filename, strerror(errno));
    hostname[hostname_idx] = '\0';
    add_hostname_or_cidr(nmap, hostname);
}

static void parse_spoof_address(char* value, char* long_opt, t_nmap* nmap) {
    if (strlen(value) > HOST_NAME_MAX) panic_parsing("nmap: hostname too long in \"%s\": %s...\n", long_opt, value);
    strcpy(nmap->spoof_hostname, value);
    nmap->spoof_hostname[HOST_NAME_MAX] = '\0';

    struct addrinfo hints = {.ai_family = AF_INET};
    struct addrinfo* res = NULL;

    int status = getaddrinfo(value, NULL, &hints, &res);
    if (status < 0 || res == NULL) panic_parsing("\nnmap: getaddrinfo failed: %s\n", gai_strerror(status));
    nmap->source_address = ((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);
}

static bool handle_arg(t_option_value opt, char* value, char short_opt, char* long_opt, t_nmap* nmap) {
    if (value == NULL) {
        if (long_opt) fprintf(stderr, "nmap: option '--%s' requires an argument\n", long_opt);
        else fprintf(stderr, "nmap: option requires an argument -- '%c'\n", short_opt);
        args_error();
    }

    nmap->opt |= opt;
    switch (opt) {
        case OPT_FILE: parse_file(value, nmap); break;
        case OPT_PORTS: parse_ports(value, nmap); break;
        case OPT_MAX_RETRIES: nmap->max_retries = atou_check(value, 0, MAX_MAX_RETRIES, long_opt); break;
        case OPT_SCAN: parse_scan(value, &nmap->scans); break;
        case OPT_SPOOF_ADDRESS: parse_spoof_address(value, long_opt, nmap); break;
        case OPT_THREADS: nmap->num_threads = atou_check(value, 0, MAX_HOSTNAMES, long_opt); break;
        case OPT_TOP_PORTS: nmap->top_ports = MAX(nmap->top_ports, atou_check(value, 1, MAX_PORTS, long_opt)); break;
        case OPT_UDP_RATE: nmap->udp_sleep_us = 1000000 / atou_check(value, 1, 1000000, long_opt); break;
        default: break;
    }
    return true;
}

static bool handle_long_opt(char* opt, size_t i, int* index, char** argv, t_nmap* nmap) {
    char* equal_sign = strchr(opt, '=');
    size_t len = equal_sign != NULL ? (size_t)(equal_sign - opt) : strlen(opt);
    bool ambiguous = false;

    if (strncmp(opt, valid_opt[i].long_opt, len) == 0) {
        for (size_t j = i + 1; valid_opt[j].opt; ++j)
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
            print_info(valid_opt[i].opt, nmap->opt);
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
        for (size_t i = 0; valid_opt[i].opt; i++) {
            if (is_long_opt)
                if ((found_long_opt = handle_long_opt(*arg + 2, i, index, arg, nmap)) == true) return true;
            if (!is_long_opt && *(*arg + 1) == valid_opt[i].short_opt) {
                if (!valid_opt[i].has_arg) {
                    print_info(valid_opt[i].opt, nmap->opt);
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
        for (size_t i = 0; i < 16; ++i) nmap->port_set[i] = ~0;
        nmap->port_set[0] ^= 1;
        nmap->port_set[16] = 1;
        nmap->port_count = MAX_PORTS;
    }
}

static void set_port_mappings(t_nmap* nmap) {
    uint16_t port_index = 0;
    for (uint32_t port = 0; port <= UINT16_MAX; port++) {
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
    for (uint16_t i = 0; i < nmap->hostname_count; ++i) {
        for (t_scan_type scan = 0; scan < SCAN_MAX; ++scan) {
            nmap->hosts[i].undefined_count[scan] = nmap->port_count;
        }
    }
}

static void set_scan_count(t_nmap* nmap) {
    for (t_scan_type scan = 0; scan < SCAN_MAX; ++scan) {
        nmap->scan_count += (nmap->scans >> scan) & 1;
    }
}

static void randomize_ports(t_nmap* nmap) {
    for (uint16_t i = 0; i < nmap->port_count; ++i) nmap->random_indices[i] = i;
    for (uint16_t i = 0; i < nmap->port_count; ++i) {
        uint32_t rd = random_u32_range(i, nmap->port_count);
        uint16_t tmp = nmap->random_indices[rd];
        nmap->random_indices[rd] = nmap->random_indices[i];
        nmap->random_indices[i] = tmp;
    }
}

void parse_args(int argc, char* argv[], t_nmap* nmap) {
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
        panic_parsing("This program requires root privileges for raw socket creation.\n");
    }
    if (!nmap->is_sudo) nmap->opt |= OPT_NO_PING;

    if (!(nmap->opt & OPT_MAX_RETRIES)) nmap->max_retries = DEFAULT_MAX_RETRIES;
    set_top_ports(nmap);
    set_default_ports(nmap);
    set_port_mappings(nmap);
    set_undefined_count(nmap);
    set_scan_count(nmap);

    if ((nmap->opt & OPT_SPOOF_ADDRESS) && (nmap->scans & 1 << SCAN_CONN)) {
        panic_parsing("You can't spoof source address while doing a connect scan.\n");
    }

    if (!(nmap->opt & OPT_NO_RANDOMIZE)) randomize_ports(nmap);
    if (nmap->num_threads > nmap->hostname_count) nmap->num_threads = nmap->hostname_count;
    nmap->num_handles = nmap->num_threads == 0 ? 1 : nmap->num_threads;
}
