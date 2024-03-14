#include "ft_nmap.h"

const option valid_opt[] = {
    {OPT_FILE,    'f', "file",    true },
    {OPT_HELP,    'h', "help",    false},
    {OPT_PORTS,   'p', "ports",   true },
    {OPT_SCAN,    's', "scan",    true },
    {OPT_THREADS, 't', "threads", true },
    {OPT_VERSION, 'V', "version", false},
    {0,           0,   NULL,      false}
};

const scan valid_scans[] = {
    {SCAN_SYN,  "SYN" },
    {SCAN_NULL, "NULL"},
    {SCAN_ACK,  "ACK" },
    {SCAN_FIN,  "FIN" },
    {SCAN_XMAS, "XMAS"},
    {SCAN_UDP,  "UDP" },
    {0,         ""    },
};

static void args_error(void) {
    fprintf(stderr, "See the output of nmap -h for a summary of options.\n");
    exit(EXIT_ARGS);
}

static int atoi_check(char* s, int max, char* opt_name, bool zero_allowed) {
    // TODO: Axel check no negative
    // TODO: Axel check 0
    int n = 0;
    int modulo = max % 10;
    int limit = max / 10;
    bool is_negative = s[0] == '-';

    for (int i = is_negative; s[i]; i++)
        if (!isdigit(s[i])) {
            fprintf(stderr, "nmap: invalid %s value (`%s' near `%s')\n", opt_name, s, s + i);
            exit(EXIT_FAILURE);
        }

    if (is_negative) {
        fprintf(stderr, "nmap: %s value too small: %s\n", opt_name, s);
        exit(EXIT_FAILURE);
    }

    for (int i = 0; s[i]; i++) {
        if ((n == limit && s[i] > modulo + '0') || n > limit) {
            fprintf(stderr, "nmap: %s value too big: %s\n", opt_name, s);
            exit(EXIT_FAILURE);
        }
        n = n * 10 + s[i] - '0';
    }

    if (!zero_allowed && n == 0) {
        fprintf(stderr, "nmap: %s value too small: 0", opt_name);
        exit(EXIT_FAILURE);
    }

    return n;
}

static void parse_ports(char* value, uint64_t* ports) {
    char* end = strchr(value, '\0');
    char* comma = end;

    while (comma) {
        comma = strchr(value, ',');
        if (value == comma || comma == end - 1) {
            fprintf(stderr, "nmap: invalid port value (`%s')\n", comma);
            exit(EXIT_FAILURE);
        }
        if (comma) *comma = '\0';

        char* hyphen = strchr(value, '-');
        if (value == hyphen || hyphen == end - 1) {
            fprintf(stderr, "nmap: invalid port value (`%s')\n", hyphen);
            exit(EXIT_FAILURE);
        }

        if (hyphen) {
            *hyphen = '\0';
            int left = atoi_check(value, UINT16_MAX, "port", true);
            int right = atoi_check(hyphen + 1, UINT16_MAX, "port", true);
            if (left > right) {
                fprintf(stderr, "Your port range %d-%d is backwards. Did you mean %d-%d?\nQUITTING!\n", left, right, right, left);
                exit(EXIT_FAILURE);
            }
            for (int i = left; i <= right; ++i) set_port(ports, i);
        } else set_port(ports, atoi_check(value, UINT16_MAX, "port", true));

        value = comma + 1;
    }
}

static void parse_scan(char* value, uint8_t* scan) {
    char* end = strchr(value, '\0');
    char* comma = end;

    while (comma) {
        comma = strchr(value, ',');
        if (value == comma || comma == end - 1) {
            fprintf(stderr, "nmap: invalid scan value (`%s')\n", comma);
            exit(EXIT_FAILURE);
        }
        if (comma) *comma = '\0';

        bool valid_scan = false;
        for (size_t j = 0; valid_scans[j].type; ++j) {
            if (!strcmp(value, valid_scans[j].name)) {
                *scan |= valid_scans[j].type;
                valid_scan = true;
                break;
            }
        }

        if (!valid_scan) {
            fprintf(stderr, "nmap: invalid scan value (`%s')\n", value);
            exit(EXIT_FAILURE);
        }

        value = comma + 1;
    }
}

static bool handle_arg(int opt, char* value, char short_opt, char* long_opt, nmap* nmap) {
    if (value == NULL) {
        if (long_opt) fprintf(stderr, "nmap: option '--%s' requires an argument\n", long_opt);
        else fprintf(stderr, "nmap: option requires an argument -- '%c'\n", short_opt);
        args_error();
    }
    // TODO: Lorenzo error messages
    if (nmap->opt & opt) { // en fait pour moi t'as le droit de faire -p 80 --threads=20 -p 443, de facto nmap fait comme ça pour certaines options. pour les portes on a un check dans le parsing avec la map uint64_t, donc en vrai balec
        if (long_opt) fprintf(stderr, "nmap: duplicate option: '--%s'\n", long_opt);
        else fprintf(stderr, "nmap: duplicate option: '-%c'\n", short_opt);
        args_error();
    }

    nmap->opt |= opt;
    switch (opt) {
        case OPT_FILE:
            nmap->file = fopen(value, "r");
            if (!nmap->file) error("Failed to open input file for reading");
            break;
        case OPT_PORTS: parse_ports(value, nmap->ports); break;
        case OPT_SCAN: parse_scan(value, &nmap->scan); break;
        case OPT_THREADS: nmap->threads = atoi_check(value, UINT8_MAX, "threads", true); break;
    }
    return true;
}

static bool handle_long_opt(char* opt, int i, int* index, char** argv, nmap* nmap) {
    char* equal_sign = strchr(opt, '=');
    size_t len = equal_sign != NULL ? (size_t)(equal_sign - opt) : strlen(opt);
    bool ambiguous = false;
    if (strncmp(opt, valid_opt[i].long_opt, len) == 0) {
        for (int j = i + 1; valid_opt[j].opt; ++j)
            if (strncmp(opt, valid_opt[j].long_opt, len) == 0) {
                if (!ambiguous) {
                    fprintf(stderr, "nmap: option '--%s' is ambiguous; possibilities: '--%s'", opt, valid_opt[i].long_opt);
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
            nmap->opt |= valid_opt[i].opt;
            if (nmap->opt & OPT_HELP) print_help();
            // TODO: version/usage
        } else {
            if (equal_sign == NULL) (*index)++;
            handle_arg(valid_opt[i].opt, equal_sign ? equal_sign + 1 : *(++argv), 0, valid_opt[i].long_opt, nmap);
        }
        return true;
    }
    return false;
}

static bool is_valid_opt(char** arg, int* index, nmap* nmap) {
    bool is_long_opt = *(*arg + 1) == '-';
    bool valid = true;
    bool found_long_opt = false;

    do
        for (int i = 0; valid_opt[i].opt; i++) {
            if (is_long_opt)
                if ((found_long_opt = handle_long_opt(*arg + 2, i, index, arg, nmap)) == true) return true;
            if (!is_long_opt && *(*arg + 1) == valid_opt[i].short_opt) {
                if (valid_opt[i].has_arg == false) nmap->opt |= valid_opt[i].opt;
                else {
                    if (*(*arg + 2) == '\0') (*index)++;
                    return handle_arg(valid_opt[i].opt, *(*arg + 2) ? *arg + 2 : *(++arg), valid_opt[i].short_opt, NULL, nmap);
                }
                if (nmap->opt & OPT_HELP) print_help();
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

void verify_arguments(int argc, char* argv[], nmap* nmap) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            if (!*nmap->hostname && i + 1 < argc) {
                strncpy(nmap->hostname, argv[i + 1], HOST_NAME_MAX);
                nmap->hostname[HOST_NAME_MAX] = '\0';
            }
            break;
        } else if (argv[i][0] == '-' && argv[i][1]) {
            if (!is_valid_opt(&argv[i], &i, nmap)) handle_unrecognized_opt(argv[i]);
        } else if (!*nmap->hostname) {
            strncpy(nmap->hostname, argv[i], HOST_NAME_MAX);
            nmap->hostname[HOST_NAME_MAX] = '\0';
        }
        // else
        //	fprintf(stderr, "nmap: extra operand `%s'\n", argv[i]), args_error();
    }
    if (!*nmap->hostname) {
        fprintf(stderr, "WARNING: No targets were specified, so 0 hosts scanned.\n");
        args_error();
    }
}
