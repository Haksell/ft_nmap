#include "ft_nmap.h"

static int short_space(t_option* opt) { return 4 * (opt->short_opt != '\0'); }

static int longest_option() {
    int res = 0;
    for (size_t i = 0; valid_opt[i].opt; ++i) {
        t_option o = valid_opt[i];
        res = MAX(res, short_space(&o) + strlen(o.long_opt));
    }
    return res;
}

static void print_help() {
    printf("ft_nmap [ip/hostname] [options]\n");
    int pad = -longest_option();
    for (size_t i = 0; valid_opt[i].opt; ++i) {
        t_option o = valid_opt[i];
        if (o.short_opt) printf("-%c, ", o.short_opt);
        printf("--%*s    %s\n", pad + short_space(&o), o.long_opt, o.description);
    }
}

void print_info(t_option_value new_opt, uint32_t nmap_opts) {
    if (nmap_opts & new_opt) return;
    if (new_opt == OPT_VERSION) printf("ft_nmap version " VERSION "\n");
    else if (new_opt == OPT_HELP) print_help();
}
