#include "ft_nmap.h"

static float get_elapsed_time(t_nmap* nmap) {
    struct timeval end_time;
    gettimeofday(&end_time, NULL);

    struct timeval elapsed_time = timeval_subtract(nmap->start_time, end_time);
    return elapsed_time.tv_sec + elapsed_time.tv_usec / 1000000.0;
}

void final_credits(t_nmap* nmap) {
    int hosts_up = 0;
    for (int i = 0; i < nmap->hostname_count; ++i) hosts_up += nmap->hosts[i].is_up;
    printf("\nnmap done: %d IP addresses (%d hosts up) scanned in %.2f seconds\n", nmap->hostname_count, hosts_up, get_elapsed_time(nmap));
}
