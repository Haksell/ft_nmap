#include "ft_nmap.h"

volatile sig_atomic_t run = true;
pthread_mutex_t mutex_run;
t_thread_globals thread_globals[MAX_HOSTNAMES];

static void final_credits(t_nmap* nmap) {
    printf("\nnmap done: %d IP addresses ", nmap->hostname_count);
    if (!(nmap->opt & OPT_SPOOF_ADDRESS)) {
        uint16_t hosts_up = 0;
        for (uint16_t i = 0; i < nmap->hostname_count; ++i) hosts_up += nmap->hosts[i].is_up;
        printf("(%d hosts up) ", hosts_up);
    }
    printf("scanned in %.2f seconds\n", (get_microseconds() - nmap->start_time) / 1000000.0);
}

static void launch_threads(t_nmap* nmap) {
    for (nmap->started_threads = 0; nmap->started_threads < nmap->num_threads && run; ++nmap->started_threads) {
        nmap->threads[nmap->started_threads] = (t_thread_info){
            .nmap = nmap,
            .globals = thread_globals[nmap->started_threads],
            .t_index = nmap->started_threads,
        };
        int res = pthread_create(
            &nmap->threads[nmap->started_threads].thread_id,
            NULL,
            send_packets,
            nmap->threads + nmap->started_threads
        );
        if (res != 0) panic("Failed to create the sender thread");
    }
}

int main(int argc, char* argv[]) {
    t_nmap nmap = {0};
    parse_args(argc, argv, &nmap);
    init_nmap(&nmap);

    if (nmap.num_threads == 0) {
        send_packets(&(t_thread_info){
            .nmap = &nmap,
            .globals = thread_globals[0],
            .t_index = 0,
        });
    } else launch_threads(&nmap);

    for (int i = 0; i < nmap.num_threads; ++i) pthread_join(nmap.threads[i].thread_id, NULL);
    if (run) final_credits(&nmap);
    cleanup(&nmap);
    return EXIT_SUCCESS;
}
