#include "ft_nmap.h"

extern pcap_t* handle;

void error(char* message) {
    // TODO: use panic
    fprintf(stderr, "nmap: %s: %s\n", message, strerror(errno));
    exit(EXIT_FAILURE); // TODO creer un exit personalisé qui appelle cleanup()
}

void g_error(char* message, int status) {
    // TODO: use panic
    if (status != EAI_NONAME) fprintf(stderr, "nmap: %s: %s\n", message, gai_strerror(status));
    else fprintf(stderr, "nmap: %s\n", "unknown host");
    exit(EXIT_FAILURE); // TODO creer un exit personalisé qui appelle cleanup()
}

void panic(const char* format, ...) {
    // TODO: free everything
    // TODO: write "ft_nmap: " directly here
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    exit(EXIT_FAILURE);
}

bool hostname_to_ip(t_nmap* nmap) {
    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_flags = AI_CANONNAME,
    };
    struct addrinfo* res = NULL;
    char* hostname = nmap->hostnames[nmap->hostname_index];

    int status = getaddrinfo(hostname, NULL, &hints, &res);
    if (status != 0 || res == NULL) {
        if (status == EAI_NONAME || status == EAI_AGAIN) {
            fprintf(stderr, "\nnmap: cannot resolve %s: %s\n", hostname, gai_strerror(status));
            return false;
        }
        g_error("getaddrinfo failed", status);
    }

    if (inet_ntop(AF_INET, &((struct sockaddr_in*)res->ai_addr)->sin_addr, nmap->hostip, INET_ADDRSTRLEN) == NULL) {
        freeaddrinfo(res);
        error("inet_ntop failed");
    }

    if (res->ai_canonname) {
        strncpy(hostname, res->ai_canonname, HOST_NAME_MAX);
        hostname[HOST_NAME_MAX] = '\0';
    }

    freeaddrinfo(res);
    return true;
}

bool ip_to_hostname(struct in_addr ip_address, char* host, size_t hostlen) {
    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_addr = ip_address,
    };

    return getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, hostlen, NULL, 0, NI_NAMEREQD) == 0;
}

in_addr_t get_source_address() {
    struct ifaddrs *ifaddr, *ifa;
    in_addr_t source_address = 0;

    if (getifaddrs(&ifaddr) == -1) error("getifaddrs failed");

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_INET) {
            if (strcmp(ifa->ifa_name, "lo") == 0) continue; /// c'est pas bon
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)ifa->ifa_addr;
            source_address = ipv4->sin_addr.s_addr;
            break;
        }
    }

    freeifaddrs(ifaddr);
    return source_address; // a verifier lorenzo
}

struct timeval timeval_subtract(struct timeval start, struct timeval end) {
    struct timeval result = {
        .tv_sec = end.tv_sec - start.tv_sec,
        .tv_usec = end.tv_usec - start.tv_usec,
    };

    if (result.tv_usec < 0) {
        result.tv_sec--;
        result.tv_usec += 1000000;
    }

    return result;
}

void get_start_time(t_nmap* nmap) {
    gettimeofday(&nmap->start_time, NULL);
    struct tm* tm = localtime(&nmap->start_time.tv_sec);

    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M %Z", tm);

    printf("Starting Nmap %s at %s\n", VERSION, timestamp);

    if (nmap->hostname_count == 0) {
        fprintf(stderr, "WARNING: No targets were specified, so 0 hosts scanned.\n");
        // Pourquoi on exit plus ? Et qu'est-ce que ca fait dans cette fonction ?
    }
}

static float get_elapsed_time(t_nmap* nmap) {
    struct timeval end_time;
    gettimeofday(&end_time, NULL);

    struct timeval elapsed_time = timeval_subtract(nmap->start_time, end_time);
    return elapsed_time.tv_sec + elapsed_time.tv_usec / 1000000.0;
}

void print_stats(t_nmap* nmap) {
    printf(
        "\nNmap done: %d IP addresses (%d hosts up) scanned in %.2f seconds\n",
        nmap->hostname_count,
        nmap->hostname_up_count,
        get_elapsed_time(nmap)
    );
}

void cleanup(t_nmap* nmap
) { // a utiliser dans la function exit en cas d'erreur + ajouter eventuellement autres choses qui vont etre free
    if (nmap->devs) pcap_freealldevs(nmap->devs);
    if (handle) pcap_close(handle);
    if (nmap->tcp_fd > 2) close(nmap->tcp_fd); // > 2 plutot ?
    if (nmap->udp_fd > 2) close(nmap->udp_fd);
    if (nmap->icmp_fd > 2) close(nmap->icmp_fd);
}
