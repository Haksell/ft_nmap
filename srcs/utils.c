#include "ft_nmap.h"

#define GAI_RETRY_US 100000

bool hostname_to_ip(char hostname[HOST_NAME_MAX + 1], char hostip[INET_ADDRSTRLEN + 1]) {
    struct addrinfo hints = {.ai_family = AF_INET};
    struct addrinfo* res = NULL;

    int status;
    for (size_t i = 0; i < 10; ++i) {
        status = getaddrinfo(hostname, NULL, &hints, &res);
        if (status == 0 && res != NULL) break;
        if (status == EAI_AGAIN || status == EAI_SYSTEM) {
            usleep(GAI_RETRY_US);
        } else if (status == EAI_NONAME) {
            fprintf(stdout, "\nnmap: cannot resolve %s: %s\n", hostname, gai_strerror(status));
            return false;
        } else {
            fprintf(stderr, "\nnmap: getaddrinfo failed: %s\n", gai_strerror(status));
            return false;
        }
    }

    if (!inet_ntop(AF_INET, &((struct sockaddr_in*)res->ai_addr)->sin_addr, hostip, INET_ADDRSTRLEN)) {
        freeaddrinfo(res);
        error("inet_ntop failed");
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
            if (strcmp(ifa->ifa_name, "lo") == 0) continue; // TODO: Lorenzo check
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)ifa->ifa_addr;
            source_address = ipv4->sin_addr.s_addr;
            break;
        }
    }

    freeifaddrs(ifaddr);
    return source_address; // a verifier lorenzo
}

// TODO: use uint64_t directly and remove this function
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

void print_start_time(t_nmap* nmap) {
    nmap->start_time = get_microseconds();
    time_t epoch_secs = nmap->start_time / 1000000;
    struct tm* tm = localtime(&epoch_secs);

    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M %Z", tm);
    printf("Starting nmap %s at %s\n", VERSION, timestamp);
}

uint64_t get_microseconds() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000 + tv.tv_usec;
}
