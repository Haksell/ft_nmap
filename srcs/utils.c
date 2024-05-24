#include "ft_nmap.h"

bool hostname_to_ip(char hostname[HOST_NAME_MAX + 1], char hostip[INET_ADDRSTRLEN + 1]) {
    struct addrinfo hints = {.ai_family = AF_INET};
    struct addrinfo* res = NULL;

    int status = getaddrinfo(hostname, NULL, &hints, &res);
    if (status == 0 && res != NULL) {
        if (!inet_ntop(AF_INET, &((struct sockaddr_in*)res->ai_addr)->sin_addr, hostip, INET_ADDRSTRLEN)) {
            freeaddrinfo(res);
            error("inet_ntop failed");
        }
        freeaddrinfo(res);
        return true;
    } else if (status == EAI_NONAME || status == EAI_AGAIN) {
        printf("nmap: cannot resolve %s: %s\n\n", hostname, gai_strerror(status));
        return false;
    } else {
        panic("nmap: getaddrinfo failed: %s\n", gai_strerror(status));
        return false;
    }
}

bool ip_to_hostname(struct in_addr ip_address, char* host, size_t hostlen) {
    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_addr = ip_address,
    };

    return getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, hostlen, NULL, 0, NI_NAMEREQD) == 0;
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

uint64_t get_microseconds() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000 + tv.tv_usec;
}
