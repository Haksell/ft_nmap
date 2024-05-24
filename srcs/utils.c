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

uint64_t get_microseconds() {
    struct timeval tv;
    if (gettimeofday(&tv, NULL) == -1) error("gettimeofday failed");
    return tv.tv_sec * 1000000 + tv.tv_usec;
}
