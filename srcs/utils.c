#include "ft_nmap.h"

void error(char* message) {
    fprintf(stderr, "nmap: %s: %s\n", message, strerror(errno)); // ajouter if socket->fd > 0 close fd
    exit(EXIT_FAILURE);
}

void g_error(char* message, int status) {
    if (status != EAI_NONAME) fprintf(stderr, "nmap: %s: %s\n", message, gai_strerror(status));
    else fprintf(stderr, "nmap: %s\n", "unknown host");
    exit(EXIT_FAILURE);
}

void hostname_to_ip(t_nmap* nmap) {
    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_flags = AI_CANONNAME,
    };
    struct addrinfo* res = NULL;

    int status = getaddrinfo(nmap->hostnames[0], NULL, &hints, &res);
    if (status != 0) g_error("getaddrinfo failed", status);

    if (inet_ntop(AF_INET, &((struct sockaddr_in*)res->ai_addr)->sin_addr, nmap->hostip, INET_ADDRSTRLEN) == NULL)
        error("inet_ntop failed");

    if (res->ai_canonname) {
        strncpy(nmap->hostnames[0], res->ai_canonname, HOST_NAME_MAX);
        nmap->hostnames[0][HOST_NAME_MAX - 1] = '\0';
    }

    freeaddrinfo(res);
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

void panic(const char* format, ...) {
    // TODO: use error
    // TODO: free everything
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    exit(EXIT_FAILURE);
}
