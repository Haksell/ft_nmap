#include "ft_nmap.h"

void error(char* message) {
    fprintf(
        stderr, "nmap: %s: %s\n", message, strerror(errno)
    ); // ajouter if socket->fd > 0 close fd
    exit(EXIT_FAILURE);
}

void g_error(int status) {
    if (status != EAI_NONAME) fprintf(stderr, "nmap: %s\n", gai_strerror(status));
    else fprintf(stderr, "nmap: %s\n", "unknown host");
    exit(EXIT_FAILURE);
}

void hostname_to_ip(nmap* nmap) {
    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_flags = AI_CANONNAME,
    };
    struct addrinfo* res = NULL;

    int status = getaddrinfo(nmap->hostname, NULL, &hints, &res);
    if (status != 0) g_error(status);

    nmap->hostaddr = *(struct sockaddr_in*)res->ai_addr;
    if (inet_ntop(AF_INET, &nmap->hostaddr.sin_addr, nmap->hostip, INET_ADDRSTRLEN) == NULL)
        error("inet_ntop failed");

    if (res->ai_canonname) {
        strncpy(nmap->hostname, res->ai_canonname, HOST_NAME_MAX);
        nmap->hostname[HOST_NAME_MAX - 1] = '\0';
    }

    freeaddrinfo(res);
}

bool ip_to_hostname(struct in_addr ip_address, char* host, size_t hostlen) {
    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_addr = ip_address,
    };

    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, hostlen, NULL, 0, NI_NAMEREQD))
        return false;
    return true;
}