#include "ft_nmap.h"

void create_socket(nmap *nmap)
{
	if (geteuid() != 0)
	{
		fprintf(stderr, "This program requires root privileges for raw socket creation.\n");
		exit(EXIT_FAILURE);
	}

	nmap->fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);  // faudra un deuxieme socket pour les paquets UDP //  a reflechir dans l'avenir si on cree un socket pour chaque type de scan. en multi-threading avec 255 threads, on peut faire 255 scans en meme temps, mais donc faut-il 255 sockets en meme temps ? Ou poll va automatiquement gerer ca ? sur ping meme avec flood ça passe, donc bon
	if (nmap->fd < 0)
		error("Socket creation failed");

	if (!(nmap->opt & OPT_PORTS))
		for (int port = 0; port < 1024; port++) // for (int i = 0; i < 15; i++)  nmap->ports[i] = 1 << 64 - i; plus rapide
			set_port(nmap->ports, port);
	if (!(nmap->opt & OPT_SCAN))
		nmap->opt |= 0b111111;

	
	gettimeofday(&nmap->start_time, NULL);
	struct tm *tm = localtime(&nmap->start_time.tv_sec);
	char timestamp[21];
	strftime(timestamp, 21, "%Y-%m-%d %H:%M CET", tm);
	printf("Starting Nmap %s at %s\n", VERSION, timestamp);
}