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

#include "libft.h"

struct host {
	char *h_name;
	struct in_addr ip_addr;
	char **ip_list;
	struct ether_addr mac_addr;
};

// program options
struct host g_host;
struct host g_requested_host;
struct ether_addr g_mac_address;
bool g_verbose = false;

void print_ethernet_header(struct ether_header *eth_hdr)
{
	if (g_verbose) {
		printf("\tSource MAC: %s\n", ether_ntoa((struct ether_addr *)eth_hdr->ether_shost));
		printf("\tTarget MAC: %s\n", ether_ntoa((struct ether_addr *)eth_hdr->ether_dhost));
	}
}

void print_arp_header(struct ether_arp *arp_hdr, int recv_len)
{
	if (g_verbose) {
		char sender_ip_str[INET_ADDRSTRLEN];
		char target_ip_str[INET_ADDRSTRLEN];

		if (inet_ntop(AF_INET, arp_hdr->arp_spa, sender_ip_str, sizeof(sender_ip_str)) == NULL) {
			strerror(errno);
			return;
		}
		if (inet_ntop(AF_INET, arp_hdr->arp_tpa, target_ip_str, sizeof(target_ip_str)) == NULL) {
			strerror(errno);
			return;
		}

		printf("\t\tHardware type: %s\n", ntohs(arp_hdr->arp_hrd) == ARPHRD_ETHER ? "Ethernet" : "Unknown");
		printf("\t\tProtocol type: %s\n", ntohs(arp_hdr->arp_pro) == ETHERTYPE_IP ? "IPv4" : "Unknown");
		printf("\t\tHardware size: %d\n", arp_hdr->arp_hln);
		printf("\t\tProtocol size: %d\n", arp_hdr->arp_pln);
		printf("\t\tOpcode: %s\n", ntohs(arp_hdr->arp_op) == ARPOP_REQUEST ? "Request" : ntohs(arp_hdr->arp_op) == ARPOP_REPLY ? "Reply" : "Unknown");
		printf("\t\tSender MAC: %s\n", ether_ntoa((struct ether_addr *)arp_hdr->arp_sha));
		printf("\t\tSender IP: %s\n", sender_ip_str);
		printf("\t\tTarget MAC: %s\n", ether_ntoa((struct ether_addr *)arp_hdr->arp_tha));
		printf("\t\tTarget IP: %s\n", target_ip_str);
		printf("\t\tPacket length: %d\n", recv_len);
	}
}

// function to convert a string to a mac address as ether_addr
int ft_ether_aton(const char *asc, struct ether_addr *haddr)
{
	// Check the length of the input string
	if (ft_strlen(asc) != 17)
	{
		return 0; // Invalid MAC address length
	}

	char nb[3];
	nb[2] = '\0';

	// Check if each byte of the MAC address is within a valid range
	for (int i = 0; i < 6; ++i)
	{
		nb[0] = asc[i * 3];
		nb[1] = asc[i * 3 + 1];
		if (ft_isalnum(nb[0]) == 0 || ft_isalnum(nb[1]) == 0)
		{
			return 0; // Invalid MAC address
		}
		haddr->ether_addr_octet[i] = ft_strtol(nb, NULL, 16);
	}

	return 1; // Valid MAC address
}

void send_arp_reply(int sfd, uint8_t *host_ip, uint8_t *host_mac, uint8_t *requested_ip, struct sockaddr_ll *recv_addr)
{
	struct ether_header eth_hdr;
	struct ether_arp arp_hdr;

	// fill ethernet header
	eth_hdr.ether_type = htons(ETHERTYPE_ARP);
	ft_memcpy(eth_hdr.ether_shost, g_mac_address.ether_addr_octet, ETHER_ADDR_LEN);
	ft_memcpy(eth_hdr.ether_dhost, host_mac, ETHER_ADDR_LEN);

	// fill arp header
	arp_hdr.arp_hrd = htons(ARPHRD_ETHER);
	arp_hdr.arp_pro = htons(ETHERTYPE_IP);
	arp_hdr.arp_hln = ETHER_ADDR_LEN;
	arp_hdr.arp_pln = sizeof(in_addr_t);
	arp_hdr.arp_op = htons(ARPOP_REPLY);
	ft_memcpy(arp_hdr.arp_sha, g_mac_address.ether_addr_octet, ETHER_ADDR_LEN);
	ft_memcpy(arp_hdr.arp_spa, requested_ip, sizeof(in_addr_t));
	ft_memcpy(arp_hdr.arp_tha, host_mac, ETHER_ADDR_LEN);
	ft_memcpy(arp_hdr.arp_tpa, host_ip, sizeof(in_addr_t));

	// fill buffer
	char buf[ETHER_HDR_LEN + sizeof(struct ether_arp)];
	ft_memcpy(buf, &eth_hdr, sizeof(struct ether_header));
	ft_memcpy(buf + sizeof(struct ether_header), &arp_hdr, sizeof(struct ether_arp));

	// print packet
	printf("\tSending reply\n");
	print_ethernet_header(&eth_hdr);
	print_arp_header(&arp_hdr, sizeof(buf));

	// send packet to requester
	if (sendto(sfd, buf, sizeof(buf), 0, (struct sockaddr *)recv_addr, sizeof(struct sockaddr_ll)) == -1)
	{
		strerror(errno);
		return;
	}
	printf("\t\tSent reply!\n");
}

void handle_arp_packets(int sfd)
{
	struct sockaddr_ll recv_addr;
	socklen_t recv_addr_len = sizeof(recv_addr);
	char recv_buf[ETH_FRAME_LEN];
	int recv_len;

	memset(&recv_addr, 0, sizeof(recv_addr));

	while (1)
	{
		recv_len = recvfrom(sfd, recv_buf, ETH_FRAME_LEN, 0, (struct sockaddr *)&recv_addr, &recv_addr_len);
		if (recv_len == -1) {
			strerror(errno);
			return;
		}
		printf("Received packet!\n");
		struct ether_header *eth_hdr = (struct ether_header *)recv_buf;
		struct ether_arp *arp_hdr = (struct ether_arp *)(recv_buf + sizeof(struct ether_header));

		// print mac addresses from ethernet header
		print_ethernet_header(eth_hdr);

		// check if the packet is an arp request
		if (ntohs(arp_hdr->arp_op) == ARPOP_REQUEST) {
			printf("\tIt's a request!\n");
			print_arp_header(arp_hdr, recv_len);

			if ((ft_memcmp(&arp_hdr->arp_spa, &g_host.ip_addr.s_addr, sizeof(in_addr_t)) == 0) ||
				(ft_memcmp(&arp_hdr->arp_sha, &g_host.mac_addr.ether_addr_octet, ETHER_ADDR_LEN) == 0)) 
			{
				//if request host ip is not null, then the option -r was used and we need to check if the requested host ip is the same as the one in the packet before sending the reply
				if (g_requested_host.ip_addr.s_addr != 0 && ft_memcmp(&arp_hdr->arp_tpa, &g_requested_host.ip_addr.s_addr, sizeof(in_addr_t)) != 0)
					continue;

				// send arp reply
				send_arp_reply(sfd, arp_hdr->arp_spa, arp_hdr->arp_sha, arp_hdr->arp_tpa, &recv_addr);
				break ;
			}
		}
	}
}

struct ifaddrs *find_interface(struct ifaddrs *ifaddr)
{
	struct ifaddrs *ifa;

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		// check if interface is up and has a broadcast address
		if (ifa->ifa_addr->sa_family == AF_INET && ifa->ifa_flags & IFF_UP && ifa->ifa_flags & IFF_BROADCAST) {
			// get the broadcast address
			struct sockaddr_in *broad_addr = (struct sockaddr_in *)ifa->ifa_dstaddr;

			char broad_addr_str[INET_ADDRSTRLEN];
			if (inet_ntop(AF_INET, &(broad_addr->sin_addr), broad_addr_str, sizeof(broad_addr_str)) == NULL)
			{
				strerror(errno);
				break;
			}

			// check if the broadcast address is from the same network using the ifa_netmask
			struct sockaddr_in *mask = (struct sockaddr_in *)ifa->ifa_netmask;

			if (g_host.ip_addr.s_addr & mask->sin_addr.s_addr == broad_addr->sin_addr.s_addr & mask->sin_addr.s_addr) {
				printf("Found interface %s with broadcast address %s\n", ifa->ifa_name, broad_addr_str);
				return ifa;
			}
			// if g_host.ip_addr is not set, check all the ips from g_host.ip_list
			else if (g_host.ip_addr.s_addr == 0) {
				for (int i = 0; g_host.ip_list[i] != NULL; i++) {
					in_addr_t ip = *(in_addr_t *)g_host.ip_list[i];
					printf("Checking if %s is in the same network as %s\n", inet_ntoa(*(struct in_addr *)&ip), broad_addr_str);
					//print results of bits operations
					if ((ip & mask->sin_addr.s_addr) == (broad_addr->sin_addr.s_addr & mask->sin_addr.s_addr)) {
						printf("Found interface %s with broadcast address %s\n", ifa->ifa_name, broad_addr_str);
						g_host.ip_addr.s_addr = ip;
						return ifa;
					}
					else {
						printf("%s is not in the same network as %s\n", inet_ntoa(*(struct in_addr *)&ip), broad_addr_str);
					}
				}
			}
			else {
				printf("Found interface %s with broadcast address %s but not in the same network\n", ifa->ifa_name, broad_addr_str);
			}
		}
	}
	return NULL;
}

int get_mac_address(char *iface, unsigned char *mac) {
	char path[128];
	int fd;

	snprintf(path, sizeof(path), "/sys/class/net/%s/address", iface);
	fd = open(path, O_RDONLY);
	if (fd == -1) {
		perror("open");
		return 1;
	}

	char mac_str[18];
	ssize_t n = read(fd, mac_str, sizeof(mac_str) - 1);
	if (n == -1) {
		perror("read");
		close(fd);
		return 1;
	}
	mac_str[n] = '\0';

	if (ft_ether_aton(mac_str, (struct ether_addr *)mac) == 0) {
		fprintf(stderr, "Invalid MAC address: %s\n", mac_str);
		close(fd);
		return 1;
	}

	close(fd);
	return 0;
}

void create_socket()
{
	// create socket
	int sfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (sfd == -1)
	{
		strerror(errno);
		return;
	}

	// find interface
	struct ifaddrs *ifaddr, *interface;
	if (getifaddrs(&ifaddr) == -1) {
		strerror(errno);
		return;
	}
	if ((interface = find_interface(ifaddr)) == NULL) {
		return;
	}
	// if g_mac_address is not set, use the interface mac address
	if (g_mac_address.ether_addr_octet[0] == 0 && g_mac_address.ether_addr_octet[1] == 0 && g_mac_address.ether_addr_octet[2] == 0 && g_mac_address.ether_addr_octet[3] == 0 && g_mac_address.ether_addr_octet[4] == 0 && g_mac_address.ether_addr_octet[5] == 0) {
		if (get_mac_address(interface->ifa_name, g_mac_address.ether_addr_octet) == 1) {
			return;
		}
	}

	printf("Using interface %s with MAC address %s\n", interface->ifa_name, ether_ntoa(&g_mac_address));

	// set interface to socket
	if (setsockopt(sfd, SOL_SOCKET, SO_BINDTODEVICE, interface->ifa_name, ft_strlen(interface->ifa_name)) == -1) {
		strerror(errno);
		return;
	}
	freeifaddrs(ifaddr);

	// handle arp packets
	handle_arp_packets(sfd);

	// close socket
	close(sfd);
}


int get_host(struct host *host, char *host_arg) {
	struct hostent *hostent = NULL;

	// check if host is an IP address
	if (inet_pton(AF_INET, host_arg, &host->ip_addr) == 0) {
		// check if host is a MAC address
		if (ft_ether_aton(host_arg, &host->mac_addr) == 0) {
			// check if host is a hostname and get its IP address if it is
			hostent = gethostbyname(host_arg);
			if (hostent == NULL)
				return -1;
			host->h_name = host_arg;
			host->ip_list = hostent->h_addr_list;
			return 2;
		}
		return 1;
	}

	return 0;
}

int get_args(int argc, char **argv) {
	char *host_arg = argv[1];
	char *requested_host_arg = NULL;
	char *mac_address_arg = NULL;
	
	for (int i = 2; i < argc; i++) {
		if (ft_strcmp(argv[i], "-r") == 0) {
			if (i + 1 < argc)
				requested_host_arg = argv[++i];
			else {
				printf("Missing argument for -t\n");
				return 1;
			}
		}
		else if (ft_strcmp(argv[i], "-m") == 0) {
			if (i + 1 < argc)
				mac_address_arg = argv[++i];
			else {
				printf("Missing argument for -m\n");
				return 1;
			}
		}
		else if (ft_strcmp(argv[i], "-v") == 0)
			g_verbose = 1;
		else {
			printf("Unknown option: %s\n", argv[i]);
			return 1;
		}
	}

	if (get_host(&g_host, host_arg) == -1) {
		printf("Invalid host: %s\n", host_arg);
		return 1;
	}

	if (requested_host_arg != NULL) {
		int ret = get_host(&g_requested_host, requested_host_arg);
		if (ret == -1 || ret == 2) {
			printf("-r : Invalid requested host: %s\n", requested_host_arg);
			return 1;
		}
	}

	if (mac_address_arg != NULL) {
		if (ft_ether_aton(mac_address_arg, &g_mac_address) == 0) {
			printf("-m : Invalid MAC address\n");
			return 1;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2 || argc > 7)
	{
		printf("Usage: %s host [-r requested_host] [-m mac_address] [-v]\n", argv[0]);
		printf("  host: The hostname, IP address, or MAC address of the target machine.\n");
		printf("  -r requested_host: The hostname or IP address of the requested machine.\n");
		printf("  -m mac_address: The MAC address to use for the arp reply. (by default, the current machine address is used)\n");
		printf("  -v: Enable verbose mode.\n");
		return 1;
	}

	ft_bzero(&g_host, sizeof(struct host));
	ft_bzero(&g_requested_host, sizeof(struct host));
	ft_bzero(&g_mac_address, sizeof(struct ether_addr));

	if (get_args(argc, argv) == 1)
		return 1;

	create_socket();

	return 0;
}
