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

#include "libft.h"

bool verbose = false;

void print_ethernet_header(struct ether_header *eth_hdr) {
	if (verbose) {
	printf("\tSource MAC: %s\n", ether_ntoa((struct ether_addr *)eth_hdr->ether_shost));
	printf("\tTarget MAC: %s\n", ether_ntoa((struct ether_addr *)eth_hdr->ether_dhost));
	}
}

void print_arp_header(struct ether_arp *arp_hdr, int recv_len) {
	if (verbose) {
	char sender_ip_str[INET_ADDRSTRLEN];
	char target_ip_str[INET_ADDRSTRLEN];

	if (inet_ntop(AF_INET, arp_hdr->arp_spa, sender_ip_str, sizeof(sender_ip_str)) == NULL) {
		strerror(errno);
		return ;
	}
	if (inet_ntop(AF_INET, arp_hdr->arp_tpa, target_ip_str, sizeof(target_ip_str)) == NULL) {
		strerror(errno);
		return ;
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

struct ifaddrs* find_interface(struct ifaddrs *ifaddr, struct in_addr *requested_ip_addr, struct in_addr *requester_ip_addr) {
	struct ifaddrs *ifa;

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {

		//check if interface is up and has a broadcast address
		if (ifa->ifa_addr->sa_family == AF_INET && ifa->ifa_flags & IFF_UP && ifa->ifa_flags & IFF_BROADCAST) {

			//get the broadcast address
			struct sockaddr_in *broad_addr = (struct sockaddr_in *)ifa->ifa_dstaddr;

			char broad_addr_str[INET_ADDRSTRLEN];
			if (inet_ntop(AF_INET, &(broad_addr->sin_addr), broad_addr_str, sizeof(broad_addr_str)) == NULL) {
				strerror(errno);
				break ;
			}

			//check if the broadcast address is from the same network using the ifa_netmask
			struct sockaddr_in *mask = (struct sockaddr_in *)ifa->ifa_netmask;

			if ((requester_ip_addr->s_addr & mask->sin_addr.s_addr) == (broad_addr->sin_addr.s_addr & mask->sin_addr.s_addr) && \
				(requested_ip_addr->s_addr & mask->sin_addr.s_addr) == (broad_addr->sin_addr.s_addr & mask->sin_addr.s_addr))
			{
				printf("Found interface %s with broadcast address %s\n", ifa->ifa_name, broad_addr_str);
				return ifa;
			}
			else
			{
				printf("Found interface %s with broadcast address %s but not in the same network\n", ifa->ifa_name, broad_addr_str);
			}
		}
	}
	return NULL;
}

void send_arp_reply(int sfd, struct ether_addr *requested_mac_addr, struct ether_addr *requester_mac_addr, struct in_addr *requested_ip_addr, struct in_addr *requester_ip_addr, struct sockaddr_ll *recv_addr) {
	struct ether_header eth_hdr;
	struct ether_arp arp_hdr;

	//fill ethernet header
	eth_hdr.ether_type = htons(ETHERTYPE_ARP);
	ft_memcpy(eth_hdr.ether_shost, requested_mac_addr, ETHER_ADDR_LEN);
	ft_memcpy(eth_hdr.ether_dhost, requester_mac_addr, ETHER_ADDR_LEN);

	//fill arp header
	arp_hdr.arp_hrd = htons(ARPHRD_ETHER);
	arp_hdr.arp_pro = htons(ETHERTYPE_IP);
	arp_hdr.arp_hln = ETHER_ADDR_LEN;
	arp_hdr.arp_pln = sizeof(in_addr_t);
	arp_hdr.arp_op = htons(ARPOP_REPLY);
	ft_memcpy(arp_hdr.arp_sha, requested_mac_addr, ETHER_ADDR_LEN);
	ft_memcpy(arp_hdr.arp_spa, requested_ip_addr, sizeof(in_addr_t));
	ft_memcpy(arp_hdr.arp_tha, requester_mac_addr, ETHER_ADDR_LEN);
	ft_memcpy(arp_hdr.arp_tpa, requester_ip_addr, sizeof(in_addr_t));

	//fill buffer
	char buf[ETHER_HDR_LEN + sizeof(struct ether_arp)];
	ft_memcpy(buf, &eth_hdr, sizeof(struct ether_header));
	ft_memcpy(buf + sizeof(struct ether_header), &arp_hdr, sizeof(struct ether_arp));

	//print packet
	printf("\tSending reply\n");
	print_ethernet_header(&eth_hdr);
	print_arp_header(&arp_hdr, sizeof(buf));

	//send packet to requester
	if (sendto(sfd, buf, sizeof(buf), 0, (struct sockaddr *)recv_addr, sizeof(struct sockaddr_ll)) == -1) {
		strerror(errno);
		return ;
	}
	printf("\t\tSent reply!\n");
}

void handle_arp_packets(int sfd, struct ether_addr *requested_mac_addr, struct ether_addr *requester_mac_addr, struct in_addr *requested_ip_addr, struct in_addr *requester_ip_addr) {
	struct sockaddr_ll recv_addr;
	socklen_t recv_addr_len = sizeof(recv_addr);
	char recv_buf[ETH_FRAME_LEN];
	int recv_len;

	memset(&recv_addr, 0, sizeof(recv_addr));

	while (1) {
		recv_len = recvfrom(sfd, recv_buf, ETH_FRAME_LEN, 0, (struct sockaddr *)&recv_addr, &recv_addr_len);
		if (recv_len == -1) {
			strerror(errno);
			return ;
		}
		printf("Received packet!\n");
		struct ether_header *eth_hdr = (struct ether_header *)recv_buf;
		struct ether_arp *arp_hdr = (struct ether_arp *)(recv_buf + sizeof(struct ether_header));

		//print mac addresses from ethernet header
		print_ethernet_header(eth_hdr);

		// check if the packet is an arp request
		if (ntohs(arp_hdr->arp_op) == ARPOP_REQUEST) {

			printf("\tIt's a request!\n");
			print_arp_header(arp_hdr, recv_len);

			//check if the packet is for us
			if (ft_memcmp(&arp_hdr->arp_spa, requester_ip_addr, sizeof(struct in_addr)) == 0 &&
				ft_memcmp(&arp_hdr->arp_tpa, requested_ip_addr, sizeof(struct in_addr)) == 0) {
				send_arp_reply(sfd, requested_mac_addr, requester_mac_addr, requested_ip_addr, requester_ip_addr, &recv_addr);
				break;
			}
		}
	}
}

void create_socket(struct ether_addr *requested_mac_addr, struct ether_addr *requester_mac_addr, struct in_addr *requested_ip_addr, struct in_addr *requester_ip_addr) {
	//create socket
	int sfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (sfd == -1) {
		strerror(errno);
		return;
	}

	//find interface
	struct ifaddrs *ifaddr, *interface;
	if (getifaddrs(&ifaddr) == -1) {
		strerror(errno);
		return;
	}
	if ((interface = find_interface(ifaddr, requested_ip_addr, requester_ip_addr)) == NULL) {
		return ;
	}

	//set interface to socket
	if (setsockopt(sfd, SOL_SOCKET, SO_BINDTODEVICE, interface->ifa_name, strlen(interface->ifa_name)) == -1) {
		strerror(errno);
		return ;
	}
	freeifaddrs(ifaddr);

	//handle arp packets
	handle_arp_packets(sfd, requested_mac_addr, requester_mac_addr, requested_ip_addr, requester_ip_addr);

	//close socket
	close(sfd);
}

//function to convert a string to a mac address as ether_addr
int ft_ether_aton(const char *asc, struct ether_addr *haddr) {
    // Check the length of the input string
    if (strlen(asc) != 17) {
        return 0; // Invalid MAC address length
    }

	char nb[3];
	nb[2] = '\0';

    // Check if each byte of the MAC address is within a valid range
    for (int i = 0; i < 6; ++i) {
		nb[0] = asc[i * 3];
		nb[1] = asc[i * 3 + 1];
		if (ft_isalnum(nb[0]) == 0 || ft_isalnum(nb[1]) == 0) {
			return 0; // Invalid MAC address
		}
		haddr->ether_addr_octet[i] = ft_strtol(nb, NULL, 16);
    }

    return 1; // Valid MAC address
}

int main(int ac, char **av) {
	if (ac < 5) {
		printf("Usage: %s <requested_ip_address> <requested_mac_address> <requester_ip_address> <requester_mac_address> [-v]\n", av[0]);
		return 1;
	}

	struct ether_addr requested_mac_addr;
	struct ether_addr requester_mac_addr;
	struct in_addr requested_ip_addr;
	struct in_addr requester_ip_addr;

	if (inet_pton(AF_INET, av[1], &requested_ip_addr) == 0) {
		printf("Invalid requested ip address\n");
		return 1;
	}
	if (ft_ether_aton(av[2], &requested_mac_addr) == 0) {
		printf("Invalid requested mac address\n");
		return 1;
	}
	if (inet_pton(AF_INET, av[3], &requester_ip_addr) == 0) {
		printf("Invalid requester ip address\n");
		return 1;
	}	
	if (ft_ether_aton(av[4], &requester_mac_addr) == 0) {
		printf("Invalid requester mac address\n");
		return 1;
	}

	if (ac == 6 && strcmp(av[5], "-v") == 0) {
		verbose = true;
	}

	create_socket(&requested_mac_addr, &requester_mac_addr, &requested_ip_addr, &requester_ip_addr);

	return 0;
}
