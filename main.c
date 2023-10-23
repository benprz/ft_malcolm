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

#define SOURCE_IP_ADDRESS "172.17.0.12"
#define SOURCE_MAC_ADDRESS "ff:ff:ff:ff:ff:ff"
#define TARGET_IP_ADDRESS "172.17.0.3"
#define TARGET_MAC_ADDRESS "02:42:ac:11:00:03"

struct ifaddrs* find_interface(struct ifaddrs *ifaddr) {
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
			struct sockaddr_in target;
			if (inet_pton(AF_INET, TARGET_IP_ADDRESS, &(target.sin_addr)) == 0) {
				strerror(errno);
				break ;
			}

			if ((target.sin_addr.s_addr & mask->sin_addr.s_addr) == (broad_addr->sin_addr.s_addr & mask->sin_addr.s_addr))
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

int main() {

	//get interface address
	struct ifaddrs *ifaddr, *interface;
	
	if (getifaddrs(&ifaddr) == -1) {
		strerror(errno);
		return 1;
	}

	if ((interface = find_interface(ifaddr)) == NULL) {
		return 1;
	}

	//create socket
	int sfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (sfd == -1) {
		strerror(errno);
		return 1;
	}

	printf("Socket created\n");

	// //bind socket to interface
	// if (setsockopt(sfd, SOL_SOCKET, SO_BINDTODEVICE, interface->ifa_name, strlen(interface->ifa_name)) == -1) {
	// 	strerror(errno);        
	// 	return 1;
	// }

	//recvfrom broadcast address of the interface arp packets
	struct sockaddr_ll recv_addr;

	recv_addr.sll_family = AF_PACKET;
	recv_addr.sll_ifindex = if_nametoindex(interface->ifa_name);
	recv_addr.sll_protocol = ETH_P_ARP;

	socklen_t recv_addr_len = sizeof(recv_addr);
	char recv_buf[ETH_FRAME_LEN];
	int recv_len;

	while (1) {
		recv_len = recvfrom(sfd, recv_buf, ETH_FRAME_LEN, 0, (struct sockaddr *)&recv_addr, &recv_addr_len);
		if (recv_len == -1) {
			strerror(errno);
			return 1;
		}
		
		//check if the packet is an arp packet
		struct ether_header *eth_hdr = (struct ether_header *)recv_buf;
		struct ether_arp *arp_hdr = (struct ether_arp *)(recv_buf + sizeof(struct ether_header));

		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {

			//stock sender ip from arp packet
			char sender_ip[INET_ADDRSTRLEN];
			char target_ip[INET_ADDRSTRLEN];
			if (inet_ntop(AF_INET, arp_hdr->arp_spa, sender_ip, sizeof(sender_ip)) == NULL) {
				strerror(errno);
				return 1;
			}
			if (inet_ntop(AF_INET, arp_hdr->arp_tpa, target_ip, sizeof(target_ip)) == NULL) {
				strerror(errno);
				return 1;
			}

			//print header
			printf("Received ARP packet ! (%d bytes)\n", recv_len);

			if (strcmp(sender_ip, TARGET_IP_ADDRESS) == 0)// && strcmp(target_ip, SOURCE_IP_ADDRESS) == 0)
			{
				printf("Opcode: %d\n", ntohs(arp_hdr->ea_hdr.ar_op));
				printf("Sender MAC: %s\n", ether_ntoa((struct ether_addr *)arp_hdr->arp_sha));
				printf("Sender IP: %s\n", sender_ip);
				printf("Target MAC: %s\n", ether_ntoa((struct ether_addr *)arp_hdr->arp_tha));
				printf("Target IP: %s\n", target_ip);
				printf("\n");
			}
		}
		

			//check if the packet is an arp reply
			// struct ether_arp *arp_hdr = (struct ether_arp *)(recv_buf + sizeof(struct ether_header));
			// if (ntohs(arp_hdr->ea_hdr.ar_op) == ARPOP_REPLY) {
			// 	printf("Received ARP reply\n");

			// 	//check if the packet is for the target
			// 	struct in_addr target_addr;
			// 	if (inet_pton(AF_INET, TARGET_IP_ADDRESS, &target_addr) == 0) {
			// 		strerror(errno);
			// 		return 1;
			// 	}

			// 	if (memcmp(arp_hdr->arp_tpa, &target_addr, sizeof(target_addr)) == 0) {
			// 		printf("Received ARP reply for target\n");

			// 		//send arp reply to the sender
			// 		struct ether_arp *arp_hdr = (struct ether_arp *)(recv_buf + sizeof(struct ether_header));
			// 		struct ether_header *eth_hdr = (struct ether_header *)recv_buf;

			// 		//swap sender and target
			// 		memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETH_ALEN);
			// 		memcpy(eth_hdr->ether_shost, interface->ifa_addr->sa_data, ETH_ALEN);
			// 		memcpy(arp_hdr->arp_tha, arp_hdr->arp_sha, ETH_ALEN);
			// 		memcpy(arp_hdr->arp_sha, interface->ifa_addr->sa_data, ETH_ALEN);

			// 		//set target ip to sender ip
			// 		memcpy(arp_hdr->arp_tpa, arp_hdr->arp_spa, sizeof(arp_hdr->arp_tpa));

			// 		//set sender ip to target ip
			// 		memcpy(arp_hdr->arp_spa, &target_addr, sizeof(arp_hdr->arp_spa));

			// 		//set opcode to arp reply
			// 		arp_hdr->ea_hdr.ar_op = htons(ARPOP_REPLY);

			// 		//send packet
			// 		if (sendto(sfd, recv_buf, recv_len, 0, (struct sockaddr *)&recv_addr, sizeof(recv_addr)) == -1) {
			// 			strerror(errno);
			// 			return 1;
			// 		}
			// 		printf("Sent ARP reply\n");
			// 	}
			// }
		// }
	}

	close(sfd);
	freeifaddrs(ifaddr);

	return 0;
}
