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

// #define REQUESTED_IP_ADRESS "10.0.2.16"
// #define REQUESTED_MAC_ADDRESS "ff:ff:ff:ff:ff:ff"
// #define REQUESTER_IP_ADDRESS "10.0.2.15"
// #define REQUESTER_MAC_ADDRESS "02:42:ac:11:00:03"

#define REQUESTED_IP_ADDRESS "172.17.0.16"
#define REQUESTED_MAC_ADDRESS "02:42:ac:11:00:03"
#define REQUESTER_IP_ADDRESS "172.17.0.2"
#define REQUESTER_MAC_ADDRESS "02:42:ac:11:00:03"

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
			if (inet_pton(AF_INET, REQUESTER_IP_ADDRESS, &(target.sin_addr)) == 0) {
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
		printf("Received packet!\n");
		//check if the packet is an arp packet
		struct ether_header *eth_hdr = (struct ether_header *)recv_buf;
		struct ether_arp *arp_hdr = (struct ether_arp *)(recv_buf + sizeof(struct ether_header));

		//print mac addresses from ethernet header
		printf("\tSource MAC: %s\n", ether_ntoa((struct ether_addr *)eth_hdr->ether_shost));
		printf("\tTarget MAC: %s\n", ether_ntoa((struct ether_addr *)eth_hdr->ether_dhost));

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
			printf("\t\tIt's an ARP packet ! (%d bytes)\n", recv_len);
			printf("\t\tOpcode: %d\n", ntohs(arp_hdr->ea_hdr.ar_op));
			printf("\t\tSender MAC: %s\n", ether_ntoa((struct ether_addr *)arp_hdr->arp_sha));
			printf("\t\tSender IP: %s\n", sender_ip);
			printf("\t\tTarget MAC: %s\n", ether_ntoa((struct ether_addr *)arp_hdr->arp_tha));
			printf("\t\tTarget IP: %s\n", target_ip);
			printf("\n");
			if (strcmp(sender_ip, REQUESTER_IP_ADDRESS) == 0 && strcmp(target_ip, REQUESTED_IP_ADDRESS) == 0)
			{
				//send arp reply to sender ip, giving REQUESTED_MAC_ADDRESS as the mac address of the target ip
				struct ether_header eth_hdr;
				struct ether_arp arp_hdr;

				//fill ethernet header
				eth_hdr.ether_type = htons(ETHERTYPE_ARP);
				ether_aton_r(REQUESTED_MAC_ADDRESS, (struct ether_addr *)eth_hdr.ether_shost);
				ether_aton_r(REQUESTER_MAC_ADDRESS, (struct ether_addr *)eth_hdr.ether_dhost);

				//fill arp header
				arp_hdr.arp_hrd = htons(ARPHRD_ETHER);
				arp_hdr.arp_pro = htons(ETHERTYPE_IP);
				arp_hdr.arp_hln = ETHER_ADDR_LEN;
				arp_hdr.arp_pln = sizeof(in_addr_t);
				arp_hdr.arp_op = htons(ARPOP_REPLY);
				ether_aton_r(REQUESTED_MAC_ADDRESS, (struct ether_addr *)arp_hdr.arp_sha);
				inet_pton(AF_INET, REQUESTED_IP_ADDRESS, arp_hdr.arp_spa);
				ether_aton_r(REQUESTER_MAC_ADDRESS, (struct ether_addr *)arp_hdr.arp_tha);
				inet_pton(AF_INET, REQUESTER_IP_ADDRESS, arp_hdr.arp_tpa);

				//fill buffer
				char buf[ETHER_HDR_LEN + sizeof(struct ether_arp)];
				memcpy(buf, &eth_hdr, sizeof(struct ether_header));
				memcpy(buf + sizeof(struct ether_header), &arp_hdr, sizeof(struct ether_arp));

				//print packet
				printf("Sending packet:\n");
				printf("\tSource MAC: %s\n", ether_ntoa((struct ether_addr *)eth_hdr.ether_shost));
				printf("\tTarget MAC: %s\n", ether_ntoa((struct ether_addr *)eth_hdr.ether_dhost));
				printf("\t\tIt's an ARP packet ! (%ld bytes)\n", sizeof(buf));
				printf("\t\tOpcode: %d\n", ntohs(arp_hdr.arp_op));
				printf("\t\tSender MAC: %s\n", ether_ntoa((struct ether_addr *)arp_hdr.arp_sha));
				printf("\t\tSender IP: %s\n", inet_ntoa(*(struct in_addr *)arp_hdr.arp_spa));
				printf("\t\tTarget MAC: %s\n", ether_ntoa((struct ether_addr *)arp_hdr.arp_tha));
				printf("\t\tTarget IP: %s\n", inet_ntoa(*(struct in_addr *)arp_hdr.arp_tpa));
				printf("\n");

				//send packet
				if (sendto(sfd, buf, sizeof(buf), 0, (struct sockaddr *)&recv_addr, sizeof(recv_addr)) == -1) {
					strerror(errno);
					return 1;
				}
				printf("Sent packet!\n");
				break ;
			}
		}
	}

	close(sfd);
	freeifaddrs(ifaddr);

	return 0;
}
