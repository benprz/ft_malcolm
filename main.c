#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>

#define TARGET_ADDRESS "192.168.1.2"

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
			if (inet_pton(AF_INET, TARGET_ADDRESS, &(target.sin_addr)) == 0) {
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
	int sfd = socket(AF_, SOCK_RAW, htons(ETHERTYPE_ARP));
	if (sfd == -1) {
		strerror(errno);
		return 1;
	}

	//set interface index
	unsigned int ifindex = if_nametoindex(interface->ifa_name);
	socklen_t ifindex_len = sizeof(ifindex);
	printf("Interface index: %d\n", ifindex);

	//bind socket to interface
	if (setsockopt(sfd, SOL_SOCKET, IP_BOUND_IF, &ifindex, ifindex_len) == -1) {
		strerror(errno);
		return 1;
	}

	//verify interface binding
	if (getsockopt(sfd, SOL_SOCKET, IP_BOUND_IF, &ifindex, &ifindex_len) == -1) {
		strerror(errno);
		return 1;
	}
	//print interface name
	char ifname[IF_NAMESIZE];
	if (if_indextoname(ifindex, ifname) == NULL) {
		strerror(errno);
		return 1;
	}
	printf("Interface name: %s\n", ifname);

	// struct sockaddr_in localAddress;
	// memset(&localAddress, 0, sizeof(localAddress));
	// localAddress.sin_family = AF_INET;
	// localAddress.sin_addr.s_addr = INADDR_ANY; // Receive on any local interface
	// localAddress.sin_port = htons(12345);

	// if (bind(sfd, (struct sockaddr*)&localAddress, sizeof(localAddress)) == -1) {
	// 	strerror(errno);
	// 	return 1;
	// }

	// //recvfrom broadcast address
	// char buffer[1024];
	// struct sockaddr_in *fromAddress = (struct sockaddr_in *)interface->ifa_dstaddr;
	// socklen_t fromAddressSize = sizeof(*fromAddress);
	// if (recvfrom(sfd, buffer, sizeof(buffer), 0, (struct sockaddr*)fromAddress, &fromAddressSize) == -1) {
	// 	strerror(errno);
	// 	return 1;
	// }


	close(sfd);
	freeifaddrs(ifaddr);

	return 0;
}
