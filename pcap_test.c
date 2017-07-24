#include <stdio.h>
#include <pcap.h>
#include <pwd.h>	// configure user's id.
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>


#ifdef _WIN32
	#define isWindows 1
#elif __linux__
	#define isWindows 0
#endif


#define SIZE_ETHERNET 14



#define IP_RF	0x8000;
#define IP_DF	0x4000;
#define IP_MF	0x2000;


int OSprevent(int OSconf);
int userPrevent(void);


#define ETHER_ADDR_LEN	6

/* Ethernet Header */
struct sniff_ethernet
{
	u_char 	ether_dhost[ETHER_ADDR_LEN];	/* Destination host mac address */
	u_char 	ether_shost[ETHER_ADDR_LEN];	/* Source host mac address */
	u_short	ether_type;				/* IP or ARP or RARP or etc. */
};



#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) 		(((ip)->ip_vhl) >> 4)

struct sniff_ip 
{
	u_char	ip_vhl;		/* version << 4 | header length >> 2 */
	u_char	ip_tos;		/* type of serice */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short	ip_off;		/* fragment offset field */

	u_char	ip_ttl;		/* time to live */
	u_char	ip_p;		/* protocol */ 
	u_short	ip_sum;		/* checksum */
	struct in_addr	ip_src, ip_dst;		/* source and dest ip address */
};



/* TCP Header */
typedef u_int tcp_seq;

struct sniff_tcp 
{
	u_short th_sport;		/* soure port */
	u_short th_dport;		/* destination port */
	tcp_seq	th_seq;			/* sequence number */
	tcp_seq	th_ack;			/* acknowledgement number */
	u_char 	th_offx2;		/* data offset, rsvd */

	u_char th_flags;		/* like fin, syn, rst.. */
#define TH_FIN	0x01
#define TH_SYN 	0x02
#define TH_RST 	0x04
#define TH_PUSH 0x08
#define TH_ACK 	0x10
#define TH_URG 	0x20
#define TH_ECE	0x40
#define TH_CWR 	0x80
#define TH_FLAGS 	(TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)

	u_short	th_win; 		/* window */
	u_short th_sum;			/* check sum */
	u_short th_urp;			/* urgent pointer */


};


#define TH_OFF(th)		(((th)->th_offx2 & 0xf0) >> 4)


int main(int argc, char * argv[]) 
{


	pcap_t *handle;				/* Session handle */
	char * device;
	char * error_buffer[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;			/* The compiled filter expression */
	char filter_exp[] = "port 80";		/* The filter expression */
	bpf_u_int32 mask;			/* The netmask of our sniffing device */
	bpf_u_int32 net;			/* The IP of our sniffing device */
	const u_char *packet;		// The actual packet
	struct pcap_pkthdr header;	// The header that pcap gi

	unsigned char ip_addr[4];

	int i = 0;					/* the valuable for counting for loop */
	short result = 0;			/* variable for storing some return values */



	const struct sniff_ethernet *ethernet;	/* The ethernet header */
	const struct sniff_ip		*ip;		/* The IP header */
	const struct sniff_tcp 		*tcp;		/* The TCP header */



	const char * payload;		/* Packet payload */




	u_int size_ip;
	u_int size_tcp;





	// prevent windows os
	result += OSprevent(isWindows);
	// prevent common user's execute
	result += userPrevent();


	if(result > 0) 
	{
		return 1;
	}


	

	// configure the network device name
	device = pcap_lookupdev(error_buffer);

	if(device == NULL) 
	{
		printf("[-] Error : $s\n", error_buffer);
		return 1;
	}

	// print my network device
	printf("[*] Your network device : %s\n", device);
	


	


	// set handle for pcap
	// BUFSIZ is defined in pcap.h

	/*
		pcap_t *pcap_open_live(const char *device, int snaplen,
                int promisc, int to_ms, char *errbuf);
	*/

	handle = pcap_open_live(device, BUFSIZ, 1, 1000, error_buffer);

	if(handle == NULL) 
	{
		printf("[-] Error %s (device : %s)\n", error_buffer, device);
		return 1;
	}







	// Compile and apply the filter 

	/*
       int pcap_compile(pcap_t *p, struct bpf_program *fp,
               const char *str, int optimize, bpf_u_int32 netmask);
	*/

	result = pcap_compile(handle, &fp, filter_exp, 0, net);
	if( result == -1 ) 
	{
		printf("[-] Filter Error (your filter = %s) : %s\n", filter_exp, pcap_geterr(handle));
		return 1;
	}

	/*
		int pcap_setfilter(pcap_t *p, struct bpf_program *fp);
	*/

	// pcap_setfilter() returns 0 on success and -1 on failure.
	result = pcap_setfilter(handle, &fp);
	
	if( result == -1 ) 				// This code means pcap_setfilter() returns false.
	{
		printf("[-] Filter Error (your fileter = %s) : %s\n", filter_exp, pcap_geterr(handle));
		return 1;
	}



	for(i = 0; i < 10; i++)
	{
		// grab a packet
		packet = pcap_next(handle, &header);

		// analyse packet with ethernet header
		ethernet 	= (struct sniff_ethernet *)(packet);

		// SIZE_ETHERNET == 14
		ip 			= (struct sniff_ip *)(packet + SIZE_ETHERNET);


		// store the length of the ip packet
		// size_ip 	= (ip->ip_vhl) & 0x0F;
		size_ip 	= IP_HL(ip) * 4;


		if(size_ip < 20) 
		{
			printf("[-] Invalid IP header length : %u bytes\n", size_ip);
			break;
			// return 1;
		}
		

		tcp 		= (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
		size_tcp 	= TH_OFF(tcp) * 4;

		// printf("[*][%d] the ip packet size : %d\n", i, size_ip);

		if(size_tcp < 20)
		{
			printf("[-] Invalid TCP header length : %u bytes\n", size_tcp);
			break;
			// return 1;
		}



		// the content of the http packet
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);






		/* <Mac Address> */


		printf("[*] Source\tMAC :\t");


		/* print the destination mac address */
		for(i=0; i < ETHER_ADDR_LEN; i++) 
		{
			printf("%02x:", ethernet->ether_shost[i]);
		}

		printf("\b \n");


		printf("[*] Destination\tMAC :\t");


		/* print the source mac address */
		for(i = 0; i < ETHER_ADDR_LEN; i++) {
			printf("%02x:", ethernet->ether_dhost[i]);
		}
		printf("\b \n\n");


		/* </Mac Address> */


		if(ntohs(ethernet->ether_type) == ETHERTYPE_IP)
		{

			char ip_str[INET_ADDRSTRLEN];

			printf("[*] The Ethertype Type is IPv4\n");



			/* print the source ip address */
			printf("[*] Source\tIP : \t");
			printf("%s\n", inet_ntop(AF_INET, &(ip->ip_src), ip_str, INET_ADDRSTRLEN));



			/* print the destination ip address */
			printf("[*] Destination\tIP : \t");
			printf("%s\n", inet_ntop(AF_INET, &(ip->ip_dst), ip_str, INET_ADDRSTRLEN));
			
			

		}


		else 
		{
			printf("[-] That Ethernet Type is not supported. sorry T.T (Your Ether Type : 0x%04x) \n", ntohs(ethernet->ether_type));
		}




		printf("[*] Source\tTCP port :\t");
		printf("%d\n", ntohs(tcp->th_sport) );

		printf("[*] Destination\tTCP prot :\t");
		printf("%d\n", ntohs(tcp->th_dport) );






		printf("\n[*] Grabbed packet data : \n");
		printf("========================================\n");
		printf("%s\n", payload);
		printf("========================================\n");

		printf("\n\n\n\n\n");


	}





	// close the grabbing a packet

	/*
		void pcap_close(pcap_t *p);
	*/	

	pcap_close(handle);

	return 0;
	

}














/* functions */



int OSprevent(int OSconf) 
{
	if(OSconf) 
	{
		printf("[*] This program doesn't support your OS.\n");
		return 1;
	}

	return 0;
}



int userPrevent(void) 
{
	struct passwd * userPw;
	userPw = getpwuid( getuid() );	
	
	if(userPw->pw_uid != 0) 
	{
		printf("[*] If you want to execute this file, you must be a root.\n");
		return 1;
	}
}
