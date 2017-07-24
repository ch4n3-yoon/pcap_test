#include <stdio.h>
#include <pcap.h>
#include <pwd.h>	// configure user's id.
#include <netinet/in.h>


#ifdef _WIN32
	#define isWindows 1
#elif __linux__
	#define isWindows 0
#endif


#define SIZE_ETHERNET 14
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) 		(((ip)->ip_vhl) >> 4)


#define IP_RF	0x8000;
#define IP_DF	0x4000;
#define IP_MF	0x2000;


int OSprevent(int OSconf);
int userPrevent(void);



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


int main(int argc, char * argv[]) 
{


	pcap_t *handle;				/* Session handle */
	char * device, errbuf[PCAP_ERRBUF_SIZE];
	char * error_buffer[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;			/* The compiled filter expression */
	char filter_exp[] = "port 80";		/* The filter expression */
	bpf_u_int32 mask;			/* The netmask of our sniffing device */
	bpf_u_int32 net;			/* The IP of our sniffing device */
	const u_char *packet;		// The actual packet
	struct pcap_pkthdr header;	// The header that pcap gi


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

		size_ip 	= IP_HL(ip) * 4;

		// size_ip 	= (ip->ip_vhl) & 0x0F;

		printf("[*][%d] the ip packet size : %d\n", i, size_ip);


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
