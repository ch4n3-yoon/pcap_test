#include <stdio.h>
#include <pcap.h>
#include <pwd.h>	// configure user's id.


#ifdef _WIN32
	#define isWindows 1
#elif __linux__
	#define isWindows 0
#endif


int OSprevent(int OSconf);
int userPrevent(void);



struct ethernet_header 
{
	char preamble[7];
	char sfd;


};


int main(int argc, char * argv[]) {


	pcap_t *handle;				/* Session handle */
	char * device, errbuf[PCAP_ERRBUF_SIZE];
	char * error_buffer[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;			/* The compiled filter expression */
	char filter_exp[] = "port 80";		/* The filter expression */
	bpf_u_int32 mask;			/* The netmask of our sniffing device */
	bpf_u_int32 net;			/* The IP of our sniffing device */
	const u_char *packet;		// The actual packet
	struct pcap_pkthdr header;	// The header that pcap gi


	int i = 0;					// the valuable for counting while loop





	short result = 0;

	// prevent windows os
	result += OSprevent(isWindows);
	// prevent common user's execute
	result += userPrevent();


	if(result > 0) {
		return 1;
	}


	

	// configure the network device name
	device = pcap_lookupdev(error_buffer);
	if(dev == NULL) {
		printf("[-] Error : $s\n", error_buffer);
		return 1;
	}

	// print my network device
	printf("[*] Your network device : %s\n", dev);
	


	


	// set handle for pcap
	// BUFSIZ is defined in pcap.h

	/*
		pcap_t *pcap_open_live(const char *device, int snaplen,
                int promisc, int to_ms, char *errbuf);
	*/

	handle = pcap_open_live(device, BUFSIZ, 1, 1000, error_buffer);
	if(handle == NULL) {
		pritnf("[-] Error %s (device : %s)\n", error_buffer, device);
		return 1;
	}







	// Compile and apply the filter 

	/*
       int pcap_compile(pcap_t *p, struct bpf_program *fp,
               const char *str, int optimize, bpf_u_int32 netmask);
	*/
	if( pcap_compile(handle, &fp, filter_exp, 0, net) == -1 ) {
		fprintf(stderr, "Couldn't parse filter %s: %s", filter_exp, pcap_geterr(handle));
		return 1;
	}
	if( pcap_setfilter(handle, &fp) == -1 ) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return 1;
	}




	while(1) {
		// Grab a packet
		packet = pcap_next(handle, &header);

		// print the length of packet
		printf("[%d] Jacked a packet with length of [%d]\n", i++, header.len);
	}

	pcap_close(handle);

	return 0;
	

}




/* functions */



int OSprevent(int OSconf) {
	if(OSconf) {
		printf("[*] This program doesn't support your OS.\n");
		return 1;
	}

	return 0;
}



int userPrevent(void) {
	struct passwd * userPw;
	userPw = getpwuid( getuid() );	
	
	if(userPw->pw_uid != 0) {
		printf("[*] If you want to execute this file, you must be a root.\n");
		return 1;
	}
}
