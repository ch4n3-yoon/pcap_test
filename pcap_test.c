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


int main(int argc, char * argv[]) {


	pcap_t *handle;				/* Session handle */
	char * dev, errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;			/* The compiled filter expression */
	char filter_exp[] = "port 80";		/* The filter expression */
	bpf_u_int32 mask;			/* The netmask of our sniffing device */
	bpf_u_int32 net;			/* The IP of our sniffing device */
	const u_char *packet;		// The actual packet
	struct pcap_pkthdr header;	// The header that pcap gi





	short result = 0;

	// prevent windows os
	result += OSprevent(isWindows);

	// prevent common user's execute
	result += userPrevent();

	if(result > 0) {
		return 1;
	}


	

	dev = pcap_lookupdev(errbuf);
	if(dev == NULL) {
		fprintf(stderr, "Couldn't find device: %s\n", errbuf);
		return 1;
	}

	printf("[*] Your network device : %s\n", dev);
	
	
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return 1;
	}

	// Compile and apply the filter 
	if( pcap_compile(handle, &fp, filter_exp, 0, net) == -1 ) {
		fprintf(stderr, "Couldn't parse filter %s: %s", filter_exp, pcap_geterr(handle));
		return 1;
	}
	if( pcap_setfilter(handle, &fp) == -1 ) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return 1;
	}

	int i = 0;
	while(1) {
		// Grab a packet
		packet = pcap_next(handle, &header);

		// print the length of packet
		printf("[%d] Jacked a packet with length of [%d]\n", i++, header.len);
	}

	pcap_close(handle);

	return 0;
	

}




/***********************************************************************/




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
