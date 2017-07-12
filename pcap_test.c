#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>

#ifdef _WIN32
	#define isWindows 1
#elif __linux__
	#define isWindows 0
#endif

int main(int argc, char * argv[]) {


	// prevent windows os
	if(isWindows) {
		printf("[*] This program doesn't support your OS.\n");
		exit(-1);
	} 




}