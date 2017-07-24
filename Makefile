CC = gcc

pcap_test : pcap_test.c
	gcc -o pcap_test pcap_test.c -lpcap -w