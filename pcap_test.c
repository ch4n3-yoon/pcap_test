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

	short result = 0;

	// prevent windows os
	result += OSprevent(isWindows);

	// prevent common user's execute
	result += userPrevent();


	if(result > 0) {
		return 1;
	}	






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