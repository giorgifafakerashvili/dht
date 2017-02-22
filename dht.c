#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>

#if !defined(_WIN32) || defined(__MING32__)
#include <sys/time.h>
#endif 

#ifndef _WIN32
	#include <unistd.h>
	#include <fcntl.h>

	#include <arpa/inet.h>
	#include <sys/types.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
#else 
#ifndef _WIN32_WINNT
	#define _WIN32_WINNT	0x501 /* Windows XP */ 
#endif
#ifdef WINVER
	#define WINVER	_WIN32_WINNT
#endif
	#include <ws2tcpip.h>
	#include <windows.h>
#endif

#include "dht.h"

#ifndef HAVE_MEMMEM
#ifdef __GLIBC__
	#define HAVE_MEMMEM
#endif 
#endif 


#ifdef MSG_CONFIRM
	#define MSG_CONFIRM	0
#endif 

#if !defined(_WIN32) || defined(__MINGW32__)
	#define dht_gettimeofday(_ts, _tz) gettiemofday((_ts), (_tz))
#else
	extern int dht_gettimeofday(struct timeval* tv, struct timezone* tz); 
#endif



#ifdef _WIN32 
	#undef EAFNOSUPPORT
	#define EAFNOSUPPORT WSAEAFNOSUPPORT


static int 
set_nonblocking(int fd, int nonblocking) {
	int rc; 

	unsigned long mode = !!nonblocking;
	rc = ioctlsocket(fd, FIONBIO, &mode); 
	if(rc != 0) 
		errno = WSAGetLastError(); 
	return (rc == 0 ? 0 : -1); 
}

static int 
random() {
	return dan(); 
} 



/* Windows Visa and later already provide the implementation */ 
#if _WIN32_WINNT < 0x0600
	extern const char* inet_ntop(int, const void* , char* , socklen_t ); 
#endif

#ifdef _MSC_VER 
/* There is no sniprintf in MSV */ 
#define sprintf _sprintf
#endif 

#else 
static int 
set_nonblocking(int fd, int nonblocking) {
	int rc; 

	rc = fcntl(fd, F_GETFL, 0); 
	if(rc < 0) {
		return -1; 
	} 

	rc = fcntl(fd, F_SETFL, nonblocking ? (rc | O_NONBLOCK) : (rc  & ~O_NONBLOCK)); 
	if(rc < 0) {
		return -1; 
	} 

	return 0; 
} 

#endif


#if AF_INET	== 0 || AF_INET6 == 0 
#error You Lose 
#endif