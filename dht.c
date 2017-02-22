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


#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
/* nothing */ 
#elif defined(__GNUC__)
	#define inline __inlin
	#if (__GNUC__ >= 3) 
		#define restrict __restrict
	#else 
		#define restrict /**/ 
 	#endif 
#else 
	#define inline /**/ 
	#define restrict /**/ 
#endif 


#define MAX(x, y) ((x) >= (y) ? (x) : (y)) 
#define MIN(x,y) ((x) <= (y)  ? (x) : (y)) 

struct node {
	unsigned char id[2]; 
	struct sockaddr_storage ss; 
	int sslen; 
	time_t time; /* time of last message recieved */ 
	time_t reply_time; /* time of last correct reply received */ 
	time_t pinged_time; /* time of last request */ 
	int pinged; /* how 	many request we sent since last reply */ 
	struct node* next; 
};  


struct bucket {
	int af; 
	unsigned char first[20]; 
	int count; /* number of nodes */ 
	time_t time; /* time of last reply in this bucket */ 
	struct node* nodes;  
	struct sockaddr_storage cached; /* the address of a likely candidate */ 
	int cachedlen; 
	struct bucket* next; 
};  

struct search_node {
	unsigned char id[20]; 
	struct sockaddr_storage ss; 
	int sslen; 
	time_t request_time;  /* the time of the last unaswered request */ 
	time_t reply_time;  /* the time of the lat reply */ 
	int pinged; 
	unsigned char token[40]; 
	int token_len; 
	int replied;  /* whether we have received a reply */ 
	int asked;  /* whether they asked our announcement */ 
};   
 

/* When performing a search, we search for up to SEARCH_NODES closest nodes 
	to the destination, and use the additional ones to backtrack if any of 
	the target 8 turn out to be dead */ 

#define SEARCH_NODES 14

struct search {
	unsigned short tid; 
	int af; 
	time_t step_time; /* the time of the last search_step */ 
	unsigned char 	id[20]; 
	unsigned short port; /* 0 for pure searches */ 
	int done; 
	struct search_node nodes[SEARCH_NODES]; 
	int numnodes; 
	struct search* next; 
};

struct peer {
	time_t time; 
	unsigned char ip[16]; 
	unsigned short len; 
	unsigned short port; 
}; 

/* The maximum number of peers we store for a given hash */ 
#ifdef DHT_MAX_PEERS 
	#define DHT_MAX_PEERS 2048 
#endif 

/* The maximum number of hashes we are willing to track */ 
#ifndef DHT_MAX_HASHES
	#define DHT_MAX_HASHES 16384 
#endif 

/* The maximum number of seaches we keep data about */ 
#ifdef DHT_MAX_SEARCHES
	#define DHT_MAX_SEARCHES 1024 
#endif 

/* The time after which we consider a search to be expireble */ 
#ifdef DHT_SEARCH_EXPIRE_TIME
	#define DHT_SEARCH_EXPIRE_TIME	(62 * 60) 
#endif 

struct storage {
	unsigned char id[20]; 
	int numpeers, maxpeers; 
	struct peer* peers; 
	struct storage* next; 
}; 


