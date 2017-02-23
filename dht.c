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


static struct storage* find_storage(const unsigned char* id); 
static void flush_search_node(struct search_node* n, struct search* sr); 

static int send_ping(const struct sockaddr* sa, int salen, 
					 const unsigned char* tid, int tid_len); 
static int send_pong(const struct sockaddr* sa, int salen, 
					 const unsigned char* tid, int tid_len); 
static int send_find_node(const struct sockaddr* sa, int salen, 
						  const unsigned char* tid, int tid_len, 
						  const unsigned char* target, int want, int confirm); 
static int send_nodes_peers(const struct sockaddr* sa, int salen, 
							const unsigned char* tid, int tid_len, 
							const unsigned char* nodes, int nodes_len, 
							const unsigned char* nodes6, int nodes6_len,
							int af, struct storage* st, 
							const unsigned char* token, int token_len); 
static int send_closest_nodes(const struct sockaddr* sa, int salen, 
							  const unsigned char* tid, int tid_len, 
							  const unsigned char* id, int want, 
							  int af, struct storage* st, 
							  const unsigned char* token, int token_len); 
static int send_get_peers(const struct sockaddr* sa, int salen, 
						  unsigned char* tid, int tid_len, 
						  unsigned char* infohash, int want, int confirm); 

static int send_peer_announcement(const struct sockaddr* sa, int salen, 
								  unsigned char* tid, int tid_len, 
								  unsigned char* infohas, unsigned short port,
								  unsigned char* token, int token_len, int confirm); 
static int send_peer_announced(struct sockaddr* sa, int salen, 
							   unsigned char* tid, int tid_len); 
static int send_error(const struct sockaddr* sa, int sa_len,
					  unsigned char* tid, int tid_len, 
					  int code, const char* message); 

#define ERROR 0	
#define REPLY 1 
#define PING 2
#define FIND_NODE 3 
#define GET_PEERS 4 
#define ANNOUNCE_PEER 5 

#define WANT 1 
#define WANT6 2 

static int parse_message(const unsigned char* buf, int buflen, 
						 unsigned char* tid, int* tid_len, 
						 unsigned char* id_return, 
						 unsigned char* info_hash_return, 
						 unsigned char* target_return, 
						 unsigned short* port_return, 
						 unsigned char* token_return, int* token_len, 
						 unsigned char* nodes_return, int* nodes_len, 
						 unsigned char* nodes6_return, int* nodes6_len, 
						 unsigned char* values_return, int* values_len, 
						 unsigned char* values6_return, int* values6_len,
						 int* want_return); 

static const unsigned char zeros[20] = {0}; 
static const unsigned char ones[20] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF
};

static const unsigned char v4prefix[16] = {
	    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0
};


static int dht_socket = -1; 
static int dht_socket6 = -1; 

static time_t search_time; 
static time_t confirm_nodes_time; 
static time_t rotate_secrets_time; 

static unsigned char myid[20]; 
static int have_v = 0; 
static unsigned char my_v[9]; 
static unsigned char secret[8]; 
static unsigned char oldsecret[8]; 

static struct bucket* buckets = NULL; 
static struct bucket* buckets6 = NULL; 
static struct storage* storage; 
static int numstorage; 

static struct search* searches = NULL; 
static int numsearches; 
static unsigned short search_id; 

/* The maximum number of nodes that we snub. There is probably little 
 * reason to increase this value */ 
#ifndef DHT_MAX_BLACKLISTED 
	#define DHT_MAX_BLACKLISTED 10
#endif 
static struct sockaddr_storage blacklist[DHT_MAX_BLACKLISTED]; 
int next_blacklisted; 

static struct timeval now; 
static time_t mybucket_grow_time, mybucket6_grow_time; 
static time_t expire_stuff_time; 

#define MAX_TOKEN_BUCKET_TOKENS	400 
static time_t token_bucket_time; 
static int token_bucket_tokens; 

FILE* dht_debug = NULL; 


#ifdef __GNUC__
	__attribute__ ((format(printf, 1, 2)))
#endif 

static void
debugf(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if(dht_debug)
        vfprintf(dht_debug, format, args);
    va_end(args);
    if(dht_debug)
        fflush(dht_debug);
}

static void 
debug_printable(const unsigned char* buf, int buflen) {
	int i; 
	if(dht_debug) {
		for(i = 0; i < buflen; ++i) {
			putc(buf[i] >= 32 && buf[i] <= 126 ? buf[i] : '.', dht_debug) ;
		}
	}
}
	

static void 
print_hex(FILE* f, const unsigned char* buf, int buflen) {
	int i; 
	for(i = 0; i < buflen; ++i) {
		fprintf(f, "%02x", buf[i]); 
	}
}


static int 
is_martian(const struct sockaddr* sa) {
	switch(sa->sa_family) {
		case AF_INET: {
			struct sockaddr_in* sin = (struct sockaddr_in*) sa; 
			const unsigned char* address = (const unsigned char*) &sin->sin_addr;
			return sin->sin_port == 0 || 
					(address[0] == 0) || 
					(address[0] == 127) || 
					((address[0] & 0xE0) == 0xE0);
		}

		case AF_INET6:  {
			struct sockaddr_in6* sin6 = (struct sockaddr_in6*) sa; 
			const unsigned char* address = (const unsigned char*) &sin6->sin6_addr; 
			return sin6->sin6_port == 0 ||
            (address[0] == 0xFF) ||
            (address[0] == 0xFE && (address[1] & 0xC0) == 0x80) ||
            (memcmp(address, zeros, 15) == 0 &&
             (address[15] == 0 || address[15] == 1)) ||
            (memcmp(address, v4prefix, 12) == 0);
			
		} 

		default: 
		return 0;
	}
}

/* Forget about the ``XOR-metric''.  An id is just a path from the
   root of the tree, so bits are numbered from the start. */

static int
id_cmp(const unsigned char *restrict id1, const unsigned char *restrict id2)
{
    /* Memcmp is guaranteed to perform an unsigned comparison. */
    return memcmp(id1, id2, 20);
}

/* Find the lowest 1 bit in an id. */
static int
lowbit(const unsigned char *id)
{
    int i, j;
    for(i = 19; i >= 0; i--)
        if(id[i] != 0)
            break;

    if(i < 0)
        return -1;

    for(j = 7; j >= 0; j--)
        if((id[i] & (0x80 >> j)) != 0)
            break;

    return 8 * i + j;
}

/* Find how many bits two ids have in common. */
static int
common_bits(const unsigned char *id1, const unsigned char *id2)
{
    int i, j;
    unsigned char xor;
    for(i = 0; i < 20; i++) {
        if(id1[i] != id2[i])
            break;
    }

    if(i == 20)
        return 160;

    xor = id1[i] ^ id2[i];

    j = 0;
    while((xor & 0x80) == 0) {
        xor <<= 1;
        j++;
    }

    return 8 * i + j;
}

/* Determine whether id1 or id2 is closer to ref */
static int
xorcmp(const unsigned char *id1, const unsigned char *id2,
       const unsigned char *ref)
{
    int i;
    for(i = 0; i < 20; i++) {
        unsigned char xor1, xor2;
        if(id1[i] == id2[i])
            continue;
        xor1 = id1[i] ^ ref[i];
        xor2 = id2[i] ^ ref[i];
        if(xor1 < xor2)
            return -1;
        else
            return 1;
    }
    return 0;
}


/* We keep buckets in sorted list list. A bucket b ranges from 
 b->first inclusive up to b->next->first exclusive */ 
static int
in_bucket(const unsigned char *id, struct bucket *b)
{
    return id_cmp(b->first, id) <= 0 &&
        (b->next == NULL || id_cmp(id, b->next->first) < 0);
}	


static struct bucket* 
find_bucket(unsigned const char* id, int af) {
	struct bucket* b = af == AF_INET ? buckets : buckets6;

	if(b == NULL) 
		return NULL; 

	while(1) {
		if(b->next == NULL) 
			return b; 
		if(id_cmp(id, b->next->first) < 0) 
			return b; 
		b = b->next; 
	}
}



static struct bucket* 
previous_bucket(struct bucket* b) {
	struct bucket* p = b->af == AF_INET ? buckets : buckets6; 

	if(b == p) return NULL; 
	while(1) {
		if(p->next == NULL) return NULL; 
		if(p->next == b) return p; 
		p = p->next; 
	}
}

/* Every bucket contains an unordered list of nodes */ 
static struct node* 
find_node(const unsigned char* id, int af) {
	struct bucket* b = find_bucket(id, af); 
	struct node* n; 
	if(b == NULL) 
		return NULL; 

	n = b->nodes; 
	while(n) {
		if(id_cmp(n->id, id) == 0) 
			return n; 
		n = n->next; 
	} 

	return NULL; 
}

/* Returns a random node in a bucket */ 
static struct node* 
random_node(struct bucket* b) {
	struct node* n; 
	int nn; 

	if(b->count == 0) return NULL; 

	nn = random() % b->count; 
	n = b->nodes; 

	while(nn > 0 && n) {
		n = n->next; 
		nn--; 
	} 

	return n; 
}

/* Returns the middle id of bucket */ 
static int 
bucket_middle(struct bucket* b, unsigned char* id_return) {
	int bit1 = lowbit(b->first); 
	int bit2 = b->next  ? lowbit(b->next->first) : -1; 

	if(bit >= 160) 
		return -1; 

	memcpy(id_return, b->first, 20); 
	id_return[bit/8] = (0x80 >> (bit % 8)); 

	return 1; 
}

/* Returns a random id within a bucket */ 
static int 
bucket_random(struct bucket* b, unsigned char* id_return) {
	int bit1 = lowbit(b->first); 
	int bit2 = b->next ? lowbit(b->next->first0) : -1; 
	int bit = MAX(bit1, bit2) + 1; 
	int i; 

	if(bit >= 160) {
		memcpy(id_return, b->first, 20); 
		return 1; 
	} 

	memcpy(id_return, b->first, bit / 8); 
	id_return[bit/8] = b->first[bit/8] & (0xFF00 >> (bit % 8)); 
	id_return[bit/8] |= random() & 0xFF >> (bit % 8); 
	for(i = bit / 8 + 1; i < 20; ++i) {
		id_return[i] = random() & 0xFF; 
	} 

	return 1; 
}

/* INsert a new node into a bucket */ 
static struct node* 
insert_node(struct node* node) {
	struct bucket* b = find_bucket(node->id, node->ss.ss_family); 

	if(b == NULL) 
		return NULL; 

	node->next = b->nodes; 
	b->nodes = node; 
	b->count++; 

	return node; 
}

/* This is our definition of a known-good node */ 
static int 
node_good(struct node* node) {
	return node->pinged <= 2 && 
		node->reply_time >= now.tv_sec -7200 && 
		node->time >= now.tv_sec - 900; 
}

/* Our transaction-ids are 4-bytes long, with the first two bites 
 * identifying the kind of request, and the remaining tow a sequence number 
 * in host order */ 
static void 
make_tid(unsigned char* tid_return, const char* prefix, unsigned short seqno) {
	tid_return[0] = prefix[0] & 0xFF; 
	tid_return[1] = prefix[1] & 0xFF; 
	memcpy(tid_return + 2, &seqno, 2); 
}

static int 
tid_match(const unsigned char* tid, const char* prefix, 
		  unsigned short* seqno_return) {
	if(tid[0] == (prefix[0] & 0xFF) && tid[1] == (prefix[1]&0xFF)) {
		if(seqno_return)
			memcpy(seqno_return, tid + 2, 2); 
		return 1; 
	} else
		return 0;
}

/* Every bucket caches the address of likely node. Ping it */ 
static int 
send_cached_ping(struct bucket* b) {
	unsigned char tid[4]; 
	int rc; 
	/* We set familiy to 0 when there's no cached node */ 
	if(b->cached.ss_family == 0) 
		return 0; 

	debugf("Sending ping to cached node\n"); 
	make_tid(tid, "pn",0); 
	rc = send_ping((struct sockaddr*)&b->cached, b->cachedlen, tid, 4); 
	b->cached.ss_family = 0; 
	b->cachedlen = 0; 
	return rc; 
}

/* Called whenever we send a request to a node, increases the ping count 
 * and, if tha reaches 3, send a ping to a new candiadate */ 
static void 
ping(struct node* n, struct bucket* b) {
	n->pinged++; 
	n->pinged_time = now.tv_sec; 
	if(n->pinged >= 3) 
		send_cached_ping(b ? b : find_bucket(n->id, n->ss.ss_family)); 
}


/* The internal blacklist is a LRU cache of nodes that have sent 
 * incorrect messages */ 
static void 
blacklist_node(const unsigned char* id, const struct sockaddr* sa, int salen) {
	int i; 

	debugf("Blacklist broken node \n"); 

	if(id) {
		struct node* n; 
		struct search* sr; 
		/* Make the node easy to discard */ 
		n =find_node(id, sa->sa_family); 
		if(n) {
			n->pinged = 3; 
			pinged(n, NULL); 
		}

		/* discard it from search in progress */ 
		sr = searches; 
		while(sr) {
			for(i = 0; i < sr->numnodes; ++i) {
				if(id_cmp(sr->nodes[i].id, id) == 0) 
					flush_search_node(&sr->nodes[i], sr); 
			}
			sr = sr->next; 
		}
	}
	/* And make sure we dont' hear from it again */ 
	memcpy(&blacklist[next_blacklisted], sa, salen); 
	next_blacklisted = (next_blacklisted + 1) % DHT_MAX_BLACKLISTED; 
}

static int 
node_blacklisted(const struct sockaddr* sa, int salen) {
	int i; 

	if((unsigned) salen > sizeof(struct sockaddr_storage)) 
		abort(); 

	if(dht_blacklisted(sa, salen)) 
		return 1; 

	for(i = 0; i < DHT_MAX_BLACKLISTED; ++i) {
		if(memcmp(&blacklisted[i], sa, salen) == 0) 
			return 1; 
	}

	return 0; 
}

