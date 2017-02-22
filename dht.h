#ifdef __cplusplus
extern "C" {
#endif


typedef void dht_callback(void* closure, int event, 
						  const unsigned char* info_hash, 
						  const void* data, size_t data_len);


#define DHT_EVENT_NONE 0
#define DHT_EVENT_VALUES 1
#define DHT_EVENT_VALUES6 2 
#define DHT_EVENT_SEARCH_DONE 3 
#define DHT_EVENT_SEARCH_DONE6 4 

extern FILE* dht_debug; 

int dht_init(int s, int s6, const unsigned char* id, const unsigned char* v); 
int dht_insert_node(const unsigned char* id, struct sockaddr* sa, int salen); 
int dht_ping_node(const struct sockaddr* sa, int salen); 
int dht_periodic(const void* buf, size_t buflen,
				 const struct sockaddr* from,int fromlen); 

int dht_search(const unsigned char* id, int port, int af, 
			   dht_callback* callback, void* closure); 

int dht_nodes(int af, int* good_return, int* dubious_return, int* cached_return, int* incoming_return); 

void dht_dump_table(FILE* f); 
int dht_get_nodes(struct sockaddr_in* sin, int* num, 
				  struct sockaddr_in6* sin6, int* num6); 

int dht_uninit(void);

/* This must be provided by the user */ 
int dht_blacklisted(const struct sockaddr* sa, int salen); 
void dht_hash(void* hash_return, int hash_size, 
			  const void* v1, int len1, 
			  const void* v2, int len2, 
			  const void* v3, int len3); 

int dht_random_bytes(void* buf, size_t size); 




#ifdef __cplusplus 
}
#endif


