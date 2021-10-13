#ifndef _CACHE_
#define _CACHE_
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "log.h"
#include "parse.h"

#define MAX_CACHE 5

// Struct to stores info of cache response
typedef struct cache {
  char *message;
  unsigned char ID[ID_LEN];
  unsigned char message_size[PREFIX_SIZE];
  char domain_name[DOMAIN_NAME_LEN];
  time_t t;
  unsigned char TTL[TTL_LEN];
  char RDDATA[RDDATA_LEN];
  bool expired;
  char expire_time[TIME_SIZE];
} Cache;

// initialize Cache
void initCache(Cache *cache);
// Add a response into cache list neither replace or new one
void addToCache(Dns_Response *dns_response, Cache *cache);
// cache a given response
void cacheResponse(FILE *logFIle, Dns_Response *dns_response, Cache *cache);
// check if there are any cache in cache list is expire or not
void updateCaches(Cache *cache);
// Check if there are a valid IP cache in cache list by given domain name
int checkValidCache(Dns_Packet *dns_packet, Cache *cache);

#endif