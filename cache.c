#include "cache.h"

void initCache(Cache *cache) {
  for (int i = 0; i < MAX_CACHE; i++) {
    cache[i].message = NULL;
  }
}

void addToCache(Dns_Response *dns_response, Cache *cache) {
  int size = (((int)dns_response->message_size[0]) << 8) |
             (dns_response->message_size[1]);

  strncpy(cache->domain_name, dns_response->domain_name, DOMAIN_NAME_LEN);

  memcpy(cache->ID, dns_response->id, ID_LEN);
  memcpy(cache->RDDATA, dns_response->RDDATA, RDDATA_LEN);
  memcpy(cache->TTL, dns_response->TTL, TTL_LEN);
  memcpy(cache->message_size, dns_response->message_size, PREFIX_SIZE);
  cache->message = (char *)calloc(sizeof(*dns_response->message), size + 1);
  memcpy(cache->message, dns_response->message, size);
  cache->expired = false;
  time(&cache->t);
}

void cacheResponse(FILE *logFile, Dns_Response *dns_response, Cache *cache) {
  time_t expire_time;

  updateCaches(cache);
  for (int i = 0; i < MAX_CACHE; i++) {
    // Check if there are any record in cache
    if (cache[i].message == NULL) {
      addToCache(dns_response, &cache[i]);
      expire_time = (((unsigned long)cache[i].TTL[0] << 24 |
                      (unsigned long)cache[i].TTL[1] << 16 |
                      (unsigned long)cache[i].TTL[2] << 8 |
                      (unsigned long)cache[i].TTL[3])) +
                    cache[i].t;
      strftime(cache[i].expire_time, TIME_SIZE, TIME_FORMAT,
               localtime(&expire_time));
      return;
    }
    // Check if there are any expired or not in caches
    if (cache[i].expired) {
      logReplacingEvent(logFile, dns_response->domain_name,
                        cache[0].domain_name);
      free(cache[i].message);
      addToCache(dns_response, &cache[i]);
      return;
    }
  }

  // Reaplce the first cache in caches list and log this event
  logReplacingEvent(logFile, dns_response->domain_name, cache[0].domain_name);

  free(cache[0].message);
  addToCache(dns_response, &cache[0]);
}

void updateCaches(Cache *cache) {
  time_t cur_t;
  double diff_t;
  unsigned long TTL;
  for (int i = 0; i < MAX_CACHE; i++) {
    if (cache[i].message == NULL)
      continue;
    if (!cache[i].expired) {
      TTL = 0;
      for (int j = 0; j < 4; j++) {
        TTL <<= 8;
        TTL |= cache[i].TTL[j];
      }
      time(&cur_t);

      diff_t = difftime(cur_t, cache[i].t);
      cache[i].t = cur_t;
      if (TTL <= diff_t) {
        cache[i].expired = true;
        continue;
      }
      TTL -= diff_t;
      // Update TTL section
      cache[i].TTL[0] = TTL >> 24;
      cache[i].TTL[1] = (TTL >> 16) % 256;
      cache[i].TTL[2] = (TTL >> 8) % 256;
      cache[i].TTL[3] = TTL % 256;
    }
  }
}

int checkValidCache(Dns_Packet *dns_packet, Cache *cache) {
  int TTL_index = HEADER_LEN * 2 + strlen(dns_packet->domain_name);
  updateCaches(cache);
  for (int i = 0; i < MAX_CACHE; i++) {
    if (cache[i].message == NULL)
      continue;
    if (memcmp(dns_packet->domain_name, cache[i].domain_name,
               DOMAIN_NAME_LEN) == 0) {
      if (!cache[i].expired) {
        // Relace response ID with request ID
        memcpy(cache[i].message, dns_packet->id, ID_LEN);
        memcpy(cache[i].message + TTL_index, cache[i].TTL, TTL_LEN);
        return i;
      }
    }
  }
  return -1;
}