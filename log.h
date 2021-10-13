#ifndef _LOG_
#define _LOG_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define SERVERLOG "dns_svr.log"
#define TIME_SIZE 32
#define TIME_FORMAT "%FT%T%z"

// Get current time
void getTime(char *buffer);
// Log request in log file
void logRequestEvent(FILE *logFile, char *domain_name);
// Log if the request type is not AAAA
void logRequestNotFoundEvent(FILE *logFile);
// Log if domain name is expires in cache
void logExpiresEvent(FILE *logFile, char *domain_name, char *expire_time);
// Log if cache eviction
void logReplacingEvent(FILE *logFile, char *domain_name,
                       char *cache_domain_name);
// Log if look up IP address for a domain name is success
void logLookUpEvent(FILE *logFile, char *domain_name, char *IP);

#endif