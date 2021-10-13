#ifndef _SERVER_
#define _SERVER_

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "cache.h"
#include "linkedList.h"
#include "log.h"
#include "parse.h"

#define PORT "8053"
#define EPOLL_SIZE 1
// 0x80 hex indicate binary 1000(QR) 0000(TC RD)
#define RESPONSE_QR 0x80
#define MAX_EVENTS 300
#define AAAA_CODE 28
#define RCODE_FOUR 4

// initialize dns server
int initServer();
// Run dns server
void runServer(char *upstream_IP, char *port, FILE *logFile);
// Connect to Upstream server
int ConnectUpstream(char *upstream_IP, char *port);
// Add or delete a given socketfd into epoll events list (depends on action)
void modifyEpolledList(int epollfd, int socketfd, int action);
// Write message to a given socketfd
void writeToSocket(int socketfd, char *message, unsigned char *message_size);
// Read message from a given socketfd
void readFromSocket(int socketfd, char **message, unsigned char *message_size);
// Set socket to non-blocking mode
void setSocketNonBlocking(int socketfd);
#endif