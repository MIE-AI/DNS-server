#ifndef _PARSE_
#define _PARSE_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum DATA_SIZE {
  PREFIX_SIZE = 2,
#define PREFIX_SIZE PREFIX_SIZE
  DOMAIN_NAME_LEN = 254,
#define DOMAIN_NAME_LEN DOMAIN_NAME_LEN
  ID_LEN = 2,
#define ID_LEN ID_LEN
  RDDATA_LEN = 16,
#define RDDATA_LEN RDDATA_LEN
  HEADER_LEN = 12,
#define HEADER_LEN HEADER_LEN
  QTYPE_LEN = 2,
#define QTYPE_LEN QTYPE_LEN
  ANSWER_SECTION_LEN = 2,
#define ANSWER_SECTION_LEN ANSWER_SECTION_LEN
  TTL_LEN = 4,
#define TTL_LEN TTL_LEN
  QCLASS_LEN = 2,
#define QCLASS_LEN QCLASS_LEN
  TYPE_LEN = 2,
#define TYPE TYPE
  CLASS_LEN = 2,
#define CLASS_LEN CLASS_LEN
  RDLENGTH_LEN = 2,
#define RDLENGTH_LEN RDLENGTH_LEN
};

// Struct to stores info of dns packets
typedef struct dns_packet {
  unsigned char id[ID_LEN];
  char *message;
  unsigned char message_size[PREFIX_SIZE];
  char domain_name[DOMAIN_NAME_LEN];
  char qtype[QTYPE_LEN];
} Dns_Packet;


// Strcuct to stores info of dns response
typedef struct dns_response {
  unsigned char id[ID_LEN];
  char *message;
  unsigned char message_size[PREFIX_SIZE];
  char domain_name[DOMAIN_NAME_LEN];
  unsigned char qtype[QTYPE_LEN];
  unsigned char num_answer[ANSWER_SECTION_LEN];
  unsigned char TTL[TTL_LEN];
  char RDDATA[RDDATA_LEN];
} Dns_Response;

// Parse a given packet and put it's info into a given dns_packet structure
void parseDnsPacket(Dns_Packet *dns_packet, char *packet,
                    unsigned char *packet_size);
// Pares a given response and put it's info into a given dns_response structure
int parseDnsResponse(Dns_Response *dns_response, char *response,
                     unsigned char *response_size);
// Parse domain name from given message
int parseDomainName(char *message, int index, char *domain_name_dest);

#endif