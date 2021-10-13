#include "parse.h"

void parseDnsPacket(Dns_Packet *dns_packet, char *packet,
                    unsigned char *packet_size) {
  int offset = HEADER_LEN, message_size = 0;
  memset(dns_packet, 0, sizeof(Dns_Packet));

  memcpy(dns_packet->id, packet, ID_LEN);
  memcpy(dns_packet->message_size, packet_size, PREFIX_SIZE);

  message_size = ((int)packet_size[0] << 8) | packet_size[1];

  if (dns_packet->message != NULL) {
    free(dns_packet->message);
    dns_packet->message = NULL;
  }
  dns_packet->message = (char *)malloc(message_size);
  memcpy(dns_packet->message, packet, message_size);

  offset = parseDomainName(packet, HEADER_LEN, dns_packet->domain_name);

  offset += QTYPE_LEN;
  memcpy(dns_packet->qtype, packet + offset, QTYPE_LEN);
}

int parseDnsResponse(Dns_Response *dns_response, char *response,
                     unsigned char *response_size) {
  int offset = HEADER_LEN, message_size = 0;
  memset(dns_response, 0, sizeof(Dns_Response));

  message_size = ((int)response_size[0] << 8) | response_size[1];

  memcpy(dns_response->id, response, ID_LEN);
  memcpy(dns_response->num_answer, response + 6, ANSWER_SECTION_LEN);

  memcpy(dns_response->message_size, response_size, PREFIX_SIZE);

  if (dns_response->message != NULL) {
    free(dns_response->message);
    dns_response->message = NULL;
  }

  dns_response->message = (char *)malloc(message_size);
  memcpy(dns_response->message, response, message_size);

  offset = parseDomainName(response, HEADER_LEN, dns_response->domain_name);

  if ((((int)dns_response->num_answer[0] << 8) | dns_response->num_answer[1]) ==
      0)
    return -1;

  // current offset at end of Question name (q name) in Question section
  // add on QTPYE and QCLASS in question section and NAME in answer section
  // to index TYPE
  // 1 bit for end the QNAME
  offset += QTYPE_LEN + QCLASS_LEN + ID_LEN + 1;
  memcpy(dns_response->qtype, response + offset, QTYPE_LEN);

  if ((((int)dns_response->qtype[0] << 8) | dns_response->qtype[1]) != 28)
    return -2;

  // current offset at TYPE under answer section add on TYPE, CLASS to index
  // TTL
  offset += TYPE_LEN + CLASS_LEN;

  memcpy(dns_response->TTL, response + offset, TTL_LEN);
  offset += RDLENGTH_LEN + TTL_LEN;
  memcpy(dns_response->RDDATA, response + offset, RDDATA_LEN);
  return 1;
}

int parseDomainName(char *message, int index, char *domain_name_dest) {
  int domain_index = 0, buffer_size = 0;
  char domain_name[DOMAIN_NAME_LEN] = {0};

  while (message[index] != 0) {
    buffer_size = (unsigned char)message[index++];
    strncat(domain_name, message + index, buffer_size);
    domain_index += buffer_size;
    index += buffer_size;
    domain_name[domain_index++] = '.';
  }

  if (domain_index > 0)
    domain_name[--domain_index] = '\0';

  strcpy(domain_name_dest, domain_name);
  return index;
}