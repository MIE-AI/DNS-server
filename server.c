#include "server.h"

void runServer(char *upstream_IP, char *port, FILE *logFile) {
  Cache cache[MAX_CACHE];
  Events *request_Event, *tmp_p;
  Dns_Packet *dns_packet;
  Dns_Response *dns_response;
  struct epoll_event events[MAX_EVENTS];
  char *message = NULL, ipv6[INET6_ADDRSTRLEN];
  unsigned char buffer[2];
  int upstream_socketfd = 0, epollfd, listenfd, waitfds, event_socketfd;
  int status, cache_index;

  dns_packet = (Dns_Packet *)malloc(sizeof(Dns_Packet));
  dns_packet->message = NULL;
  dns_response = (Dns_Response *)malloc(sizeof(Dns_Response));
  dns_response->message = NULL;

  request_Event = (Events *)malloc(sizeof(Events));
  request_Event->socketfd = 0;
  request_Event->upstreamfd = 0;
  memset(request_Event->reqeustID, 0, ID_LEN);
  request_Event->next = NULL;
  initCache(cache);

  listenfd = initServer();
  setSocketNonBlocking(listenfd);

  epollfd = epoll_create(EPOLL_SIZE);
  // Add listen socket into epoll event list
  modifyEpolledList(epollfd, listenfd, EPOLL_CTL_ADD);

  while (1) {
    waitfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);

    if (waitfds < 0) {
      perror("EPOLL_WAIT() FAILED");
      break;
    }
    if (waitfds == 0) {
      printf("EPOLL_WAIT FUNCTION TIMEOUT!. \n");
      continue;
    }

    for (int i = 0; i < waitfds; i++) {
      tmp_p = request_Event->next;
      while (tmp_p != NULL) {
        upstream_socketfd = tmp_p->upstreamfd;
        if (events[i].data.fd == upstream_socketfd)
          break;
        tmp_p = tmp_p->next;
      }
      if ((events[i].data.fd == upstream_socketfd) &&
          (events[i].events & EPOLLIN)) {
        readFromSocket(upstream_socketfd, &message, buffer);
        status = parseDnsResponse(dns_response, message, buffer);
        // Free the message after parse into struct 'Dns_Response'
        free(message);
        event_socketfd = lookupEvent(request_Event, dns_response->id);
        if (status != 1) {
          // No answer in response or answer is not tpye AAAA
          writeToSocket(event_socketfd, dns_response->message,
                        dns_response->message_size);
          close(event_socketfd);
          close(upstream_socketfd);
          removeEvent(request_Event, dns_response->id);
          // Free current dns_response's message after sent
          free(dns_response->message);
          continue;
        } else {
          cacheResponse(logFile, dns_response, cache);
          inet_ntop(AF_INET6, dns_response->RDDATA, ipv6, INET6_ADDRSTRLEN);
          // Send response back to client
          writeToSocket(event_socketfd, dns_response->message,
                        dns_response->message_size);
          close(event_socketfd);
          close(upstream_socketfd);
          // Only log the first answer in response
          logLookUpEvent(logFile, dns_response->domain_name, ipv6);
          removeEvent(request_Event, dns_response->id);
          // Free current dns_response's message after sent
          free(dns_response->message);
          continue;
        }
      }

      if ((events[i].data.fd == listenfd) && (events[i].events & EPOLLIN)) {
        // If the events is listenSock then a client is connecting to a sever
        struct addrinfo client;
        socklen_t client_len = sizeof(client);
        int client_socket =
            accept(listenfd, (struct sockaddr *)&client, &client_len);

        setSocketNonBlocking(client_socket);

        if (client_socket < 0) {
          perror("ACCEPT FAILED!\n");
          continue;
        }
        // Add new client to epoll list
        modifyEpolledList(epollfd, client_socket, EPOLL_CTL_ADD);
        continue;
      } else if ((events[i].events & EPOLLIN) &&
                 events[i].data.fd != upstream_socketfd) {
        // Another event occur case one: Got data transfer from client Case two:
        // client disconnected Get client's data
        readFromSocket(events[i].data.fd, &message, buffer);
        parseDnsPacket(dns_packet, message, buffer);
        // Free the message after parse into struct 'Dns_Packet'
        free(message);
        // Log request event
        logRequestEvent(logFile, dns_packet->domain_name);
        // Check if there are a valid cache in list
        if ((cache_index = checkValidCache(dns_packet, cache)) != -1) {
          logExpiresEvent(logFile, cache[cache_index].domain_name,
                          cache[cache_index].expire_time);
          inet_ntop(AF_INET6, cache[cache_index].RDDATA, ipv6,
                    INET6_ADDRSTRLEN);
          logLookUpEvent(logFile, cache[cache_index].domain_name, ipv6);
          // Send cache response back to client
          writeToSocket(events[i].data.fd, cache[cache_index].message,
                        cache[cache_index].message_size);
          close(events[i].data.fd);
          continue;
        }

        if ((dns_packet->qtype[0] | dns_packet->qtype[1]) == AAAA_CODE) {
          // AAAA request
          upstream_socketfd = ConnectUpstream(upstream_IP, port);
          modifyEpolledList(epollfd, upstream_socketfd, EPOLL_CTL_ADD);
          request_Event = insertNewEvents(
              request_Event, createEvent(events[i].data.fd, dns_packet->id,
                                         upstream_socketfd));
          writeToSocket(upstream_socketfd, dns_packet->message,
                        dns_packet->message_size);
          free(dns_packet->message);
          continue;
        } else {
          // Not a AAAA request
          logRequestNotFoundEvent(logFile);
          // Change QR bit
          dns_packet->message[2] = RESPONSE_QR;
          // Change Rcode
          dns_packet->message[3] =
              ((dns_packet->message[3] >> 4) << 4) | RCODE_FOUR;
          writeToSocket(events[i].data.fd, dns_packet->message,
                        dns_packet->message_size);
          close(events[i].data.fd);
          free(dns_packet->message);
          continue;
        }
      }
    }
  }
}

int initServer() {
  struct addrinfo hint, *dns_server;
  int socketfd;

  memset(&hint, 0, sizeof(hint));
  hint.ai_family = AF_INET;
  hint.ai_socktype = SOCK_STREAM;
  hint.ai_flags = AI_PASSIVE;
  getaddrinfo(NULL, PORT, &hint, &dns_server);

  if ((socketfd = socket(dns_server->ai_family, dns_server->ai_socktype,
                         dns_server->ai_protocol)) < 0) {
    perror("SOCKET ERROR!");
    exit(EXIT_FAILURE);
  }

  int const enable = 1;
  if (setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) <
      0) {
    perror("SETSOCKOPT ERROR!");
    exit(EXIT_FAILURE);
  }

  if (bind(socketfd, dns_server->ai_addr, dns_server->ai_addrlen) < 0) {
    perror("BIND ERROR!");
    exit(EXIT_FAILURE);
  }

  if (listen(socketfd, 5) != 0) {
    perror("LISTEN ERROR!");
    exit(EXIT_FAILURE);
  }
  freeaddrinfo(dns_server);
  return socketfd;
}

int ConnectUpstream(char *upstream_IP, char *port) {
  int socketfd;
  struct addrinfo hint, *upstream_info, *rp;
  memset(&hint, 0, sizeof hint);
  hint.ai_family = AF_INET;
  hint.ai_socktype = SOCK_STREAM;

  if (getaddrinfo(upstream_IP, port, &hint, &upstream_info) != 0) {
    exit(EXIT_FAILURE);
  }

  for (rp = upstream_info; rp != NULL; rp = rp->ai_next) {
    socketfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (socketfd == -1)
      continue;
    if (connect(socketfd, rp->ai_addr, rp->ai_addrlen) != -1)
      break;
    close(socketfd);
  }

  if (rp == NULL) {
    fprintf(stderr, "CONNECT FAILED!\n");
    exit(EXIT_FAILURE);
  }
  freeaddrinfo(upstream_info);
  return socketfd;
}

void modifyEpolledList(int epollfd, int socketfd, int action) {
  struct epoll_event ev_list;
  memset(&ev_list, 0, sizeof(struct epoll_event));
  ev_list.data.fd = socketfd;
  ev_list.events = EPOLLIN;
  epoll_ctl(epollfd, action, socketfd, &ev_list);
}

void writeToSocket(int socketfd, char *message, unsigned char *message_size) {
  int bytes;
  int size = ((int)message_size[0] << 8) | message_size[1];

  if ((bytes = write(socketfd, message_size, PREFIX_SIZE)) <= 0) {
    perror("WRITE ERROR!");
    exit(EXIT_FAILURE);
  }

  if ((bytes = write(socketfd, message, size)) <= 0) {
    perror("WRITE ERROR!");
    exit(EXIT_FAILURE);
  }
}

void readFromSocket(int socketfd, char **message, unsigned char *message_size) {
  int read_size = 0, off_set = 0, size;
  memset(message_size, 0, PREFIX_SIZE);

  for (;;) {
    read_size = read(socketfd, message_size + off_set, sizeof(char));
    if (read_size == -1)
      continue;
    off_set += read_size;
    if (off_set >= PREFIX_SIZE)
      break;
  }

  size = (((int)message_size[0]) << 8) | (message_size[1]);
  *message = (char *)calloc(sizeof(*message), size);
  off_set = 0;
  for (;;) {
    read_size = read(socketfd, *message + off_set, sizeof(char));
    if (read_size == -1)
      continue;
    off_set += read_size;
    if (off_set >= size)
      break;
  }
}

void setSocketNonBlocking(int socketfd) {
  int flag = fcntl(socketfd, F_GETFL, 0);
  fcntl(socketfd, F_SETFL, flag | O_NONBLOCK);
}