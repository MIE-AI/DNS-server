#ifndef _LINKEDLIST_

#include "parse.h"

// LinkedList data structure to stores dns events
typedef struct EVENTS {
  unsigned char reqeustID[ID_LEN];
  int socketfd;
  int upstreamfd;
  struct EVENTS *next;
} Events;

// Create a event by given info
Events *createEvent(int socketfd, unsigned char *requestID,
                    int upstream_socketfd);
// Insert a new event into event list
Events *insertNewEvents(Events *events, Events *new_event);
// Remove a given event ID in event list
void removeEvent(Events *events, unsigned char *requestID);
// Look up event socketfd by given request ID
int lookupEvent(Events *events, unsigned char *requestID);

#endif