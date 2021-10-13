#include "linkedList.h"

Events *insertNewEvents(Events *events, Events *new_event) {
  Events *tmp = events;
  while (tmp->next) {
    tmp = tmp->next;
  }

  new_event->next = tmp->next;
  tmp->next = new_event;
  return events;
}

Events *createEvent(int socketfd, unsigned char *requestID,
                    int upstream_socketfd) {
  Events *new_event = (Events *)malloc(sizeof(Events));
  memcpy(new_event->reqeustID, requestID, ID_LEN);
  new_event->socketfd = socketfd;
  new_event->upstreamfd = upstream_socketfd;
  new_event->next = NULL;
  return new_event;
}

void removeEvent(Events *events, unsigned char *requestID) {
  Events *tmp;

  if (events != NULL) {
    while (events->next != NULL) {
      if (memcmp(events->next->reqeustID, requestID, ID_LEN) == 0) {
        break;
      }
      events = events->next;
    }
  }

  tmp = events->next;
  events->next = tmp->next;
  free(tmp);
}

int lookupEvent(Events *events, unsigned char *requestID) {
  Events *tmp = events;
  while (tmp != NULL) {
    if (memcmp(tmp->reqeustID, requestID, ID_LEN) == 0) {
      return tmp->socketfd;
    }
    tmp = tmp->next;
  }
  return -1;
}