#include "zmq_relay.h"
#include <zmq.h>

int wirego_version_major_cb(void) {
  return -1;
}

int wirego_version_minor_cb(void) {
  return -1;
}

int wirego_zmq_ping(wirego_t *wirego_h) {
  const char ping_cmd[] = "ping";
  const char ping_resp[] = "echo reply";
  char response[255];

  int ret = zmq_send(wirego_h->zsock, (void*)(ping_cmd), sizeof(ping_cmd), 0);
  if (ret != 0) {
    return -1;
  }

	int size = zmq_recv (wirego_h->zsock, response, sizeof(response), 0);
  if (size == sizeof(ping_resp)) {
    return 0;
  }
  return -1;
}