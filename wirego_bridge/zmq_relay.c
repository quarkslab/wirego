#include "zmq_relay.h"
#include <zmq.h>
#include <wsutil/wslog.h>

int wirego_version_major_cb(wirego_t *wirego_h) {
  const char cmd[] = "version_major";
  char response[255];

  ws_warning("sending version major...");
  
  int ret = zmq_send(wirego_h->zsock, (void*)(cmd), sizeof(cmd), 0);
  if (ret == -1) {
    return -1;
  }
  ws_warning("waiting version major response...");

  zmq_msg_t msg;
  zmq_msg_init (&msg);
	int size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  char * resp = zmq_msg_data(&msg);

  if (size != 1) {
    return -1;
  }

  return resp[0];
}

int wirego_version_minor_cb(wirego_t *wirego_h) {
  const char cmd[] = "version_minor";
  char response[255];

  ws_warning("sending version minor...");
  
  int ret = zmq_send(wirego_h->zsock, (void*)(cmd), sizeof(cmd), 0);
  if (ret == -1) {
    return -1;
  }
  ws_warning("waiting version minor response...");

  zmq_msg_t msg;
  zmq_msg_init (&msg);
	int size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  char * resp = zmq_msg_data(&msg);

  if (size != 1) {
    return -1;
  }

  return resp[0];
}

int wirego_zmq_ping(wirego_t *wirego_h) {
  const char ping_cmd[] = "ping";
  const char ping_resp[] = "echo reply";
  char response[255];

  ws_warning("sending ping...");
  
  int ret = zmq_send(wirego_h->zsock, (void*)(ping_cmd), sizeof(ping_cmd), 0);
  if (ret == -1) {
    return -1;
  }
  ws_warning("waiting ping response...");

  zmq_msg_t msg;
  zmq_msg_init (&msg);
	int size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  char * resp = zmq_msg_data(&msg);
  if ((size == sizeof(ping_resp)) && resp[size-1] == 0 && !strcmp(resp, ping_resp)) {
    return 0;
  }
  return -1;
}