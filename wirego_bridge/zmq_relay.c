#include "zmq_relay.h"
#include <zmq.h>
#include <wsutil/wslog.h>

int wirego_version_cb(wirego_t *wirego_h, int *major, int*minor) {
  const char cmd[] = "version";
  char * resp;
  int size;
  zmq_msg_t msg;
  int ret = -1;

  *major = 0;
  *minor = 0;
  ws_warning("sending version request ...");
  
  if (zmq_send(wirego_h->zsock, (void*)(cmd), sizeof(cmd), 0) == -1) {
    return -1;
  }
  ws_warning("waiting version response...");

  //Frame 0 contains major version (1 byte)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  resp = zmq_msg_data(&msg);
  if (size != 1) {
    goto done;
  }
  *major = resp[0];
  

  //Frame 1 contains minor version (1 byte)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  resp = zmq_msg_data(&msg);
  if (size != 1) {
    goto done;
  }
  *minor = resp[0];
  zmq_msg_close (&msg);
  ret = 0;
  goto done;

done:
zmq_msg_close (&msg);
  return ret;
}

int wirego_zmq_ping(wirego_t *wirego_h) {
  const char ping_cmd[] = "ping";
  const char ping_resp[] = "echo reply";
  int ret = -1;

  ws_warning("sending ping...");
  
  if (zmq_send(wirego_h->zsock, (void*)(ping_cmd), sizeof(ping_cmd), 0) == -1) {
    return -1;
  }
  ws_warning("waiting ping response...");

  zmq_msg_t msg;
  zmq_msg_init (&msg);
	int size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  char * resp = zmq_msg_data(&msg);
  if ((size == sizeof(ping_resp)) && resp[size-1] == 0 && !strcmp(resp, ping_resp)) {
    ret = 0;
    goto done;
  }

done:
  zmq_msg_close (&msg);
  return ret;
}