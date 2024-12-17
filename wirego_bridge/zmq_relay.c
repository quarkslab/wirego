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

char * wirego_get_name_cb(wirego_t *wirego_h) {
  const char cmd[] = "get_name";
  char *name = NULL;

  ws_warning("sending get name...");
  
  if (zmq_send(wirego_h->zsock, (void*)(cmd), sizeof(cmd), 0) == -1) {
    return name;
  }
  ws_warning("waiting get name response...");

  zmq_msg_t msg;
  zmq_msg_init (&msg);
	int size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  char * resp = zmq_msg_data(&msg);
  if ((size == 0) || (resp[size-1] != 0x00)) {
    goto done;
  }

  name = (char*) calloc(size, 1);
  strcpy(name, resp);

done:
  zmq_msg_close (&msg);
  return name;
}

int wirego_get_fields_count_cb(wirego_t *wirego_h) {
  const char cmd[] = "get_fields_count";
  char * resp;
  int size;
  zmq_msg_t msg;
  int fields_count = -1;

  ws_warning("sending get_fields_count request ...");
  
  if (zmq_send(wirego_h->zsock, (void*)(cmd), sizeof(cmd), 0) == -1) {
    return -1;
  }
  ws_warning("waiting get_fields_count response...");

  //Frame 0 contains fields count (4 bytes / little endian)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  resp = zmq_msg_data(&msg);
  if (size != 4) {
    goto done;
  }
  fields_count = *((int*)(resp));
  goto done;

done:
  zmq_msg_close (&msg);
  return fields_count;
}

int wirego_get_field_cb(wirego_t *wirego_h, int idx, int *wirego_field_id, char** name, char** filter, int *value_type, int *display) {
  const char cmd[] = "get_field";
  char * resp;
  int size;
  zmq_msg_t msg;
  int ret = -1;

  *wirego_field_id = -1;
  *name = NULL;
  *filter = NULL;
  *value_type = -1;
  *display = -1;
 
  ws_warning("sending get_field request ...");
  
  if (zmq_send(wirego_h->zsock, (void*)(cmd), sizeof(cmd), ZMQ_SNDMORE) == -1) {
    return -1;
  }
  if (zmq_send(wirego_h->zsock, &idx, sizeof(int), 0) == -1) {
    return -1;
  }
  ws_warning("waiting get_field response...");

  //Frame 0 contains field id
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  resp = zmq_msg_data(&msg);
  if (size != 4) {
    goto done;
  }
  *wirego_field_id = *(int*)resp;
  zmq_msg_close (&msg);

  //Frame 1 contains field name (c string)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  resp = zmq_msg_data(&msg);
  if ((size == 0) || (resp[size-1] != 0x00)) {
    goto done;
  }
  *name = (char*) calloc(size, 1);
  strcpy(*name, resp);
  zmq_msg_close (&msg);

  //Frame 2 contains field filter (c string)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  resp = zmq_msg_data(&msg);
  if ((size == 0) || (resp[size-1] != 0x00)) {
    goto done;
  }
  *filter = (char*) calloc(size, 1);
  strcpy(*name, resp);
  zmq_msg_close (&msg);

  //Frame 3 contains value type
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  resp = zmq_msg_data(&msg);
  if (size != 4) {
    goto done;
  }
  *value_type = *(int*)resp;
  zmq_msg_close (&msg);

  //Frame 4 contains display type
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  resp = zmq_msg_data(&msg);
  if (size != 4) {
    goto done;
  }
  *display = *(int*)resp;
  zmq_msg_close (&msg);

  ret = 0;
  goto done;

done:
  zmq_msg_close (&msg);
  return ret;
}

char* wirego_get_plugin_filter_cb(wirego_t *wirego_h){
  const char cmd[] = "get_plugin_filter";
  char *name = NULL;

  ws_warning("sending get_plugin_filter...");
  
  if (zmq_send(wirego_h->zsock, (void*)(cmd), sizeof(cmd), 0) == -1) {
    return name;
  }
  ws_warning("waiting get_plugin_filter response...");

  zmq_msg_t msg;
  zmq_msg_init (&msg);
	int size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  char * resp = zmq_msg_data(&msg);
  if ((size == 0) || (resp[size-1] != 0x00)) {
    goto done;
  }

  name = (char*) calloc(size, 1);
  strcpy(name, resp);

done:
  zmq_msg_close (&msg);
  return name;
}