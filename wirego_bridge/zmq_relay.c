#include "zmq_relay.h"
#include <zmq.h>
#include <wsutil/wslog.h>


//wirego_version_cb asks remote ZMQ endpoint for its version
int wirego_version_cb(wirego_t* wirego_h, int *major, int*minor) {
  const char cmd[] = "version";
  char* resp;
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

//wirego_zmq_ping send a ping to a remote ZMQ endpoint and hope for a reply
int wirego_zmq_ping(wirego_t* wirego_h) {
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
  char* resp = zmq_msg_data(&msg);
  if ((size == sizeof(ping_resp)) && resp[size-1] == 0 && !strcmp(resp, ping_resp)) {
    ret = 0;
    goto done;
  }

done:
  zmq_msg_close (&msg);
  return ret;
}

//wirego_get_name_cb asks for the remote ZMQ endpoint for it's name
char* wirego_get_name_cb(wirego_t* wirego_h) {
  const char cmd[] = "get_name";
  char*name = NULL;

  ws_warning("sending get name...");
  
  if (zmq_send(wirego_h->zsock, (void*)(cmd), sizeof(cmd), 0) == -1) {
    return name;
  }
  ws_warning("waiting get name response...");

  zmq_msg_t msg;
  zmq_msg_init (&msg);
	int size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  char* resp = zmq_msg_data(&msg);
  if ((size == 0) || (resp[size-1] != 0x00)) {
    goto done;
  }

  name = (char*) calloc(size, 1);
  strcpy(name, resp);
  ws_warning("wirego_get_name_cb %s",name);

done:
  zmq_msg_close (&msg);
  return name;
}


//wirego_get_plugin_filter_cb asks the remote ZMQ endpoint for its filter
char* wirego_get_plugin_filter_cb(wirego_t* wirego_h){
  const char cmd[] = "get_plugin_filter";
  char*filter = NULL;

  ws_warning("sending get_plugin_filter...");
  
  if (zmq_send(wirego_h->zsock, (void*)(cmd), sizeof(cmd), 0) == -1) {
    return filter;
  }
  ws_warning("waiting get_plugin_filter response...");

  zmq_msg_t msg;
  zmq_msg_init (&msg);
	int size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  char* resp = zmq_msg_data(&msg);
  if ((size == 0) || (resp[size-1] != 0x00)) {
    goto done;
  }

  filter = (char*) calloc(size, 1);
  strcpy(filter, resp);
  ws_warning("wirego_get_plugin_filter_cb %s",filter);

done:
  zmq_msg_close (&msg);
  return filter;
}

//wirego_get_fields_count_cb asks the remote ZMQ endpoint for the number of custom fields to be declared
int wirego_get_fields_count_cb(wirego_t* wirego_h) {
  const char cmd[] = "get_fields_count";
  char* resp;
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
  ws_warning("wirego_get_fields_count_cb %d",fields_count);

  goto done;

done:
  zmq_msg_close (&msg);
  return fields_count;
}

//wirego_get_field_cb asks the remote ZMQ endpoint for the details about field number "idx"
int wirego_get_field_cb(wirego_t* wirego_h, int idx, int *wirego_field_id, char** name, char** filter, int *value_type, int *display) {
  const char cmd[] = "get_field";
  char* resp;
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

  //Frame 0 contains field id (int)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  resp = zmq_msg_data(&msg);
  if (size != 4) {
    zmq_msg_close (&msg);
    return -1;
  }
  *wirego_field_id = *(int*)resp;
  zmq_msg_close (&msg);

  //Frame 1 contains field name (c string)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  resp = zmq_msg_data(&msg);
  if ((size == 0) || (resp[size-1] != 0x00)) {
    zmq_msg_close (&msg);
    return -1;
  }
  *name = (char*) calloc(size, 1);
  strcpy(*name, resp);
  zmq_msg_close (&msg);

  //Frame 2 contains field filter (c string)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  resp = zmq_msg_data(&msg);
  if ((size == 0) || (resp[size-1] != 0x00)) {
    zmq_msg_close (&msg);
    return -1;
  }
  *filter = (char*) calloc(size, 1);
  strcpy(*filter, resp);
  zmq_msg_close (&msg);

  //Frame 3 contains value type (int)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  resp = zmq_msg_data(&msg);
  if (size != 4) {
    zmq_msg_close (&msg);
    return -1;
  }
  *value_type = *(int*)resp;
  zmq_msg_close (&msg);

  //Frame 4 contains display type (int)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  resp = zmq_msg_data(&msg);
  if (size != 4) {
    zmq_msg_close (&msg);
    return -1;
  }
  *display = *(int*)resp;
  zmq_msg_close (&msg);

  ws_warning("wirego_get_field(%d) Field id:%d Name: %s Filter: %s Vtype %d Display %d", idx, *wirego_field_id, *name, *filter, *value_type, *display);

  ret = 0;

  return ret;
}

//wirego_detect_int_cb asks the remote ZMQ endpoint for the detection filter of type "int" with given index
char* wirego_detect_int_cb(wirego_t* wirego_h, int *filter_value, int idx) {
  const char cmd[] = "detect_int";
  char* resp;
  int size;
  zmq_msg_t msg;

  char* filter = NULL;
  *filter_value = -1;
  
  ws_warning("sending detect_int request ...");
  
  if (zmq_send(wirego_h->zsock, (void*)(cmd), sizeof(cmd), ZMQ_SNDMORE) == -1) {
    return NULL;
  }
  if (zmq_send(wirego_h->zsock, &idx, sizeof(int), 0) == -1) {
    return NULL;
  }
  ws_warning("waiting detect_int response...");

  //Frame 0 contains filter string (string)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  resp = zmq_msg_data(&msg);
  if ((size == 0) || (resp[size-1] != 0x00)) {
    zmq_msg_close (&msg);
    return NULL;
  }
  filter = (char*) calloc(size, 1);
  strcpy(filter, resp);

  //Frame 1 contains match value (int)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  resp = zmq_msg_data(&msg);
  if (size != 4) {
    zmq_msg_close (&msg);
    return NULL;
  }
  *filter_value = *(int*)resp;
  zmq_msg_close (&msg);

  ws_warning("wirego_detect_int(%d) %s = %d", idx, filter, *filter_value);

  return filter;
}

char* wirego_detect_string_cb(wirego_t* wirego_h,  char**filter_value, int idx) {
  const char cmd[] = "detect_string";
  char* resp;
  int size;
  zmq_msg_t msg;

  char* filter = NULL;
  *filter_value = NULL;
  
  ws_warning("sending detect_string request ...");
  
  if (zmq_send(wirego_h->zsock, (void*)(cmd), sizeof(cmd), ZMQ_SNDMORE) == -1) {
    return NULL;
  }
  if (zmq_send(wirego_h->zsock, &idx, sizeof(int), 0) == -1) {
    return NULL;
  }
  ws_warning("waiting detect_string response...");

  //Frame 0 contains filter string (string)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  resp = zmq_msg_data(&msg);
  if ((size == 0) || (resp[size-1] != 0x00)) {
    zmq_msg_close (&msg);
    return NULL;
  }
  filter = (char*) calloc(size, 1);
  strcpy(filter, resp);

  //Frame 1 contains match value (string)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  resp = zmq_msg_data(&msg);
  if ((size == 0) || (resp[size-1] != 0x00)) {
    zmq_msg_close (&msg);
    return NULL;
  }
  *filter_value = (char*) calloc(size, 1);
  strcpy(*filter_value, resp);

  ws_warning("wirego_detect_string(%d) %s = %s", idx, filter, *filter_value);

  return filter;
}

char* wirego_detect_heuristic_parent_cb(wirego_t* wirego_h, int idx) {
  const char cmd[] = "detect_heuristic_parent";
  char* resp;
  int size;
  zmq_msg_t msg;

  char* parent_protocol = NULL;
  
  ws_warning("sending detect_heuristic_parent request ...");
  
  if (zmq_send(wirego_h->zsock, (void*)(cmd), sizeof(cmd), ZMQ_SNDMORE) == -1) {
    return NULL;
  }
  if (zmq_send(wirego_h->zsock, &idx, sizeof(int), 0) == -1) {
    return NULL;
  }
  ws_warning("waiting detect_heuristic_parent response...");

  //Frame 0 contains parent_protocol (string)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  resp = zmq_msg_data(&msg);
  if ((size == 0) || (resp[size-1] != 0x00)) {
    zmq_msg_close (&msg);
    return NULL;
  }
  parent_protocol = (char*) calloc(size, 1);
  strcpy(parent_protocol, resp);


  ws_warning("detect_heuristic_parent(%d) %s", idx, parent_protocol);
  return parent_protocol;
}


int wirego_detection_heuristic_cb(wirego_t* wirego_h, int packet_number, char* src, char* dst, char* layer, char* packet, int packet_size) {
  if (src == NULL || dst == NULL || layer == NULL || packet == NULL || packet_size == 0) {
    return -1;
  }

  const char cmd[] = "detection_heuristic";
  char* resp;
  int size;
  zmq_msg_t msg;
  int detection_result = -1;
 
  
  ws_warning("sending detection_heuristic request ...");
  
  if (zmq_send(wirego_h->zsock, (void*)(cmd), sizeof(cmd), ZMQ_SNDMORE) == -1) {
    return -1;
  }
  if (zmq_send(wirego_h->zsock, &packet_number, sizeof(int), ZMQ_SNDMORE) == -1) {
    return -1;
  }
  if (zmq_send(wirego_h->zsock, src, sizeof(src), ZMQ_SNDMORE) == -1) {
    return -1;
  }
  if (zmq_send(wirego_h->zsock, dst, sizeof(dst), ZMQ_SNDMORE) == -1) {
    return -1;
  }
  if (zmq_send(wirego_h->zsock, layer, sizeof(layer), ZMQ_SNDMORE) == -1) {
    return -1;
  }
  if (zmq_send(wirego_h->zsock, packet, packet_size, 0) == -1) {
    return -1;
  }
  ws_warning("waiting detection_heuristic response...");

  //Frame 0 contains detection result (byte)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  resp = zmq_msg_data(&msg);
  if (size != 1) {
    zmq_msg_close (&msg);
    return -1;
  }
  detection_result = resp[0];
  zmq_msg_close (&msg);


  ws_warning("detection_heuristic %d", detection_result);
  return detection_result;
}

int wirego_dissect_packet_cb(wirego_t* wirego_h, int packet_number, char* src, char* dst, char* layer, char* packet, int packet_size) {
  if (src == NULL || dst == NULL || layer == NULL || packet == NULL || packet_size == 0) {
    return -1;
  }

  const char cmd[] = "dissect_packet";
  char* resp;
  int size;
  zmq_msg_t msg;
  int dissect_handler = -1;
 
  
  ws_warning("sending dissect_packet request ...");
  
  if (zmq_send(wirego_h->zsock, (void*)(cmd), sizeof(cmd), ZMQ_SNDMORE) == -1) {
    return -1;
  }
  if (zmq_send(wirego_h->zsock, &packet_number, sizeof(int), ZMQ_SNDMORE) == -1) {
    return -1;
  }
  if (zmq_send(wirego_h->zsock, src, sizeof(src), ZMQ_SNDMORE) == -1) {
    return -1;
  }
  if (zmq_send(wirego_h->zsock, dst, sizeof(dst), ZMQ_SNDMORE) == -1) {
    return -1;
  }
  if (zmq_send(wirego_h->zsock, layer, sizeof(layer), ZMQ_SNDMORE) == -1) {
    return -1;
  }
  if (zmq_send(wirego_h->zsock, packet, packet_size, 0) == -1) {
    return -1;
  }
  ws_warning("waiting dissect_packet response...");

  //Frame 0 contains detection result (byte)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  resp = zmq_msg_data(&msg);
  if (size != 4) {
    zmq_msg_close (&msg);
    return -1;
  }
  dissect_handler = *((int*)(resp));
  zmq_msg_close (&msg);


  ws_warning("dissect_packet %d", dissect_handler);
  return dissect_handler;
}


char* wirego_result_get_protocol_cb(wirego_t* wirego_h, int dissect_handle){
  const char cmd[] = "result_get_protocol";
  char* resp;
  int size;
  zmq_msg_t msg;

  char* protocol = NULL;
  
  ws_warning("sending result_get_protocol request ...");
  
  if (zmq_send(wirego_h->zsock, (void*)(cmd), sizeof(cmd), ZMQ_SNDMORE) == -1) {
    return NULL;
  }
  if (zmq_send(wirego_h->zsock, &dissect_handle, sizeof(int), 0) == -1) {
    return NULL;
  }
  ws_warning("waiting result_get_protocol response...");

  //Frame 0 contains protocol (string)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  resp = zmq_msg_data(&msg);
  if ((size == 0) || (resp[size-1] != 0x00)) {
    zmq_msg_close (&msg);
    return NULL;
  }
  protocol = (char*) calloc(size, 1);
  strcpy(protocol, resp);


  ws_warning("result_get_protocol(%d) %s", idx, protocol);
  return protocol;
}

char* wirego_result_get_info_cb(wirego_t* wirego_h, int dissect_handle){
  const char cmd[] = "result_get_info";
  char* resp;
  int size;
  zmq_msg_t msg;

  char* info = NULL;
  
  ws_warning("sending result_get_info request ...");
  
  if (zmq_send(wirego_h->zsock, (void*)(cmd), sizeof(cmd), ZMQ_SNDMORE) == -1) {
    return NULL;
  }
  if (zmq_send(wirego_h->zsock, &dissect_handle, sizeof(int), 0) == -1) {
    return NULL;
  }
  ws_warning("waiting result_get_info response...");

  //Frame 0 contains info (string)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  resp = zmq_msg_data(&msg);
  if ((size == 0) || (resp[size-1] != 0x00)) {
    zmq_msg_close (&msg);
    return NULL;
  }
  info = (char*) calloc(size, 1);
  strcpy(info, resp);


  ws_warning("result_get_info(%d) %s", idx, info);
  return protocol;
}

int wirego_result_get_fields_count_cb(wirego_t* wirego_h, int dissect_handle){

}

void wirego_result_get_field_cb(wirego_t* wirego_h, int dissect_handle, int idx, int* parent_idx, int* wirego_field_id, int* offset, int* length) {

}

void wirego_result_release_cb(wirego_t* wirego_h, int dissect_handle){

}

