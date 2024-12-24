#include "zmq_relay.h"
#include <zmq.h>
#include <wsutil/wslog.h>

/*
  This is the Wirego's ZMQ protocol implementation. 
  For any details concernning commands, arguments and encoding types, please refer to the dedicated specification.
*/

//Reads a C-String from a msg. Returns an allocated pointer or NULL
char * read_string_from_msg(zmq_msg_t *msg, int size) {
  char* resp = zmq_msg_data(msg);
  if ((size == 0) || (resp[size-1] != 0x00)) {
    return NULL;
  }
  return strdup(resp);
}

//Reads a 32 bits integer from a msg, to val. Returns 0 on success and -1 on failure.
int read_int_from_msg(zmq_msg_t *msg, int size, int *val) {
  char *resp = zmq_msg_data(msg);
  if (size != 4) {
    *val = 0;
    return -1;
  }
  *val = *(int*)resp;
  return 0;
}

//Reads a byte from a msg, to val. Returns 0 on success and -1 on failure.
int read_byte_from_msg(zmq_msg_t *msg, int size, char *val) {
  char *resp = zmq_msg_data(msg);
  if (size != 1) {
    *val = 0;
    return -1;
  }
  *val = resp[0];
  return 0;
}

//wirego_utility_get_version asks remote ZMQ endpoint for its version
//Returns 0 on success and -1 on failure.
int wirego_utility_get_version(wirego_t* wirego_h, int *major, int*minor) {
  const char cmd[] = "utility_get_version";
  int size;
  zmq_msg_t msg;
  char b;
  int ret;
  char status;
  *major = 0;
  *minor = 0;
  ws_noisy("sending utility_get_version ...");
  
  if (zmq_send(wirego_h->zsock, (void*)(cmd), sizeof(cmd), 0) == -1) {
    return -1;
  }
  ws_noisy("waiting utility_get_version response...");

  //Read REP status (1 byte)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_byte_from_msg(&msg, size, &status);
  zmq_msg_close (&msg);
  if ((ret == -1) || (status == 0)) {
    return -1;
  }

  //Frame 1 contains major version (1 byte)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_byte_from_msg(&msg, size, &b);
  zmq_msg_close (&msg);
  *major = b;
  if (ret == -1) {
    return -1;
  }

  //Frame 2 contains minor version (1 byte)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_byte_from_msg(&msg, size, &b);
  zmq_msg_close (&msg);
  *minor = b;
  if (ret == -1) {
    return -1;
  }
  
  return 0;
}

//wirego_utility_ping send a ping to a remote ZMQ endpoint and hope for a reply
//Returns 0 on success and -1 on failure.
int wirego_utility_ping(wirego_t* wirego_h) {
  const char ping_cmd[] = "utility_ping";
  char status;
  zmq_msg_t msg;
  int size;
  int ret;
  ws_noisy("sending utility_ping...");
  
  if (zmq_send(wirego_h->zsock, (void*)(ping_cmd), sizeof(ping_cmd), 0) == -1) {
    return -1;
  }
  ws_noisy("waiting utility_ping response...");

  //Read REP status (1 byte)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_byte_from_msg(&msg, size, &status);
  zmq_msg_close (&msg);
  if ((ret == -1) || (status == 0)) {
    return -1;
  }

  return 0;
}

//wirego_setup_get_plugin_name asks for the remote ZMQ endpoint for it's name
//Returns allocated string containing name or NULL
char* wirego_setup_get_plugin_name(wirego_t* wirego_h) {
  const char cmd[] = "setup_get_plugin_name";
  char* name = NULL;
  char status;
  zmq_msg_t msg;
  int size;
  int ret;
  ws_noisy("sending setup_get_plugin_name...");
  
  if (zmq_send(wirego_h->zsock, (void*)(cmd), sizeof(cmd), 0) == -1) {
    return NULL;
  }
  ws_noisy("waiting setup_get_plugin_name response...");

  //Read REP status (1 byte)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_byte_from_msg(&msg, size, &status);
  zmq_msg_close (&msg);
  if ((ret == -1) || (status == 0)) {
    return NULL;
  }

  //Frame 1 contains name (string)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  name = read_string_from_msg(&msg, size);
  zmq_msg_close (&msg);

  if (name)
    ws_noisy("setup_get_plugin_name %s",name);

  return name;
}


//wirego_setup_get_plugin_filter asks the remote ZMQ endpoint for its filter
//Returns allocated string with filter or NULL
char* wirego_setup_get_plugin_filter(wirego_t* wirego_h){
  const char cmd[] = "setup_get_plugin_filter";
  char*filter = NULL;
  char status;
  zmq_msg_t msg;
  int size;
  int ret;

  ws_noisy("sending setup_get_plugin_filter...");
  
  if (zmq_send(wirego_h->zsock, (void*)(cmd), sizeof(cmd), 0) == -1) {
    return filter;
  }
  ws_noisy("waiting setup_get_plugin_filter response...");

  //Read REP status (1 byte)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_byte_from_msg(&msg, size, &status);
  zmq_msg_close (&msg);
  if ((ret == -1) || (status == 0)) {
    return NULL;
  }

  //Frame 1 contains filter (string)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  filter = read_string_from_msg(&msg, size);
  zmq_msg_close (&msg);

  if (filter)
    ws_noisy("setup_get_plugin_filter %s",filter);

  return filter;
}

//wirego_setup_get_fields_count asks the remote ZMQ endpoint for the number of custom fields to be declared
int wirego_setup_get_fields_count(wirego_t* wirego_h) {
  const char cmd[] = "setup_get_fields_count";
  int size;
  zmq_msg_t msg;
  int fields_count = -1;
  int ret;
  char status;

  ws_noisy("sending setup_get_fields_count request ...");
  
  if (zmq_send(wirego_h->zsock, (void*)(cmd), sizeof(cmd), 0) == -1) {
    return -1;
  }
  ws_noisy("waiting setup_get_fields_count response...");

  //Read REP status (1 byte)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_byte_from_msg(&msg, size, &status);
  zmq_msg_close (&msg);
  if ((ret == -1) || (status == 0)) {
    return -1;
  }

  //Frame 1 contains fields count (4 bytes / little endian)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_int_from_msg(&msg, size, &fields_count);
  zmq_msg_close (&msg);

  if (ret == -1)
    return -1;

  ws_noisy("setup_get_fields_count %d",fields_count);

  return fields_count;
}

//wirego_setup_get_field asks the remote ZMQ endpoint for the details about field number "idx"
int wirego_setup_get_field(wirego_t* wirego_h, int idx, int *wirego_field_id, char** name, char** filter, int *value_type, int *display) {
  const char cmd[] = "setup_get_field";
  int size;
  int ret;
  zmq_msg_t msg;
  char status;

  *wirego_field_id = -1;
  *name = NULL;
  *filter = NULL;
  *value_type = -1;
  *display = -1;
 
  ws_noisy("sending setup_get_field request ...");
  
  if (zmq_send(wirego_h->zsock, (void*)(cmd), sizeof(cmd), ZMQ_SNDMORE) == -1) {
    return -1;
  }
  if (zmq_send(wirego_h->zsock, &idx, sizeof(int), 0) == -1) {
    return -1;
  }
  ws_noisy("waiting setup_get_field response...");

  //Read REP status (1 byte)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_byte_from_msg(&msg, size, &status);
  zmq_msg_close (&msg);
  if ((ret == -1) || (status == 0)) {
    return -1;
  }

  //Frame 1 contains field id (int)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_int_from_msg(&msg, size, wirego_field_id);
  zmq_msg_close (&msg);
  if (ret == -1) {
    return -1;
  }

  //Frame 2 contains field name (c string)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  *name = read_string_from_msg(&msg, size);
  zmq_msg_close (&msg);
  if (!*name) {
    return -1;    
  }


  //Frame 3 contains field filter (c string)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  *filter = read_string_from_msg(&msg, size);
  zmq_msg_close (&msg);
  if (!*filter) {
    free(*name);
    *name = NULL;
    return -1;    
  }

  //Frame 4 contains value type (int)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_int_from_msg(&msg, size, value_type);
  zmq_msg_close (&msg);
  if (ret == -1) {
    free(*name);
    *name = NULL;
    free(*filter);
    *filter = NULL;
    return -1;
  }

  //Frame 5 contains display type (int)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_int_from_msg(&msg, size, display);
  zmq_msg_close (&msg);
  if (ret == -1) {
    free(*name);
    *name = NULL;
    free(*filter);
    *filter = NULL;
    return -1;
  }

  ws_noisy("setup_get_field(%d) Field id:%d Name: %s Filter: %s Vtype %d Display %d", idx, *wirego_field_id, *name, *filter, *value_type, *display);

  return 0;
}

//wirego_setup_detect_int asks the remote ZMQ endpoint for the detection filter of type "int" with given index
char* wirego_setup_detect_int(wirego_t* wirego_h, int *filter_value, int idx) {
  const char cmd[] = "setup_detect_int";
  int ret;
  int size;
  zmq_msg_t msg;
  char status;
  char* filter = NULL;
  *filter_value = -1;
  
  ws_noisy("sending setup_detect_int request ...");
  
  if (zmq_send(wirego_h->zsock, (void*)(cmd), sizeof(cmd), ZMQ_SNDMORE) == -1) {
    return NULL;
  }
  if (zmq_send(wirego_h->zsock, &idx, sizeof(int), 0) == -1) {
    return NULL;
  }
  ws_noisy("waiting setup_detect_int response...");

  //Read REP status (1 byte)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_byte_from_msg(&msg, size, &status);
  zmq_msg_close (&msg);
  if ((ret == -1) || (status == 0)) {
    return NULL;
  }

  //Frame 1 contains filter string (string)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  filter = read_string_from_msg(&msg, size);
  zmq_msg_close (&msg);
  if (!filter) {
    return NULL;    
  }

  //Frame 2 contains match value (int)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_int_from_msg(&msg, size, filter_value);
  zmq_msg_close (&msg);
  if (ret == -1) {
    free(filter);
    return NULL;
  }

  ws_noisy("setup_detect_int(%d) %s = %d", idx, filter, *filter_value);

  return filter;
}

char* wirego_setup_detect_string(wirego_t* wirego_h,  char**filter_value, int idx) {
  const char cmd[] = "setup_detect_string";
  int size;
  zmq_msg_t msg;
  char status;
  char* filter = NULL;
  int ret;

  *filter_value = NULL;
  
  ws_noisy("sending setup_detect_string request ...");
  
  if (zmq_send(wirego_h->zsock, (void*)(cmd), sizeof(cmd), ZMQ_SNDMORE) == -1) {
    return NULL;
  }
  if (zmq_send(wirego_h->zsock, &idx, sizeof(int), 0) == -1) {
    return NULL;
  }
  ws_noisy("waiting setup_detect_string response...");

  //Read REP status (1 byte)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_byte_from_msg(&msg, size, &status);
  zmq_msg_close (&msg);
  if ((ret == -1) || (status == 0)) {
    return NULL;
  }

  //Frame 1 contains filter string (string)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  filter = read_string_from_msg(&msg, size);
  zmq_msg_close (&msg);
  if (!filter) {
    return NULL;    
  }

  //Frame 2 contains match value (string)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  *filter_value = read_string_from_msg(&msg, size);
  zmq_msg_close (&msg);
  if (!*filter_value) {
    free(filter);
    return NULL;    
  }

  ws_noisy("setup_detect_string(%d) %s = %s", idx, filter, *filter_value);

  return filter;
}

char* wirego_setup_detect_heuristic_parent(wirego_t* wirego_h, int idx) {
  const char cmd[] = "setup_detect_heuristic_parent";
  int size;
  zmq_msg_t msg;
  char status;
  char* parent_protocol = NULL;
  int ret;

  ws_noisy("sending setup_detect_heuristic_parent request ...");
  
  if (zmq_send(wirego_h->zsock, (void*)(cmd), sizeof(cmd), ZMQ_SNDMORE) == -1) {
    return NULL;
  }
  if (zmq_send(wirego_h->zsock, &idx, sizeof(int), 0) == -1) {
    return NULL;
  }
  ws_noisy("waiting setup_detect_heuristic_parent response...");

  //Read REP status (1 byte)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_byte_from_msg(&msg, size, &status);
  zmq_msg_close (&msg);
  if ((ret == -1) || (status == 0)) {
    return NULL;
  }

  //Frame 1 contains parent_protocol (string)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  parent_protocol = read_string_from_msg(&msg, size);
  zmq_msg_close (&msg);
  if (!parent_protocol) {
    return NULL;    
  }

  ws_noisy("setup_detect_heuristic_parent(%d) %s", idx, parent_protocol);
  return parent_protocol;
}

// wirego_process_heuristic returns 0 on detection success, -1 on failure or no detection
int wirego_process_heuristic(wirego_t* wirego_h, int packet_number, char* src, char* dst, char* layer, const char* packet, int packet_size) {
  if (src == NULL || dst == NULL || layer == NULL || packet == NULL || packet_size == 0) {
    return -1;
  }

  const char cmd[] = "process_heuristic";
  int size;
  zmq_msg_t msg;
  int detection_result = -1;
  char b;
  int ret;
  char status;

  ws_noisy("sending process_heuristic request ...");
  
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
  ws_noisy("waiting process_heuristic response...");

  //Read REP status (1 byte)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_byte_from_msg(&msg, size, &status);
  zmq_msg_close (&msg);
  if ((ret == -1) || (status == 0)) {
    return -1;
  }

  //Frame 1 contains detection result (byte)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_byte_from_msg(&msg, size, &b);
  zmq_msg_close (&msg);

  if (ret == -1) {
    return -1;
  }
  detection_result = b;

  ws_noisy("process_heuristic %d", detection_result);
  return detection_result;
}

int wirego_process_dissect_packet(wirego_t* wirego_h, int packet_number, char* src, char* dst, char* layer, const char* packet, int packet_size) {
  const char cmd[] = "process_dissect_packet";
  int size;
  zmq_msg_t msg;
  int dissect_handler = -1;
  char status;
  int ret;

  if (src == NULL || dst == NULL || layer == NULL || packet == NULL || packet_size == 0) {
    return -1;
  }

  
  ws_noisy("sending process_dissect_packet request ...");
  
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
  ws_noisy("waiting process_dissect_packet response...");

  //Read REP status (1 byte)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_byte_from_msg(&msg, size, &status);
  zmq_msg_close (&msg);
  if ((ret == -1) || (status == 0)) {
    return -1;
  }

  //Frame 1 contains a dissect handler (int)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_int_from_msg(&msg, size, &dissect_handler);
  if (ret == -1) {
    return -1;
  }
  zmq_msg_close (&msg);

  ws_noisy("process_dissect_packet %d", dissect_handler);
  return dissect_handler;
}


char* wirego_result_get_protocol(wirego_t* wirego_h, int dissect_handle){
  const char cmd[] = "result_get_protocol";
  int size;
  zmq_msg_t msg;
  char* protocol = NULL;
  char status;
  int ret;

  ws_noisy("sending result_get_protocol request ...");
  
  if (zmq_send(wirego_h->zsock, (void*)(cmd), sizeof(cmd), ZMQ_SNDMORE) == -1) {
    return NULL;
  }
  if (zmq_send(wirego_h->zsock, &dissect_handle, sizeof(int), 0) == -1) {
    return NULL;
  }
  ws_noisy("waiting result_get_protocol response...");

  //Read REP status (1 byte)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_byte_from_msg(&msg, size, &status);
  zmq_msg_close (&msg);
  if ((ret == -1) || (status == 0)) {
    return NULL;
  }

  //Frame 1 contains protocol (string)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  protocol = read_string_from_msg(&msg, size);
  zmq_msg_close (&msg);
  if (!protocol) {
    return NULL;    
  }

  ws_noisy("result_get_protocol(%d) %s", dissect_handle, protocol);
  return protocol;
}

char* wirego_result_get_info(wirego_t* wirego_h, int dissect_handle){
  const char cmd[] = "result_get_info";
  int size;
  zmq_msg_t msg;
  char* info = NULL;
  char status;
  int ret;

  ws_noisy("sending result_get_info request ...");
  
  if (zmq_send(wirego_h->zsock, (void*)(cmd), sizeof(cmd), ZMQ_SNDMORE) == -1) {
    return NULL;
  }
  if (zmq_send(wirego_h->zsock, &dissect_handle, sizeof(int), 0) == -1) {
    return NULL;
  }
  ws_noisy("waiting result_get_info response...");

  //Read REP status (1 byte)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_byte_from_msg(&msg, size, &status);
  zmq_msg_close (&msg);
  if ((ret == -1) || (status == 0)) {
    return NULL;
  }

  //Frame 1 contains info (string)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  info = read_string_from_msg(&msg, size);
  zmq_msg_close (&msg);
  if (!info) {
    return NULL;    
  }

  ws_noisy("result_get_info(%d) %s", dissect_handle, info);
  return info;
}

int wirego_result_get_fields_count(wirego_t* wirego_h, int dissect_handle){
  const char cmd[] = "result_get_fields_count";
  int size;
  zmq_msg_t msg;
  int ret;
  int count = -1;
  char status;
  
  ws_noisy("sending result_get_fields_count request ...");
  
  if (zmq_send(wirego_h->zsock, (void*)(cmd), sizeof(cmd), ZMQ_SNDMORE) == -1) {
    return -1;
  }
  if (zmq_send(wirego_h->zsock, &dissect_handle, sizeof(int), 0) == -1) {
    return -1;
  }
  ws_noisy("waiting result_get_fields_count response...");

  //Read REP status (1 byte)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_byte_from_msg(&msg, size, &status);
  zmq_msg_close (&msg);
  if ((ret == -1) || (status == 0)) {
    return -1;
  }

  //Frame 1 contains info (string)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_int_from_msg(&msg, size, &count);
  zmq_msg_close (&msg);

  if (ret == -1)
    return -1;
  ws_noisy("result_get_fields_count(%d) %d", dissect_handle, count);
  return count;
}

int wirego_result_get_field(wirego_t* wirego_h, int dissect_handle, int idx, int* parent_idx, int* wirego_field_id, int* offset, int* length) {
  const char cmd[] = "result_get_field";
  int size;
  zmq_msg_t msg;
  int ret;
  char status;

  *parent_idx = -1;
  *wirego_field_id = -1;
  *offset = -1;
  *length = -1;
  
  ws_noisy("sending result_get_field request ...");
  
  if (zmq_send(wirego_h->zsock, (void*)(cmd), sizeof(cmd), ZMQ_SNDMORE) == -1) {
    return -1;
  }
  if (zmq_send(wirego_h->zsock, &dissect_handle, sizeof(int), ZMQ_SNDMORE) == -1) {
    return -1;
  }  if (zmq_send(wirego_h->zsock, &idx, sizeof(int), 0) == -1) {
    return -1;
  }
  ws_noisy("waiting result_get_field response...");

  //Read REP status (1 byte)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_byte_from_msg(&msg, size, &status);
  zmq_msg_close (&msg);
  if ((ret == -1) || (status == 0)) {
    return -1;
  }

  //Frame 1 contains field parent_idx (int)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_int_from_msg(&msg, size, parent_idx);
  zmq_msg_close (&msg);
  if (ret == -1)
    return -1;

  //Frame 2 contains field wirego_field_id (int)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_int_from_msg(&msg, size, wirego_field_id);
  zmq_msg_close (&msg);
  if (ret == -1)
    return -1;

  //Frame 3 contains field offset (int)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_int_from_msg(&msg, size, offset);
  zmq_msg_close (&msg);
  if (ret == -1)
    return -1;

  //Frame 4 contains field length (int)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_int_from_msg(&msg, size, length);
  zmq_msg_close (&msg);
  if (ret == -1)
    return -1;

  ws_noisy("result_get_field(%d, %d) parent_idx %d wirego_field_id %d offs %d length %d", dissect_handle, idx, *parent_idx, *wirego_field_id, *offset, *length);
  return 0;
}

int wirego_result_release(wirego_t* wirego_h, int dissect_handle){
  const char cmd[] = "result_release";
  int size;
  zmq_msg_t msg;
  char b;
  char status;
  int ret;

  ws_noisy("sending result_release request ...");
  
  if (zmq_send(wirego_h->zsock, (void*)(cmd), sizeof(cmd), ZMQ_SNDMORE) == -1) {
    return -1;
  }
  if (zmq_send(wirego_h->zsock, &dissect_handle, sizeof(int), 0) == -1) {
    return -1;
  }
  ws_noisy("waiting result_release response...");

  //Read REP status (1 byte)
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_byte_from_msg(&msg, size, &status);
  zmq_msg_close (&msg);
  if ((ret == -1) || (status == 0)) {
    return -1;
  }

  //Frame 1 contains dummy result
  zmq_msg_init (&msg);
	size = zmq_recvmsg(wirego_h->zsock, &msg, 0);
  ret = read_byte_from_msg(&msg, size, &b);
  zmq_msg_close (&msg);
  if (ret == -1)
    return -1;
  ws_noisy("result_release(%d) %d", dissect_handle, b);
  return 0;
}

