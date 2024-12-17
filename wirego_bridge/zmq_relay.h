#ifndef _ZMQ_RELAY_H_
#define _ZMQ_RELAY_H_

#include "wirego.h"


//Utility ZMQ functions
int wirego_zmq_ping(wirego_t *wirego_h);

//ZMQ relay commands to Wirego plugin
int wirego_version_cb(wirego_t *wirego_h, int *major, int*minor);
char * wirego_get_name_cb(wirego_t *wirego_h);
int wirego_get_fields_count_cb(wirego_t *wirego_h);
int wirego_get_field_cb(wirego_t *wirego_h, int idx, int *wirego_field_id, char** name, char** filter, int *value_type, int *display);
char* wirego_get_plugin_filter_cb(wirego_t *wirego_h);
char* wirego_detect_int_cb(wirego_t *wirego_h, int *filter_value, int idx);
char* wirego_detect_string_cb(wirego_t *wirego_h, char** filter_value, int idx);
char* wirego_detect_heuristic_parent_cb(wirego_t *wirego_h, int idx);

int wirego_detection_heuristic_cb(wirego_t *wirego_h, int packet_number, char * src, char * dst, char* layer, char* packet, int packet_size);
int wirego_dissect_packet_cb(wirego_t *wirego_h, int, char *, char *, char*, char*, int);
char* wirego_result_get_protocol_cb(wirego_t *wirego_h, int);
char* wirego_result_get_info_cb(wirego_t *wirego_h, int);
int wirego_result_get_fields_count_cb(wirego_t *wirego_h, int);
void wirego_result_get_field_cb(wirego_t *wirego_h, int, int, int*, int*, int*, int*);
void wirego_result_release_cb(wirego_t *wirego_h, int);


#endif