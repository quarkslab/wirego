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
char* wirego_detect_int_cb(int*, int);
char* wirego_detect_string_cb(char**, int);
char* wirego_detect_heuristic_cb(int);


/*
extern int (*wirego_detection_heuristic_cb)(int, char *, char *, char*, char*, int);
extern int (*wirego_dissect_packet_cb)(int, char *, char *, char*, char*, int);
extern char* (*wirego_result_get_protocol_cb)(int);
extern char* (*wirego_result_get_info_cb)(int);
extern int (*wirego_result_get_fields_count_cb)(int);
extern void (*wirego_result_get_field_cb)(int, int, int*, int*, int*, int*);
extern void (*wirego_result_release_cb)(int);

*/

#endif