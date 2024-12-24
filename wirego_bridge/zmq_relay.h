#ifndef _ZMQ_RELAY_H_
#define _ZMQ_RELAY_H_

#include "wirego.h"


//Utility ZMQ functions
int wirego_utility_ping(wirego_t* wirego_h);
int wirego_utility_get_version(wirego_t* wirego_h, int *major, int*minor);

//Wirego setup ZMQ functions
char * wirego_setup_get_plugin_name(wirego_t* wirego_h);
char* wirego_setup_get_plugin_filter(wirego_t* wirego_h);
int wirego_setup_get_fields_count(wirego_t* wirego_h);
int wirego_setup_get_field(wirego_t* wirego_h, int idx, int *wirego_field_id, char** name, char** filter, int *value_type, int *display);
char* wirego_setup_detect_int(wirego_t* wirego_h, int* filter_value, int idx);
char* wirego_setup_detect_string(wirego_t* wirego_h, char** filter_value, int idx);
char* wirego_setup_detect_heuristic_parent(wirego_t* wirego_h, int idx);

//Wirego packet processing ZMQ functions
int wirego_process_heuristic(wirego_t* wirego_h, int packet_number, char* src, char* dst, char* layer, const char* packet, int packet_size);
int wirego_process_dissect_packet(wirego_t* wirego_h, int packet_number, char* src, char* dst, char* layer, const char* packet, int packet_size);

//Wirego result ZMQ functions
char* wirego_result_get_protocol(wirego_t* wirego_h, int dissect_handle);
char* wirego_result_get_info(wirego_t* wirego_h, int dissect_handle);
int wirego_result_get_fields_count(wirego_t* wirego_h, int dissect_handle);
int wirego_result_get_field(wirego_t* wirego_h, int dissect_handle, int idx, int* parent_idx, int* wirego_field_id, int* offset, int* length);
int wirego_result_release(wirego_t* wirego_h, int dissect_handle);


#endif