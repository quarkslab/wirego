#ifndef _PLUGIN_LOADER_H_
#define _PLUGIN_LOADER_H_

#include <stdlib.h>

//Golang wrapper
extern int (*wirego_setup_cb)(void);
extern int (*wirego_version_major_cb)(void);
extern int (*wirego_version_minor_cb)(void);
extern char* (*wirego_plugin_name_cb)(void);
extern char* (*wirego_plugin_filter_cb)(void);
extern char* (*wirego_detect_int_cb)(int*);
extern int (*wirego_get_fields_count_cb)(void);
extern int (*wirego_get_field_cb)(int, int*, char**, char**, int *, int*);
extern int (*wirego_dissect_packet_cb)(char*, int);
extern int (*wirego_result_release_cb)(int);
extern char* (*wirego_result_get_protocol_cb)(int);
extern char* (*wirego_result_get_info_cb)(int);
extern int (*wirego_result_get_fields_count_cb)(int);
extern void (*wirego_result_get_field_cb)(int, int, int*, int*, int*);


int wirego_is_plugin_loaded(void);
int wirego_load_plugin(char *plugin_path);


#endif