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

int wirego_plugin_loaded(void);
int wirego_load_plugin(char *plugin_path);


#endif