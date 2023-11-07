
#include "plugin-loader.h"
#include "config.h"
#include <stdio.h>
#include <dlfcn.h>

void * plugin_h = NULL;
int (*wirego_setup_cb)(void) = NULL;
int (*wirego_version_major_cb)(void) = NULL;
int (*wirego_version_minor_cb)(void) = NULL;
char* (*wirego_plugin_name_cb)(void) = NULL;
char* (*wirego_plugin_filter_cb)(void) = NULL;
char* (*wirego_detect_int_cb)(int*, int) = NULL;
char* (*wirego_detect_string_cb)(char**, int) = NULL;
int (*wirego_get_fields_count_cb)(void) = NULL;
int (*wirego_get_field_cb)(int, int*, char**, char**, int *, int*) = NULL;
int (*wirego_dissect_packet_cb)(char *, char*, char*, int) = NULL;
int (*wirego_result_release_cb)(int) = NULL;
char* (*wirego_result_get_protocol_cb)(int) = NULL;
char* (*wirego_result_get_info_cb)(int) = NULL;
int (*wirego_result_get_fields_count_cb)(int) = NULL;
void (*wirego_result_get_field_cb)(int, int, int*, int*, int*) = NULL;


int wirego_is_plugin_loaded(void) {
  return plugin_h?1:0;
}

int wirego_load_failure_helper(const char *str) {
  printf("%s", str);
  dlclose(plugin_h);
  plugin_h = NULL;
  return -1;
}

int wirego_load_plugin(char *plugin_path) {
  if (plugin_h != NULL)
    return -1;
  
  //Open shared library
  plugin_h = dlopen(plugin_path, RTLD_LAZY);
  if (plugin_h == NULL) {
    return wirego_load_failure_helper("Failed to open plugin");
  }

  //Setup callbacks to the golang plugin
  wirego_version_major_cb = (int (*) (void)) dlsym(plugin_h, "wirego_version_major");
  if (wirego_version_major_cb == NULL) {
    return wirego_load_failure_helper("Failed to find symbol wirego_version_major");
  }

  wirego_version_minor_cb = (int (*) (void)) dlsym(plugin_h, "wirego_version_minor");
  if (wirego_version_minor_cb == NULL) {
    return wirego_load_failure_helper("Failed to find symbol wirego_version_minor");
  }

  wirego_setup_cb = (int (*) (void)) dlsym(plugin_h, "wirego_setup");
  if (wirego_setup_cb == NULL) {
    return wirego_load_failure_helper("Failed to find symbol wirego_setup");
  }

  wirego_plugin_name_cb = (char* (*) (void)) dlsym(plugin_h, "wirego_plugin_name");
  if (wirego_plugin_name_cb == NULL) {
    return wirego_load_failure_helper("Failed to find symbol wirego_plugin_name");
  }

  wirego_plugin_filter_cb = (char* (*) (void)) dlsym(plugin_h, "wirego_plugin_filter");
  if (wirego_plugin_filter_cb == NULL) {
    return wirego_load_failure_helper("Failed to find symbol wirego_plugin_filter");
  }

  wirego_detect_int_cb = (char* (*) (int*, int)) dlsym(plugin_h, "wirego_detect_int");
  if (wirego_detect_int_cb == NULL) {
    return wirego_load_failure_helper("Failed to find symbol wirego_detect_int");
  }

  wirego_detect_string_cb = (char* (*) (char**, int)) dlsym(plugin_h, "wirego_detect_string");
  if (wirego_detect_string_cb == NULL) {
    return wirego_load_failure_helper("Failed to find symbol wirego_detect_string");
  }

  wirego_get_fields_count_cb = (int (*) (void)) dlsym(plugin_h, "wirego_get_fields_count");
  if (wirego_get_fields_count_cb == NULL) {
    return wirego_load_failure_helper("Failed to find symbol wirego_get_fields_count");
  }

  wirego_get_field_cb = (int (*) (int, int*, char**, char**, int*, int*)) dlsym(plugin_h, "wirego_get_field");
  if (wirego_get_field_cb == NULL) {
    return wirego_load_failure_helper("Failed to find symbol wirego_get_field");
  }

  wirego_dissect_packet_cb = (int (*) (char*, char*, char*, int)) dlsym(plugin_h, "wirego_dissect_packet");
  if (wirego_dissect_packet_cb == NULL) {
    return wirego_load_failure_helper("Failed to find symbol wirego_dissect_packet");
  }

  wirego_result_release_cb = (int (*) (int)) dlsym(plugin_h, "wirego_result_release");
  if (wirego_result_release_cb == NULL) {
    return wirego_load_failure_helper("Failed to find symbol wirego_result_release");
  }

  wirego_result_get_protocol_cb = (char* (*) (int)) dlsym(plugin_h, "wirego_result_get_protocol");
  if (wirego_result_get_protocol_cb == NULL) {
    return wirego_load_failure_helper("Failed to find symbol wirego_result_get_protocol");
  }

  wirego_result_get_info_cb = (char* (*) (int)) dlsym(plugin_h, "wirego_result_get_info");
  if (wirego_result_get_info_cb == NULL) {
    return wirego_load_failure_helper("Failed to find symbol wirego_result_get_info");
  }

  wirego_result_get_fields_count_cb = (int (*) (int)) dlsym(plugin_h, "wirego_result_get_fields_count");
  if (wirego_result_get_fields_count_cb == NULL) {
    return wirego_load_failure_helper("Failed to find symbol wirego_result_get_fields_count");
  }

  wirego_result_get_field_cb = (void (*) (int, int, int*, int*, int*)) dlsym(plugin_h, "wirego_result_get_field");
  if (wirego_result_get_field_cb == NULL) {
    return wirego_load_failure_helper("Failed to find symbol wirego_result_get_field");
  }

  //Init plugin
  if (wirego_setup_cb() == -1) {
    return wirego_load_failure_helper("Plugin setup failed");
  }

  return 0;
}


