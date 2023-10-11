/* packet-wirego.h
 *
 * Wirego plugin for golang integration by Benoit Girard
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "config.h"
#include <stdlib.h>
#include <dlfcn.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>
#include <wsutil/str_util.h>
#include "packet-wirego.h"

void proto_register_wirego(void);
void proto_reg_handoff_wirego(void);
static int dissect_wirego(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_);



//static dissector_handle_t wirego_handle;
static int proto_wirego = -1;

//Fields names
static int hf_wirego_pdu_type = -1;
static int hf_wirego_field2_type = -1;

//WireGo's subtree
static int ett_wirego  = -1;

//Golang wrapper
static void * plugin_h = NULL;
static int (*wirego_version_major_cb)(void) = NULL;
static int (*wirego_version_minor_cb)(void) = NULL;
static char* (*wirego_plugin_name_cb)(void) = NULL;
static char* (*wirego_plugin_filter_cb)(void) = NULL;
static char* (*wirego_detect_int_cb)(int*) = NULL;



int wirego_load_plugin(char *plugin_path) {
  if (plugin_h != NULL)
    return -1;
  
  //Open shared library
  plugin_h = dlopen(plugin_path, RTLD_LAZY);
  if (plugin_h == NULL) {
    printf("Failed to load plugin %s\n", plugin_path);
    return -1;
  }

  //Setup callbacks to the golang plugin
  wirego_version_major_cb = (int (*) (void)) dlsym(plugin_h, "wirego_version_major");
  if (wirego_version_major_cb == NULL) {
    printf("Failed to load plugin %s (missing symbol)\n", plugin_path);
    return -1;
  }

  wirego_version_minor_cb = (int (*) (void)) dlsym(plugin_h, "wirego_version_minor");
  if (wirego_version_minor_cb == NULL) {
    printf("Failed to load plugin %s (missing symbol)\n", plugin_path);
    return -1;
  }

  wirego_plugin_name_cb = (char* (*) (void)) dlsym(plugin_h, "wirego_plugin_name");
  if (wirego_plugin_name_cb == NULL) {
    printf("Failed to load plugin %s (missing symbol)\n", plugin_path);
    return -1;
  }

  wirego_plugin_filter_cb = (char* (*) (void)) dlsym(plugin_h, "wirego_plugin_filter");
  if (wirego_plugin_filter_cb == NULL) {
    printf("Failed to load plugin %s (missing symbol)\n", plugin_path);
    return -1;
  }

  wirego_detect_int_cb = (char* (*) (int*)) dlsym(plugin_h, "wirego_detect_int");
  if (wirego_detect_int_cb == NULL) {
    printf("Failed to load plugin %s (missing symbol)\n", plugin_path);
    return -1;
  }

  return 0;
}

//Register protocol when plugin is loaded.
void proto_register_wirego(void) {

  //Retrive golang plugin from env variable
  char * golang_plugin_path = NULL;
  golang_plugin_path = getenv("WIREGO_PLUGIN");
  if (golang_plugin_path == NULL) {
    printf("WIREGO_PLUGIN not set.\n");
    return;
  }

  //Load the golang plugin
  if (wirego_load_plugin(golang_plugin_path) == -1) {
    return;
  }

  printf("Wirego version: %d.%d\n", wirego_version_major_cb(), wirego_version_minor_cb());

  //Setup a list of "header fields" (hf)
  static hf_register_info hf[] = {
        { &hf_wirego_pdu_type,  //Field id that will be set on register
            { 
              "WireGo PDU Type", // Field name
              "wirego.type", // Filter name
              FT_UINT8, // Value type
              BASE_DEC, // Display mode
              NULL, // Strings
              0x0, // Bitmask
              NULL, // Description
              HFILL  // (macro to fill all remaining fields)
            }
        },
        { &hf_wirego_field2_type,  //Field id that will be set on register
            { 
              "WireGo field 2", // Field name
              "wirego.field2", // Filter name
              FT_UINT32, // Value type
              BASE_HEX, // Display mode
              NULL, // Strings
              0x0, // Bitmask
              NULL, // Description
              HFILL  // (macro to fill all remaining fields)
            }
        }
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_wirego
    };

  //Register the plugin (long name, short name, filter)
  static char long_name[255];
  char * name = wirego_plugin_name_cb();
  
  memset(long_name, 0x00, 255);
  snprintf(long_name, 255, "%s (Wirego v%d.%d)", name, wirego_version_major_cb(), wirego_version_minor_cb());
  proto_wirego = proto_register_protocol(long_name, name, wirego_plugin_filter_cb());
  //Don't release name and filter, since those are used by wireshark's internals

  //Register our custom fields
  proto_register_field_array(proto_wirego, hf, array_length(hf));

  //Register the protocol subtree
  proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_wirego(void) {
  static dissector_handle_t wirego_handle;

  if (plugin_h == NULL) 
    return;
    
  //Register dissector
  wirego_handle = create_dissector_handle(dissect_wirego, proto_wirego);

  //Set dissector filter (int)
  int filter_value;
  char *filter_name;
  filter_name = wirego_detect_int_cb(&filter_value);
  if (filter_name != NULL) {
    dissector_add_uint(filter_name, filter_value, wirego_handle);
    printf("Registered dissector: %s = %d\n", filter_name, filter_value);
    free(filter_name);
  }

}

static int
dissect_wirego(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  //Flag protocol name
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "WireGo");

  //Fill "info" column
  //col_clear(pinfo->cinfo,COL_INFO);
  col_set_str(pinfo->cinfo, COL_INFO, "Hello world.");

  //Add a subtree on this packet
  proto_item *ti = proto_tree_add_item(tree, proto_wirego, tvb, 0, -1, ENC_BIG_ENDIAN);

  int start_offset = 0;
  proto_tree *wirego_tree = proto_item_add_subtree(ti, ett_wirego);

  //proto_tree_add_item(proto_tree *tree, int hfindex, tvbuff_t *tvb, const gint start, gint length, const guint encoding)
  
  proto_tree_add_item(wirego_tree, hf_wirego_pdu_type, tvb, start_offset, 1, ENC_BIG_ENDIAN);
  start_offset += 1;
  proto_tree_add_item(wirego_tree, hf_wirego_field2_type, tvb, start_offset, 4, ENC_BIG_ENDIAN);
  start_offset += 4;
  return tvb_captured_length(tvb);
}

