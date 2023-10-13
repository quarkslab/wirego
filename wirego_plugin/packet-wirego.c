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

//WireGo's subtree
static int ett_wirego  = -1;

//Golang wrapper
static void * plugin_h = NULL;
static int (*wirego_setup_cb)(void) = NULL;
static int (*wirego_version_major_cb)(void) = NULL;
static int (*wirego_version_minor_cb)(void) = NULL;
static char* (*wirego_plugin_name_cb)(void) = NULL;
static char* (*wirego_plugin_filter_cb)(void) = NULL;
static char* (*wirego_detect_int_cb)(int*) = NULL;
static int (*wirego_get_fields_count_cb)(void) = NULL;
static int (*wirego_get_field_cb)(int, int*, char**, char**, int *, int*) = NULL;


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

  wirego_detect_int_cb = (char* (*) (int*)) dlsym(plugin_h, "wirego_detect_int");
  if (wirego_detect_int_cb == NULL) {
    return wirego_load_failure_helper("Failed to find symbol wirego_detect_int");
  }

  wirego_get_fields_count_cb = (int (*) (void)) dlsym(plugin_h, "wirego_get_fields_count");
  if (wirego_get_fields_count_cb == NULL) {
    return wirego_load_failure_helper("Failed to find symbol wirego_get_fields_count");
  }

  wirego_get_field_cb = (int (*) (int, int*, char**, char**, int*, int*)) dlsym(plugin_h, "wirego_get_field");
  if (wirego_get_field_cb == NULL) {
    return wirego_load_failure_helper("Failed to find symbol wirego_get_field");
  }


  //Init plugin
  if (wirego_setup_cb() == -1) {
    return wirego_load_failure_helper("Plugin setup failed");
  }
  return 0;
}

//Map our go plugin internal field identifiers to the ones provided by Wireshark
typedef struct {
  int internal_id;
  int external_id;
} field_id_to_plugin_field_id_t;
field_id_to_plugin_field_id_t * fields_mapping = NULL;

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
  static hf_register_info *hfx;
  int fields_count = wirego_get_fields_count_cb();
  hfx = (hf_register_info*) malloc(fields_count * sizeof(hf_register_info));
  fields_mapping = (field_id_to_plugin_field_id_t *) malloc(fields_count * sizeof(field_id_to_plugin_field_id_t));

  for (int i = 0; i < fields_count; i++) {
    int internal_id;
    char *name;
    char *filter;
    int value_type;
    int display;
  

    wirego_get_field_cb(i, &internal_id, &name, &filter, &value_type, &display);

    fields_mapping[i].internal_id = internal_id;
    fields_mapping[i].external_id = -1;
    hfx[i].p_id = &(fields_mapping[i].external_id);
    hfx[i].hfinfo.name = name;
    hfx[i].hfinfo.abbrev = filter;
    switch (value_type) {
      case 0x01:
        hfx[i].hfinfo.type = FT_NONE;
      break;
      case 0x02:
        hfx[i].hfinfo.type = FT_BOOLEAN;
      break;
      case 0x03:
        hfx[i].hfinfo.type = FT_UINT8;
      break;
      case 0x04:
        hfx[i].hfinfo.type = FT_INT8;
      break;
      case 0x05:
        hfx[i].hfinfo.type = FT_UINT16;
      break;
      case 0x06:
        hfx[i].hfinfo.type = FT_INT16;
      break;
      case 0x07:
        hfx[i].hfinfo.type = FT_UINT32;
      break;
      case 0x08:
        hfx[i].hfinfo.type = FT_INT32;
      break;
      case 0x09:
        hfx[i].hfinfo.type = FT_STRINGZ;
      break;
      case 0x10:
        hfx[i].hfinfo.type = FT_STRING;   
      break;             
      default:
      printf("Invalid type: %02x\n", value_type);
        hfx[i].hfinfo.type = FT_NONE;
    };
    switch (display) {
      case 0x01:
        hfx[i].hfinfo.display = BASE_NONE;
      break;
      case 0x02:
        hfx[i].hfinfo.display = BASE_DEC;
      break;
      case 0x03:
        hfx[i].hfinfo.display = BASE_HEX;
      break;
      default:
        hfx[i].hfinfo.display = BASE_HEX;
      break;
    }
    hfx[i].hfinfo.strings = NULL;
    hfx[i].hfinfo.bitmask = 0x00;
    hfx[i].hfinfo.blurb = NULL;

  //HFILL
    hfx[i].hfinfo.id = -1;
    hfx[i].hfinfo.parent = 0;
    hfx[i].hfinfo.ref_type = HF_REF_TYPE_NONE;
    hfx[i].hfinfo.same_name_prev_id = -1;
    hfx[i].hfinfo.same_name_next = NULL;
  }


/*
  static hf_register_info hfx[] = {
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
*/
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
  proto_register_field_array(proto_wirego, hfx, fields_count);

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
  
  proto_tree_add_item(wirego_tree, fields_mapping[0].external_id, tvb, start_offset, 1, ENC_BIG_ENDIAN);
  start_offset += 1;
  proto_tree_add_item(wirego_tree, fields_mapping[1].external_id, tvb, start_offset, 4, ENC_BIG_ENDIAN);
  start_offset += 4;
  return tvb_captured_length(tvb);
}

