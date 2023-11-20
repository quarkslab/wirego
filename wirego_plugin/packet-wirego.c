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
#include <arpa/inet.h>
#include "plugin-loader.h"
#include "packet-wirego.h"

void proto_register_wirego(void);
void proto_reg_handoff_wirego(void);
static int dissect_wirego(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_);
void register_preferences_menu(void);
char * get_plugin_path(void);

//static dissector_handle_t wirego_handle;
static int proto_wirego = -1;

//WireGo's subtree
static int ett_wirego  = -1;



//Map our go plugin internal field identifiers to the ones provided by Wireshark
typedef struct {
  int internal_id;
  int external_id;
} field_id_to_plugin_field_id_t;

int fields_count = -1;
field_id_to_plugin_field_id_t * fields_mapping = NULL;

//Register protocol when plugin is loaded.
void proto_register_wirego(void) {

  //Register preferences menu (actually more a helper to an actual pref)
  register_preferences_menu();

  //Retrive golang plugin from env variable
  char * golang_plugin_path = get_plugin_path();

  if ((golang_plugin_path == NULL) || (!strlen(golang_plugin_path))) {
    printf("Wirego: $HOME/.wirego does not exist\n");
    return;
  }

  //Load the golang plugin
  if (wirego_load_plugin(golang_plugin_path) == -1) {
    return;
  }

  printf("Wirego version: %d.%d\n", wirego_version_major_cb(), wirego_version_minor_cb());

  //Setup a list of "header fields" (hf)
  static hf_register_info *hfx;

  //Ask plugin how many custom fields are declared
  fields_count = wirego_get_fields_count_cb();
  hfx = (hf_register_info*) malloc(fields_count * sizeof(hf_register_info));
  fields_mapping = (field_id_to_plugin_field_id_t *) malloc(fields_count * sizeof(field_id_to_plugin_field_id_t));

  for (int i = 0; i < fields_count; i++) {
    int internal_id;
    char *name;
    char *filter;
    int value_type;
    int display;

    //Fetch field
    wirego_get_field_cb(i, &internal_id, &name, &filter, &value_type, &display);

    //Convert field to wireshark
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

char * get_plugin_path(void) {
  char config_path[1024];
  static char plugin_path[1024];
  FILE * f;
  memset(config_path, 0x00, 1024);
  memset(plugin_path, 0x00, 1024);
  char * home = getenv("HOME");
  snprintf(config_path, 1023, "%s/.wirego", home);

  f = fopen(config_path, "r");
  if (!f)
    return "";

  unsigned long r = fread(plugin_path, 1, 1024, f);
  fclose(f);
  if (r && plugin_path[r-1] == 0x0a)
    plugin_path[r-1] = 0x00;
  return plugin_path;
}

void register_preferences_menu(void) {
  module_t *wirego_module;
  static char current_config[1024];
  char * current_plugin_path = NULL;

  int proto_main_wirego = proto_register_protocol("Wirego", "Wirego", "wirego");

  wirego_module = prefs_register_protocol(proto_main_wirego, NULL);
  current_plugin_path = get_plugin_path();

  memset(current_config, 0x00, 1024);
  if (strlen(current_plugin_path) != 0)
    snprintf(current_config, 1023, "Current configuration is: %s", current_plugin_path);
  else    
    snprintf(current_config, 1023, "Current configuration is not set)");

  prefs_register_static_text_preference(wirego_module, "helper",
        "Edit $HOME/.wirego to set the path to the golang plugin",
        "Wirego configuraiton file contains the fullpath to the wirego golang plugin");

  prefs_register_static_text_preference(wirego_module, "path",
        current_config,
        "Wirego configuraiton file contains the fullpath to the wirego golang plugin");

}


void proto_reg_handoff_wirego(void) {
  static dissector_handle_t wirego_handle;
  char *filter_name;

  if (!wirego_is_plugin_loaded()) 
    return;
    
  //Register dissector
  wirego_handle = create_dissector_handle(dissect_wirego, proto_wirego);

  //Set dissector filter (int)
  int idx = 0;
  while (1) {
    int filter_value;
    filter_name = wirego_detect_int_cb(&filter_value, idx);

    if (filter_name == NULL)
      break;
    dissector_add_uint(filter_name, filter_value, wirego_handle);
    free(filter_name);
    idx++;
  }

  //Set dissector filter (string)
  idx = 0;
  while (1) {
    char* filter_value_str;
    filter_name = wirego_detect_string_cb(&filter_value_str, idx);
    if (filter_name == NULL)
      break;
    dissector_add_string(filter_name, filter_value_str, wirego_handle);
    free(filter_name);
    idx++;
  }
}

static int
dissect_wirego(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  /*
    In a more classic Wireshark plugin we would use all the tvb_* accessors here
    Since processing of the packet is performed in the golang plugin (that's actually the very purpose
    of this insanity), and since I won't write bindings for the complete wireshark API, we need to push
    the packet buffer to the plugin.

    We have two options here:

      - use tvb_get_ptr
      - use tvb_memcpy
    
    The get_ptr would be the more obvious, but it is marked as very dangerous. Since this buffer would be pushed 
    to a golang plugin it could eventually be even more dangerous.
    Thus we're using tvb_memcpy, which will provide us a dedicated buffer to play with.
    That's not optimal at all, but we'll start with this.
  */
  int pdu_len = tvb_reported_length(tvb);

  if (pdu_len <= 0)
    return 0;

/*

  printf("Type: %d ", pinfo->net_src.type);
  if (pinfo->net_src.len == 4) {
    unsigned int addr = *((unsigned int*)pinfo->net_src.data);
    
    printf("%d.%d.%d.%d", addr &0xFF, (addr>>8)&0xFF, (addr>>16)&0xFF, (addr>>24)&0xFF);
  }
  printf("\n");
*/
  
  //Very suboptimal, FIXME.
  char * golang_buff = (char*) malloc(pdu_len);
  char src[255];
  char dst[255];
  src[0] = 0x00;
  dst[0] = 0x00;

  switch (pinfo->net_src.type) {
    case AT_IPv4:
      inet_ntop(AF_INET, pinfo->net_src.data, src, 255);
      break;
    case AT_IPv6:
      inet_ntop(AF_INET6, pinfo->net_src.data, src, 255);
      break;
    case AT_ETHER:
    sprintf(src, "%02x:%02x:%02x:%02x:%02x:%02x", ((const char*)pinfo->net_src.data)[0]&0xFF, 
    ((const char*)pinfo->net_src.data)[1]&0xFF,
    ((const char*)pinfo->net_src.data)[2]&0xFF,
    ((const char*)pinfo->net_src.data)[3]&0xFF,
    ((const char*)pinfo->net_src.data)[4]&0xFF,
    ((const char*)pinfo->net_src.data)[5]&0xFF);
    break;
  }
  switch (pinfo->net_dst.type) {
    case AT_IPv4:
      inet_ntop(AF_INET, pinfo->net_dst.data, dst, 255);
      break;
    case AT_IPv6:
      inet_ntop(AF_INET6, pinfo->net_dst.data, dst, 255);
      break;
          case AT_ETHER:
      sprintf(dst, "%02x:%02x:%02x:%02x:%02x:%02x", ((const char*)pinfo->net_dst.data)[0]&0xFF, 
      ((const char*)pinfo->net_dst.data)[1]&0xFF,
      ((const char*)pinfo->net_dst.data)[2]&0xFF,
      ((const char*)pinfo->net_dst.data)[3]&0xFF,
      ((const char*)pinfo->net_dst.data)[4]&0xFF,
      ((const char*)pinfo->net_dst.data)[5]&0xFF);
    break;
  }

  //Compile network stack
  unsigned int full_layer_size = 512;
  char * full_layer = malloc(full_layer_size *sizeof(char));
	wmem_list_frame_t *protos = wmem_list_head(pinfo->layers);
	int	    proto_id;
	const char *name;
	while (protos != NULL)
	{
		proto_id = GPOINTER_TO_INT(wmem_list_frame_data(protos));
		name = proto_get_protocol_filter_name(proto_id);

    if (strlen(full_layer) + 1 + strlen(name) + 1 >= full_layer_size) {
      full_layer_size += 512 + 1 + strlen(name);
      full_layer = realloc(full_layer, full_layer_size);
    }
		strcat(full_layer, name);
    strcat(full_layer, ".");
		protos = wmem_list_frame_next(protos);
	}
  //Strip trailing '.'
  if (strlen(full_layer))
    full_layer[strlen(full_layer) - 1] = 0x00;

  tvb_memcpy(tvb, golang_buff, 0, pdu_len);
  int handle = wirego_dissect_packet_cb(src, dst, full_layer, golang_buff, pdu_len);
  free(golang_buff);
  golang_buff = NULL;
  free(full_layer);
  full_layer = NULL;

  //Flag protocol name
  col_set_str(pinfo->cinfo, COL_PROTOCOL, wirego_result_get_protocol_cb(handle));

  //Fill "info" column
  col_set_str(pinfo->cinfo, COL_INFO, wirego_result_get_info_cb(handle));

  int result_fields_count = wirego_result_get_fields_count_cb(handle);

  if (result_fields_count != 0) {
    //Add a subtree on this packet
    proto_item *ti = proto_tree_add_item(tree, proto_wirego, tvb, 0, -1, ENC_BIG_ENDIAN);
    proto_tree *wirego_tree = proto_item_add_subtree(ti, ett_wirego);

    for (int i = 0; i < result_fields_count; i++) {
      int external_id = -1;
      int internal_id;
      int offset;
      int length;
      wirego_result_get_field_cb(handle, i, &internal_id, &offset, &length);
      for (int j = 0; j < fields_count; j++) {
        if (fields_mapping[j].internal_id == internal_id) {
          external_id = fields_mapping[j].external_id;
          break;
        }
      }
      if (external_id != -1) {
        proto_tree_add_item(wirego_tree, external_id, tvb, offset, length, ENC_BIG_ENDIAN);
      }
    }

  }
  wirego_result_release_cb(handle);

  return tvb_captured_length(tvb);
}

