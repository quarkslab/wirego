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

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>
#include <wsutil/str_util.h>
#include <wsutil/report_message.h>
#include <wsutil/wslog.h>
#include <wsutil/to_str.h>

#include "plugin-loader.h"
#include "packet-wirego.h"

void proto_register_wirego(void);
void proto_reg_handoff_wirego(void);
static int dissect_wirego(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_);
void register_preferences_menu(void);
char * get_plugin_path(void);
enum ftenum field_value_type_to_ws(int vtype);
field_display_e field_display_type_to_ws(int dtype);
int get_wireshark_field_id_from_wirego_field_id(int wirego_field_id);
char * compile_network_stack(packet_info *pinfo);
void pinfo_to_proto_stack(packet_info *pinfo, char *src, char *dst);

static int proto_wirego = -1;

//WireGo's subtree
static int ett_wirego  = -1;

//Plugin path
static const gchar* pref_wirego_config_filename = "";



//Map our go plugin internal field identifiers to the ones provided by Wireshark
typedef struct {
  int wirego_field_id;
  int wireshark_field_id;
} field_id_to_plugin_field_id_t;

int fields_count = -1;
field_id_to_plugin_field_id_t * fields_mapping = NULL;

//Register protocol when plugin is loaded.
void proto_register_wirego(void) {

  //Register preferences menu (used to set the golang plugin path)
  register_preferences_menu();

  //Retrive golang plugin from env variable
  char * golang_plugin_path = get_plugin_path();

  if ((golang_plugin_path == NULL) || (!strlen(golang_plugin_path))) {
    ws_warning("Wirego: plugin path is not set\n");
    return;
  }

  //Load the golang plugin
  if (wirego_load_plugin(golang_plugin_path) == -1) {
    ws_warning("Wirego failed to load the golang plugin at %s", golang_plugin_path);
    report_failure("Wirego failed to load the golang plugin at %s", golang_plugin_path);
    return;
  }

  ws_warning("Wirego version: %d.%d\n", wirego_version_major_cb(), wirego_version_minor_cb());

  //Setup a list of "header fields" (hf)
  static hf_register_info *hfx;

  //Ask plugin how many custom fields are declared
  fields_count = wirego_get_fields_count_cb();
  hfx = (hf_register_info*) malloc(fields_count * sizeof(hf_register_info));
  fields_mapping = (field_id_to_plugin_field_id_t *) malloc(fields_count * sizeof(field_id_to_plugin_field_id_t));

  for (int i = 0; i < fields_count; i++) {
    int wirego_field_id;
    char *name;
    char *filter;
    int value_type;
    int display;

    //Fetch field
    wirego_get_field_cb(i, &wirego_field_id, &name, &filter, &value_type, &display);

    //Convert field to wireshark
    fields_mapping[i].wirego_field_id = wirego_field_id;
    fields_mapping[i].wireshark_field_id = -1;
    hfx[i].p_id = &(fields_mapping[i].wireshark_field_id);
    hfx[i].hfinfo.name = name;
    hfx[i].hfinfo.abbrev = filter;
    hfx[i].hfinfo.type = field_value_type_to_ws(value_type);
    hfx[i].hfinfo.display = field_display_type_to_ws(display);
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
  
  snprintf(long_name, 255, "%s (Wirego v%d.%d)", name, wirego_version_major_cb(), wirego_version_minor_cb());
  //Wireshark will directly store the returns strings into internal structures and tables.
  proto_wirego = proto_register_protocol(long_name, name, wirego_plugin_filter_cb());
  //Don't release name and filter, since those are used by wireshark's internals
  //Register our custom fields
  proto_register_field_array(proto_wirego, hfx, fields_count);

  //Register the protocol subtree
  proto_register_subtree_array(ett, array_length(ett));
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
    free(filter_value_str);
    free(filter_name);
    idx++;
  }
}

static int
dissect_wirego(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  int pdu_len;
  char * golang_buff = NULL;
  char src[255];
  char dst[255];
  char * full_layer = NULL;
  int dissectHandle = -1;
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


  if (!tvb || !pinfo)
    return -1;

  pdu_len = tvb_reported_length(tvb);
  if (pdu_len <= 0)
    return 0;

  src[0] = 0x00;
  dst[0] = 0x00;
  pinfo_to_proto_stack(pinfo, src, dst);


  full_layer = compile_network_stack(pinfo);

  //Pass everything to the golang plugin
  golang_buff = (char*) malloc(pdu_len);
  tvb_memcpy(tvb, golang_buff, 0, pdu_len);
  dissectHandle = wirego_dissect_packet_cb(pinfo->num, src, dst, full_layer, golang_buff, pdu_len);
  free(golang_buff);
  golang_buff = NULL;
  free(full_layer);
  full_layer = NULL;

  if (dissectHandle == -1) {
    //col_set_str will keep a pointer to the given value
    //while col_add_str will duplicate
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Wirego plugin failed.");
    col_set_str(pinfo->cinfo, COL_INFO, "Wirego plugin failed.");
    return -1;
  }

  //Analyse plugin results

  //Flag protocol name
  col_set_str(pinfo->cinfo, COL_PROTOCOL, wirego_result_get_protocol_cb(dissectHandle));

  //Fill "info" column
  col_set_str(pinfo->cinfo, COL_INFO, wirego_result_get_info_cb(dissectHandle));

  //During the first pass, tree can eventually be NULL
  //Wireshark does not ask the plugin to fill detailed structures
  if (tree) {
    //How many custom fields did the plugin return?
    int result_fields_count = wirego_result_get_fields_count_cb(dissectHandle);
    if (result_fields_count != 0) {
      
      //Add a subtree on this packet
      proto_item *ti = proto_tree_add_item(tree, proto_wirego, tvb, 0, -1, ENC_BIG_ENDIAN);
      if (!ti) goto DONE;
      proto_tree *wirego_tree = proto_item_add_subtree(ti, ett_wirego);
      if (!wirego_tree)  goto DONE;

      //Process all custom fields
      for (int i = 0; i < result_fields_count; i++) {
        int wireshark_field_id = -1;
        int wirego_field_id;
        int offset;
        int length;
        //Ask plugin for result
        wirego_result_get_field_cb(dissectHandle, i, &wirego_field_id, &offset, &length);
        //Convert plugin field id to wireshark id
        wireshark_field_id = get_wireshark_field_id_from_wirego_field_id(wirego_field_id);
        //Add tree entry
        if (wireshark_field_id != -1) {
          proto_tree_add_item(wirego_tree, wireshark_field_id, tvb, offset, length, ENC_BIG_ENDIAN);
        }
      }    
    }
  }
DONE:
  wirego_result_release_cb(dissectHandle);
  return tvb_captured_length(tvb);
}



char * get_plugin_path(void) {
  char config_path[1024];
  static char plugin_path[1024];
  FILE * f;
  memset(plugin_path, 0x00, 1024);
  char * home = getenv("HOME");

  if (!home) 
    return "";

  snprintf(config_path, 1024, "%s/.wirego", home);
  f = fopen(config_path, "r");
  if (!f)
    return "";

  unsigned long r = fread(plugin_path, 1, 1024, f);
  fclose(f);
  if (r && plugin_path[r-1] == 0x0a)
    plugin_path[r-1] = 0x00;
  return plugin_path;
}

int save_plugin_path(const char * path) {
  FILE * f;
  char config_path[1024];
  char * home = getenv("HOME");
  snprintf(config_path, 1024, "%s/.wirego", home);
  f = fopen(config_path, "w");
  if (!f)
    return -1;
  fwrite(path, 1, strlen(path), f);
  fclose(f);
  return 0;
}

void preferences_apply_cb(void) {
  if (strcmp(get_plugin_path(), pref_wirego_config_filename)) {
    save_plugin_path(pref_wirego_config_filename);
    ws_warning("Wirego: Updated plugin path to %s\n",pref_wirego_config_filename);
  }
}

// Define the Wirego preferences panel
void register_preferences_menu(void) {
  module_t *wirego_module;
  int proto_main_wirego = proto_register_protocol("Wirego", "Wirego", "wirego");
  wirego_module = prefs_register_protocol(proto_main_wirego, preferences_apply_cb);

	prefs_register_filename_preference(wirego_module, "pluginpath",
					   "Wirego plugin path",
					   "The fullpath to the wirego plugin, written in Go",
					   &pref_wirego_config_filename, FALSE);

  prefs_register_static_text_preference(wirego_module, "helper",
        "You will need to restart Wireshark after changing the plugin path.",
        "");

}


enum ftenum field_value_type_to_ws(int vtype) {
  switch (vtype) {
    case 0x01:
      return FT_NONE;
    break;
    case 0x02:
      return FT_BOOLEAN;
    break;
    case 0x03:
      return FT_UINT8;
    break;
    case 0x04:
      return FT_INT8;
    break;
    case 0x05:
      return FT_UINT16;
    break;
    case 0x06:
      return FT_INT16;
    break;
    case 0x07:
      return FT_UINT32;
    break;
    case 0x08:
      return FT_INT32;
    break;
    case 0x09:
      return FT_STRINGZ;
    break;
    case 0x10:
      return FT_STRING;   
    break;             
    default:
      return FT_NONE;
  };
  return FT_NONE;
}

field_display_e field_display_type_to_ws(int dtype) {
  switch (dtype) {
    case 0x01:
      return BASE_NONE;
    break;
    case 0x02:
      return BASE_DEC;
    break;
    case 0x03:
      return BASE_HEX;
    break;
    default:
      return BASE_NONE;
    break;
  }
  return BASE_NONE;
}


void pinfo_to_proto_stack(packet_info *pinfo, char *src, char *dst) {
  //Very suboptimal, FIXME.

  src[0] = 0x00;
  dst[0] = 0x00;

  if (!pinfo || !pinfo->net_src.data || !pinfo->net_dst.data)
    return;

  switch (pinfo->net_src.type) {
    case AT_IPv4:
      ip_to_str_buf((const guint8*)pinfo->net_src.data, src, 255);
    break;
    case AT_IPv6:
      ip6_to_str_buf((const ws_in6_addr *)pinfo->net_src.data, src, 255);
    break;
    case AT_ETHER:
      sprintf(src, "%02x:%02x:%02x:%02x:%02x:%02x", 
        ((const char*)pinfo->net_src.data)[0]&0xFF, 
        ((const char*)pinfo->net_src.data)[1]&0xFF,
        ((const char*)pinfo->net_src.data)[2]&0xFF,
        ((const char*)pinfo->net_src.data)[3]&0xFF,
        ((const char*)pinfo->net_src.data)[4]&0xFF,
        ((const char*)pinfo->net_src.data)[5]&0xFF);
    break;
  }
  switch (pinfo->net_dst.type) {
    case AT_IPv4:
      ip_to_str_buf((const guint8*)pinfo->net_dst.data, dst, 255);
      break;
    case AT_IPv6:
      ip6_to_str_buf((const ws_in6_addr *)pinfo->net_dst.data, dst, 255);
    break;
    case AT_ETHER:
      sprintf(dst, "%02x:%02x:%02x:%02x:%02x:%02x",
      ((const char*)pinfo->net_dst.data)[0]&0xFF, 
      ((const char*)pinfo->net_dst.data)[1]&0xFF,
      ((const char*)pinfo->net_dst.data)[2]&0xFF,
      ((const char*)pinfo->net_dst.data)[3]&0xFF,
      ((const char*)pinfo->net_dst.data)[4]&0xFF,
      ((const char*)pinfo->net_dst.data)[5]&0xFF);
    break;
  }
}

char * compile_network_stack(packet_info *pinfo) {
  unsigned int full_layer_size = 512;
  char * full_layer = calloc(full_layer_size, sizeof(char));
	wmem_list_frame_t *protos;
	int	    proto_id;
	const char *name;

  if (!pinfo || !pinfo->layers)
    return full_layer;

  protos = wmem_list_head(pinfo->layers);
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

  return full_layer;
}

int get_wireshark_field_id_from_wirego_field_id(int wirego_field_id) {
  for (int idx = 0; idx < fields_count; idx++) {
    if (fields_mapping[idx].wirego_field_id == wirego_field_id) {
      return fields_mapping[idx].wireshark_field_id;
    }
  }
  return -1;  
}

