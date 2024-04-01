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
#include "preferences.h"
#include "dissect.h"
#include "helpers.h"

void proto_register_wirego(void);
void proto_reg_handoff_wirego(void);
void extract_adresses_from_packet_info(packet_info *pinfo, char *src, char *dst);


//WireGo's subtree
int ett_wirego  = -1;
int fields_count = -1;
int proto_wirego = -1;

field_id_to_plugin_field_id_t * fields_mapping = NULL;


//Convert a field id, as provided by the Golang plugin to a Wireshark filed id,
//as returned by wireshark backend during declaration
int get_wireshark_field_id_from_wirego_field_id(int wirego_field_id) {
  for (int idx = 0; idx < fields_count; idx++) {
    if (fields_mapping[idx].wirego_field_id == wirego_field_id) {
      return fields_mapping[idx].wireshark_field_id;
    }
  }
  return -1; 
}


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
ws_warning("registered %d fields", fields_count);
  //Register the protocol subtree
  proto_register_subtree_array(ett, array_length(ett));
}


static gboolean wirego_heuristic_check(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  int pdu_len;
  char * golang_buff = NULL;
  char src[255];
  char dst[255];
  char * full_layer = NULL;
  int detected;

  if (!tvb || !pinfo)
    return -1;

  pdu_len = tvb_reported_length(tvb);
  if (pdu_len <= 0)
    return 0;

  src[0] = 0x00;
  dst[0] = 0x00;
  extract_adresses_from_packet_info(pinfo, src, dst);


  full_layer = compile_network_stack(pinfo);

  //Pass everything to the golang plugin
  golang_buff = (char*) malloc(pdu_len);
  tvb_memcpy(tvb, golang_buff, 0, pdu_len);
  detected = wirego_detection_heuristic_cb(pinfo->num, src, dst, full_layer, golang_buff, pdu_len);
  free(golang_buff);
  golang_buff = NULL;
  free(full_layer);
  full_layer = NULL;

  if (detected == 0)
    return FALSE;
  
  dissect_wirego(tvb, pinfo, tree, data);
  return TRUE;
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

  //Set dissector heuristic
  idx = 0;
  while (1) {
    char* parent_protocol_str;
    parent_protocol_str = wirego_detect_heuristic_cb(idx);
    if (parent_protocol_str == NULL)
      break;
    heur_dissector_add(parent_protocol_str, wirego_heuristic_check, "Wirego", "wirego_tcp", proto_wirego, HEURISTIC_ENABLE);
    free(parent_protocol_str);
    idx++;
  }

}
