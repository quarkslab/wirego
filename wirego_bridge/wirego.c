/* packet-wirego.h
 *
 * Wirego plugin for ZMQ integration by Benoit Girard
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
#define ZMQ_BUILD_DRAFT_API
#include <zmq.h>

#include "wirego.h"
#include "preferences.h"
#include "zmq_relay.h"
#include "version.h"
#include "helpers.h"
#include "dissect.h"

#define ZMQ_TIMEOUT 2*1000

static wirego_t wirego_h;

int wirego_is_plugin_loaded(void);
static gboolean wirego_heuristic_check(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

wirego_t * get_wirego_h(void) {
  return &wirego_h;
}

//Register protocol when plugin is loaded.
void proto_register_wirego(void) {
  //Setup Wirego's structure
  memset(&wirego_h, 0x00, sizeof(wirego_t));
  wirego_h.loaded = 0;
  wirego_h.ett_wirego  = -1;
  wirego_h.fields_count = -1;
  wirego_h.proto_wirego = -1;
  wirego_h.fields_mapping = NULL;

  ws_warning("Wirego starting with czmq %d.%d\n", ZMQ_VERSION_MAJOR, ZMQ_VERSION_MINOR);

  //Register preferences menu (used to set the ZMQ endpoint)
  register_preferences_menu();

  //get ZMQ Endpoint
  wirego_h.zmq_endpoint = get_zmq_endpoint();
  ws_warning("Wirego ZMQ Endpoint set to %s\n", wirego_h.zmq_endpoint);

  //Make sure it's set
  if ((wirego_h.zmq_endpoint == NULL) || (!strlen(wirego_h.zmq_endpoint))) {
    ws_warning("Wirego: ZMQ endpoint not set\n");
    return;
  }

  // Setup ZMQ
  wirego_h.zctx = zmq_ctx_new();
  wirego_h.zsock = zmq_socket(wirego_h.zctx, ZMQ_REQ);
  if (wirego_h.zsock == NULL) {
    ws_warning("Wirego: failed to create ZMQ socket (%s)\n",zmq_strerror (errno));
    return;
  }

  //Setup timeouts in order to make sure that, if the remote plugin is not running, Wireshark does not
  //wait indefinitively for us.
  int timeout_ms = ZMQ_TIMEOUT;
  if (zmq_setsockopt(wirego_h.zsock, ZMQ_CONNECT_TIMEOUT, &timeout_ms, sizeof(timeout_ms)) != 0)
    ws_warning("Wirego: failed to set socket option (timeout)");
  if (zmq_setsockopt(wirego_h.zsock, ZMQ_RCVTIMEO, &timeout_ms, sizeof(timeout_ms)) != 0)
    ws_warning("Wirego: failed to set socket option (rcvtimeout)");
  if (zmq_setsockopt(wirego_h.zsock, ZMQ_SNDTIMEO, &timeout_ms, sizeof(timeout_ms)) != 0)
    ws_warning("Wirego: failed to set socket option (sndtimeout)");


  //Connect to remote Wirego plugin
  //If connection fails, connect will likely return 0
  int ret = zmq_connect(wirego_h.zsock, wirego_h.zmq_endpoint);
  if (ret != 0) {
    ws_warning("Wirego: failed to connect to ZMQ endpoint (%s)\n",zmq_strerror (errno));
    return;
  }

  //Let's ping using ZMQ
  ret = wirego_zmq_ping(&wirego_h);
  if (ret != 0) {
    ws_warning("Wirego: failed to contact ZMQ endpoint (ping)");
    return;
  }
  ws_warning("Wirego: ping success");

  //Check API version
  int vmajor, vminor;
  ret = wirego_version_cb(&wirego_h, &vmajor, &vminor);
  if (ret != 0) {
    ws_warning("Wirego: failed to retrieve remote version");
    return;
  }
  ws_warning("Wirego bridge version: %d.%d", WIREGO_VERSION_MAJOR, WIREGO_VERSION_MINOR);
  ws_warning("Wirego remote version: %d.%d", vmajor, vminor);
  if ((vmajor != WIREGO_VERSION_MAJOR) || (vminor != WIREGO_VERSION_MINOR)) {
    ws_warning("Wirego versions differs, aborting.");
    return;
  }

  //Setup a list of "header fields" (hf)
  static hf_register_info *hfx;

  //Ask plugin how many custom fields are declared
  wirego_h.fields_count = wirego_get_fields_count_cb(&wirego_h);
  if (wirego_h.fields_count == -1) {
    ws_warning("Wirego: failed to retrieve remote fields count");
    return;
  }

  //Setup custom fields list
  hfx = (hf_register_info*) malloc(wirego_h.fields_count * sizeof(hf_register_info));
  wirego_h.fields_mapping = (field_id_to_plugin_field_id_t *) malloc(wirego_h.fields_count * sizeof(field_id_to_plugin_field_id_t));

  for (int i = 0; i < wirego_h.fields_count; i++) {
    int wirego_field_id;
    char *name;
    char *filter;
    int value_type;
    int display;

    //Fetch field
    if (wirego_get_field_cb(&wirego_h, i, &wirego_field_id, &name, &filter, &value_type, &display) == -1) {
      ws_warning("Wirego: failed to retrieve field %d info from remote", i);
      return;
    }

    //Convert field to wireshark
    wirego_h.fields_mapping[i].wirego_field_id = wirego_field_id; //Field id, declared by remote plugin
    wirego_h.fields_mapping[i].wireshark_field_id = -1; // Wireshark field id (will be updated by Wireshark later)
    hfx[i].p_id = &(wirego_h.fields_mapping[i].wireshark_field_id);
    hfx[i].hfinfo.name = name; // Allocated string, given to Wireshark
    hfx[i].hfinfo.abbrev = filter; // Allocated string, given to Wireshark
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
      &wirego_h.ett_wirego
  };

  //Setup plugin's long name
  static char long_name[255];
  char * name = wirego_get_name_cb(&wirego_h);
  if (!name) {
    ws_warning("Failed to retrieve remote Wirego plugin name");
    return;
  }
  snprintf(long_name, 255, "%s (Wirego v%d.%d)", name, vmajor, vminor);

  //Fetch filter name
  char* filter = wirego_get_plugin_filter_cb(&wirego_h);
  if (!filter) {
    ws_warning("Failed to retrieve remote Wirego plugin filter");
    return;
  }

  //Register the plugin (long name, short name, filter)
  //Don't release name and filter, since those are used by wireshark's internals
  wirego_h.proto_wirego = proto_register_protocol(long_name, name, filter);

  //Register our custom fields
  proto_register_field_array(wirego_h.proto_wirego, hfx, wirego_h.fields_count);

  //Register the protocol subtree
  proto_register_subtree_array(ett, array_length(ett));

  // Everything is fine, mark as ready for handoff
  wirego_h.loaded = 1;
}

//proto_reg_handoff_wirego is called by Wireshark once all plugins have been properly registered.
void proto_reg_handoff_wirego(void) {
  static dissector_handle_t wirego_handle;
  char *filter_name;

  //Make sure register succeeded
  if (!wirego_is_plugin_loaded()) 
    return;
  
  //Register dissector
  wirego_handle = create_dissector_handle(dissect_wirego, wirego_h.proto_wirego);

  //Set dissector filter (int)
  int idx = 0;
  while (1) {
    int filter_value;
    filter_name = wirego_detect_int_cb(&wirego_h, &filter_value, idx);

    //Reached last int filter
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
    filter_name = wirego_detect_string_cb(&wirego_h, &filter_value_str, idx);

    //Reached last int filter
    if (filter_name == NULL)
      break;
    dissector_add_string(filter_name, filter_value_str, wirego_handle);
    free(filter_value_str);
    free(filter_name);
    idx++;
  }

  //Set dissector heuristic parents
  idx = 0;
  while (1) {
    char name[64];
    char display_name[128];
    char* parent_protocol_str;
    parent_protocol_str = wirego_detect_heuristic_parent_cb(&wirego_h, idx);

    //Reached last heuristic parent
    if (parent_protocol_str == NULL)
      break;

    snprintf(name, 64, "wirego_heur_%d", idx);
    snprintf(display_name, 128, "%s over %s", wirego_get_name_cb(&wirego_h), parent_protocol_str);

    heur_dissector_add(parent_protocol_str, wirego_heuristic_check, display_name, name, wirego_h.proto_wirego, HEURISTIC_ENABLE);
    free(parent_protocol_str);
    idx++;
  }
}


//get_wireshark_field_id_from_wirego_field_id converts a field id, as provided by the remote plugin to a Wireshark field id,
//as returned by wireshark backend during declaration
int get_wireshark_field_id_from_wirego_field_id(int wirego_field_id) {
  for (int idx = 0; idx < wirego_h.fields_count; idx++) {
    if (wirego_h.fields_mapping[idx].wirego_field_id == wirego_field_id) {
      return wirego_h.fields_mapping[idx].wireshark_field_id;
    }
  }
  return -1; 
}


//wirego_is_plugin_loaded tells if register succeeded
int wirego_is_plugin_loaded(void) {
  return wirego_h.loaded?1:0;
}

// wirego_heuristic_check is called by Wireshark for heuristic detections, everytime one of the registered "heuristic parent"
// is found
static gboolean wirego_heuristic_check(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  int pdu_len;
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
  detected = wirego_detection_heuristic_cb(&wirego_h, pinfo->num, src, dst, full_layer, tvb_get_ptr(tvb, 0, pdu_len), pdu_len);
  free(full_layer);
  full_layer = NULL;

  if (detected == -1)
    return FALSE;
  
  dissect_wirego(tvb, pinfo, tree, data);
  return TRUE;
}