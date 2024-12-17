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

static wirego_t wirego_h;

int get_wireshark_field_id_from_wirego_field_id(int wirego_field_id);

//Register protocol when plugin is loaded.
void proto_register_wirego(void) {
  memset(&wirego_h, 0x00, sizeof(wirego_t));

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

  wirego_h.zctx = zmq_ctx_new();
  wirego_h.zsock = zmq_socket(wirego_h.zctx, ZMQ_REQ);
  if (wirego_h.zsock == NULL) {
    ws_warning("Wirego: failed to create ZMQ socket (%s)\n",zmq_strerror (errno));
    return;
  }

  //Connect to remote Wirego plugin
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

  ws_warning("Remote Wirego version: %d.%d", vmajor, vminor);

  if ((vmajor != WIREGO_VERSION_MAJOR) || (vminor != WIREGO_VERSION_MINOR)) {
    ws_warning("Wireshark plugin (%d.%d) and remote Wirego versions differs (%d.%d)", WIREGO_VERSION_MAJOR, WIREGO_VERSION_MINOR, vmajor, vminor);
  }

  //---
    //Setup a list of "header fields" (hf)
  static hf_register_info *hfx;

  //Ask plugin how many custom fields are declared
  wirego_h.fields_count = wirego_get_fields_count_cb(&wirego_h);
  hfx = (hf_register_info*) malloc(wirego_h.fields_count * sizeof(hf_register_info));
  wirego_h.fields_mapping = (field_id_to_plugin_field_id_t *) malloc(wirego_h.fields_count * sizeof(field_id_to_plugin_field_id_t));

  for (int i = 0; i < wirego_h.fields_count; i++) {
    int wirego_field_id;
    char *name;
    char *filter;
    int value_type;
    int display;

    //Fetch field
    wirego_get_field_cb(&wirego_h, i, &wirego_field_id, &name, &filter, &value_type, &display);

    //Convert field to wireshark
    wirego_h.fields_mapping[i].wirego_field_id = wirego_field_id;
    wirego_h.fields_mapping[i].wireshark_field_id = -1;
    hfx[i].p_id = &(wirego_h.fields_mapping[i].wireshark_field_id);
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
      &wirego_h.ett_wirego
  };

  //Register the plugin (long name, short name, filter)
  static char long_name[255];
  char * name = wirego_get_name_cb(&wirego_h);
  
  snprintf(long_name, 255, "%s (Wirego v%d.%d)", name, vmajor, vminor);
  //Wireshark will directly store the returns strings into internal structures and tables.
  wirego_h.proto_wirego = proto_register_protocol(long_name, name, wirego_get_plugin_filter_cb(&wirego_h));
  //Don't release name and filter, since those are used by wireshark's internals
  //Register our custom fields
  proto_register_field_array(wirego_h.proto_wirego, hfx, wirego_h.fields_count);

  //Register the protocol subtree
  proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_wirego(void) {

}


//Convert a field id, as provided by the Golang plugin to a Wireshark filed id,
//as returned by wireshark backend during declaration
int get_wireshark_field_id_from_wirego_field_id(int wirego_field_id) {
  for (int idx = 0; idx < wirego_h.fields_count; idx++) {
    if (wirego_h.fields_mapping[idx].wirego_field_id == wirego_field_id) {
      return wirego_h.fields_mapping[idx].wireshark_field_id;
    }
  }
  return -1; 
}