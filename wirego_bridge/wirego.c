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

static wirego_t wirego_h;

//Register protocol when plugin is loaded.
void proto_register_wirego(void) {
  memset(&wirego_h, 0x00, sizeof(wirego_t));

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

/*
  int vmajor = wirego_version_major_cb(&wirego_h);
  int vminor = wirego_version_minor_cb(&wirego_h);
  */
  ws_warning("Remote Wirego version: %d.%d", vmajor, vminor);

  if ((vmajor != WIREGO_VERSION_MAJOR) || (vminor != WIREGO_VERSION_MINOR)) {
    ws_warning("Wireshark plugin (%d.%d) and remote Wirego versions differs (%d.%d)", WIREGO_VERSION_MAJOR, WIREGO_VERSION_MINOR, vmajor, vminor);
  }
}

void proto_reg_handoff_wirego(void) {

}
