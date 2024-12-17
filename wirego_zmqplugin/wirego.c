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
#include <czmq.h>

#include "preferences.h"
#include "zmq_relay.h"

//Register protocol when plugin is loaded.
void proto_register_wirego(void) {
  ws_warning("Wirego starting with czmq %d.%d\n", CZMQ_VERSION_MAJOR, CZMQ_VERSION_MINOR);

  //Register preferences menu (used to set the ZMQ endpoint)
  register_preferences_menu();

  //get ZMQ Endpoint
  char * zmq_endpoint = get_zmq_endpoint();
  ws_warning("Wirego ZMQ Endpoint set to %s\n", zmq_endpoint);

  //Make sure it's set
  if ((zmq_endpoint == NULL) || (!strlen(zmq_endpoint))) {
    ws_warning("Wirego: ZMQ endpoint not set\n");
    return;
  }

  ws_warning("Wirego version: %d.%d", wirego_version_major_cb(), wirego_version_minor_cb());

}

void proto_reg_handoff_wirego(void) {

}
