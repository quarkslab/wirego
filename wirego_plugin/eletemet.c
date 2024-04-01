#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>
#include <wsutil/str_util.h>
#include <wsutil/report_message.h>
#include <wsutil/wslog.h>
#include <arpa/inet.h>
#include "plugin-loader.h"
#include "packet-wirego.h"

void proto_register_wirego(void) {

  // Register protocol
  proto_wirego = proto_register_protocol("Wirego Example", "wg example", "wgexample");

  // Register custom fields
  proto_register_field_array(proto_wirego, fields_array, fields_count);
  proto_register_subtree_array(ett, array_length(ett));
}


void proto_reg_handoff_wirego(void) {
  static dissector_handle_t wirego_handle;

  wirego_handle = create_dissector_handle(dissect_wirego, proto_wirego);
  dissector_add_uint("tcp.port", 25, wirego_handle);

}


