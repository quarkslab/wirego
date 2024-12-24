
#include "dissect.h"
#include "helpers.h"
#include "zmq_relay.h"
#include "wirego.h"


void tree_add_item(wirego_t *wirego_h, proto_item *parent_node, int dissectHandle, tvbuff_t *tvb,  int idx, int count);

int dissect_wirego(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  int pdu_len;
  char src[255];
  char dst[255];
  char * full_layer = NULL;
  int dissectHandle = -1;

  wirego_t *wirego_h = get_wirego_h();
 
  if (!tvb || !pinfo)
    return -1;

  pdu_len = tvb_reported_length(tvb);
  if (pdu_len <= 0)
    return 0;

  src[0] = 0x00;
  dst[0] = 0x00;
  extract_adresses_from_packet_info(pinfo, src, dst);


  full_layer = compile_network_stack(pinfo);
  dissectHandle = wirego_process_dissect_packet(wirego_h, pinfo->num, src, dst, full_layer, tvb_get_ptr(tvb, 0, pdu_len), pdu_len);
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
  char * protocol = wirego_result_get_protocol(wirego_h, dissectHandle);
  if (protocol)
    col_set_str(pinfo->cinfo, COL_PROTOCOL, protocol);


  //Fill "info" column
  char * info = wirego_result_get_info(wirego_h, dissectHandle);
  if (info)
    col_set_str(pinfo->cinfo, COL_INFO, info);

  //During the first pass, tree can eventually be NULL
  //Wireshark does not ask the plugin to fill detailed structures
  if (!tree)
    goto DONE;

  //How many custom fields did the plugin return?
  int result_fields_count = wirego_result_get_fields_count(wirego_h, dissectHandle);

  if (result_fields_count <= 0)
    goto DONE;

  //Add a subtree on this packet
  proto_item *ti = proto_tree_add_item(tree, wirego_h->proto_wirego, tvb, 0, -1, ENC_BIG_ENDIAN);
  if (!ti) {
    goto DONE;
  }
  proto_tree *wirego_tree = proto_item_add_subtree(ti, wirego_h->ett_wirego);
  if (!wirego_tree) {
    goto DONE;
  }

  //Process all custom fields

  for (int i = 0; i < result_fields_count; i++) {
    int parent_idx;
    int wirego_field_id;
    int offset;
    int length;


    //Ask plugin for result
    if (wirego_result_get_field(wirego_h, dissectHandle, i, &parent_idx, &wirego_field_id, &offset, &length) == -1)
      break;

    if (parent_idx == -1)
      tree_add_item(wirego_h, wirego_tree, dissectHandle, tvb, i,result_fields_count);
  }

DONE:
  wirego_result_release(wirego_h, dissectHandle);
  return tvb_captured_length(tvb);
}

void tree_add_item(wirego_t *wirego_h, proto_item *parent_node, int dissectHandle, tvbuff_t *tvb,  int idx, int count) {
  int wireshark_field_id = -1;
  int parent_idx;
  int wirego_field_id;
  int offset;
  int length;


  //Ask plugin for result
  wirego_result_get_field(wirego_h, dissectHandle, idx, &parent_idx, &wirego_field_id, &offset, &length);

  //Convert plugin field id to wireshark id
  wireshark_field_id = get_wireshark_field_id_from_wirego_field_id(wirego_field_id);

  //Add tree entry
  if (wireshark_field_id == -1) {
    ws_warning("Wirego plugin returned unknown field id %d, cannot map to Wireshark field id", wirego_field_id);
  return;
  }

  proto_item *sub = proto_tree_add_item(parent_node, wireshark_field_id, tvb, offset, length, ENC_BIG_ENDIAN);


  //look for childs
  proto_tree *subsub = NULL;

  for (int i = 0; i < count; i++) {
    wirego_result_get_field(wirego_h, dissectHandle, i, &parent_idx, &wirego_field_id, &offset, &length);
    if (parent_idx == idx) {
      if (!subsub)
        subsub = proto_item_add_subtree(sub, wirego_h->ett_wirego);
      tree_add_item(wirego_h, sub, dissectHandle, tvb, i, count);
    }
  }
  
}






