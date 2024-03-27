#include "helpers.h"
#include <wsutil/to_str.h>


//Extract src and dst addresses from packet_info structure. It can be an IPv4, IPv6 or Ethernet address
void extract_adresses_from_packet_info(packet_info *pinfo, char *src, char *dst) {
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

//Try to nuild a relevant network stack string from a packet_info.
//Since this structure is quite complex, we don't really want to try mapping this
//to a full Golang structure (through the C/Go bindings)
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
