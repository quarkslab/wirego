#ifndef _HELPERS_H_
#define _HELPERS_H_

#include <epan/packet.h>

#define DISPLAY_ADDR_LEN 255

void extract_adresses_from_packet_info(packet_info *pinfo, char *src, char *dst, uint32_t add_max_len);
char * compile_network_stack(packet_info *pinfo);
field_display_e field_display_type_to_ws(int dtype);
enum ftenum field_value_type_to_ws(int vtype);

#endif
