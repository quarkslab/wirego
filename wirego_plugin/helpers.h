#ifndef _HELPERS_H_
#define _HELPERS_H_

#include <epan/packet.h>

void extract_adresses_from_packet_info(packet_info *pinfo, char *src, char *dst);
char * compile_network_stack(packet_info *pinfo);
field_display_e field_display_type_to_ws(int dtype);
enum ftenum field_value_type_to_ws(int vtype);

#endif
