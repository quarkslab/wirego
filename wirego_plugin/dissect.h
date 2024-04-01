#ifndef _DISSECT_H_
#define _DISSECT_H_

#include <epan/dissectors/packet-tcp.h>


int dissect_wirego(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);


#endif