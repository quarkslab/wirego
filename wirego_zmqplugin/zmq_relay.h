#ifndef _ZMQ_RELAY_H_
#define _ZMQ_RELAY_H_

#include "wirego.h"


int wirego_zmq_ping(wirego_t *wirego_h);

//ZMQ relay commands to Wirego plugin
int wirego_version_major_cb(void);
int wirego_version_minor_cb(void);


#endif