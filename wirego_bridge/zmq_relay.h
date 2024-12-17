#ifndef _ZMQ_RELAY_H_
#define _ZMQ_RELAY_H_

#include "wirego.h"


//Utility ZMQ functions
int wirego_zmq_ping(wirego_t *wirego_h);
int wirego_version_cb(wirego_t *wirego_h, int *major, int*minor);

//ZMQ relay commands to Wirego plugin


#endif