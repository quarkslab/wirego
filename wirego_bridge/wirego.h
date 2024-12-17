#ifndef _WIREGO_H_
#define _WIREGO_H_

typedef struct _wirego {
  char * zmq_endpoint;
  void * zctx;
  void * zsock;
} wirego_t;

#endif