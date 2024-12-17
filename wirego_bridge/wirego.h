#ifndef _WIREGO_H_
#define _WIREGO_H_

//Map our go plugin internal field identifiers to the ones provided by Wireshark
typedef struct {
  int wirego_field_id;
  int wireshark_field_id;
} field_id_to_plugin_field_id_t;


typedef struct _wirego {
  int loaded;
  char * zmq_endpoint;
  void * zctx;
  void * zsock;

  //Wireshark internals
  int ett_wirego;
  int fields_count;
  int proto_wirego;
  field_id_to_plugin_field_id_t * fields_mapping;

} wirego_t;

wirego_t * get_wirego_h(void);
int get_wireshark_field_id_from_wirego_field_id(int wirego_field_id);

#endif