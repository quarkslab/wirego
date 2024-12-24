#include "preferences.h"
#include <stdio.h>
#include <epan/prefs.h>
#include <wsutil/report_message.h>
#include <wsutil/wslog.h>
#include <epan/proto.h>


//ZMQ Endpoint
static const gchar* pref_wirego_zmq_endpoint = "";


/*
  Since we need to connect to the Wirego plugin in order to fetch several parameters 
  during initialization, we can't simply rely on the Wireshark parameters mechanism.
  Parameters are loaded once all plugins are initialized, hence the ZMQ endpoint value 
  will be made available too late.

  The last configured value in the parameters is saved on a local hidden file.
*/

// get_zmq_endpoint reads the last configured endpoint from the save file
char * get_zmq_endpoint(void) {
  char config_path[1024];
  static char zmq_endpoint[1024];
  FILE * f;
  memset(zmq_endpoint, 0x00, 1024);
  char * home = getenv("HOME");

  if (!home) 
    return "";

  snprintf(config_path, 1024, "%s/.wirego", home);
  f = fopen(config_path, "r");
  if (!f)
    return "";

  unsigned long r = fread(zmq_endpoint, 1, 1024, f);
  fclose(f);

  //Drop eventual trailing
  if (r && zmq_endpoint[r-1] == 0x0a)
    zmq_endpoint[r-1] = 0x00;
  return zmq_endpoint;
}

// save_zmq_endpoint updated the save file with the current configured endpoint
int save_zmq_endpoint(const char * zmq_endpoint) {
  FILE * f;
  char config_path[1024];
  char * home = getenv("HOME");
  snprintf(config_path, 1024, "%s/.wirego", home);
  f = fopen(config_path, "w");
  if (!f)
    return -1;
  fwrite(zmq_endpoint, 1, strlen(zmq_endpoint), f);
  fclose(f);
  return 0;
}

// preferences_apply_cb is called by wireshark when the Wirego's preferences are updated or loaded
void preferences_apply_cb(void) {
  char * zmq_endpoint = get_zmq_endpoint();

  //Set default value
  if (strlen(zmq_endpoint) == 0) {
    save_zmq_endpoint("tcp://localhost:1234");
  }

  //If value loaded from wireshark's prefs is different than ours, update
  if (strcmp(zmq_endpoint, pref_wirego_zmq_endpoint)) {
    save_zmq_endpoint(pref_wirego_zmq_endpoint);
    ws_warning("Wirego: Updated zmq_endpoint to %s\n",pref_wirego_zmq_endpoint);
  }
}

// register_preferences_menu defines the Wirego preferences panel
void register_preferences_menu(void) {
  module_t *wirego_module;
  int proto_main_wirego = proto_register_protocol("Wirego", "Wirego", "wirego");
  wirego_module = prefs_register_protocol(proto_main_wirego, preferences_apply_cb);

	prefs_register_string_preference(wirego_module, "zmq_endpoint",
					   "Wirego ZMQ Endpoint",
					   "ZMQ Endpoint shared with your wirego plugin",
					   &pref_wirego_zmq_endpoint);

  prefs_register_static_text_preference(wirego_module, "helper",
        "You will need to restart Wireshark after changing the ZMQ Endpoint.",
        "");

}