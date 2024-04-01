#include "preferences.h"
#include <stdio.h>
#include <epan/prefs.h>
#include <wsutil/report_message.h>
#include <wsutil/wslog.h>
#include <epan/proto.h>


//Plugin path
static const gchar* pref_wirego_config_filename = "";




char * get_plugin_path(void) {
  char config_path[1024];
  static char plugin_path[1024];
  FILE * f;
  memset(plugin_path, 0x00, 1024);
  char * home = getenv("HOME");

  if (!home) 
    return "";

  snprintf(config_path, 1024, "%s/.wirego", home);
  f = fopen(config_path, "r");
  if (!f)
    return "";

  unsigned long r = fread(plugin_path, 1, 1024, f);
  fclose(f);
  if (r && plugin_path[r-1] == 0x0a)
    plugin_path[r-1] = 0x00;
  return plugin_path;
}

int save_plugin_path(const char * path) {
  FILE * f;
  char config_path[1024];
  char * home = getenv("HOME");
  snprintf(config_path, 1024, "%s/.wirego", home);
  f = fopen(config_path, "w");
  if (!f)
    return -1;
  fwrite(path, 1, strlen(path), f);
  fclose(f);
  return 0;
}

void preferences_apply_cb(void) {
  if (strcmp(get_plugin_path(), pref_wirego_config_filename)) {
    save_plugin_path(pref_wirego_config_filename);
    ws_warning("Wirego: Updated plugin path to %s\n",pref_wirego_config_filename);
  }
}

// Define the Wirego preferences panel
void register_preferences_menu(void) {
  module_t *wirego_module;
  int proto_main_wirego = proto_register_protocol("Wirego", "Wirego", "wirego");
  wirego_module = prefs_register_protocol(proto_main_wirego, preferences_apply_cb);

	prefs_register_filename_preference(wirego_module, "pluginpath",
					   "Wirego plugin path",
					   "The fullpath to the wirego plugin, written in Go",
					   &pref_wirego_config_filename, FALSE);

  prefs_register_static_text_preference(wirego_module, "helper",
        "You will need to restart Wireshark after changing the plugin path.",
        "");

}