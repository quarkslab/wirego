#ifndef _PREFS_H_
#define _PREFS_H_

char * get_plugin_path(void);
int save_plugin_path(const char * path);
void register_preferences_menu(void);
void preferences_apply_cb(void);


#endif