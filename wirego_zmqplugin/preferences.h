#ifndef _PREFS_H_
#define _PREFS_H_

char * get_zmq_endpoint(void);
int save_zmq_endpoint(const char * path);
void register_preferences_menu(void);
void preferences_apply_cb(void);


#endif