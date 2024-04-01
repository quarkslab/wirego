/* packet-wirego.h
 *
 * Wirego plugin for golang integration by Benoit Girard
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */



//Map our go plugin internal field identifiers to the ones provided by Wireshark
typedef struct {
  int wirego_field_id;
  int wireshark_field_id;
} field_id_to_plugin_field_id_t;

int get_wireshark_field_id_from_wirego_field_id(int wirego_field_id);

extern int ett_wirego;
extern int proto_wirego;



/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
