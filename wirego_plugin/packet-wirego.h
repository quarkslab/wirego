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




typedef struct {
    guint32 cmd;
    guint32 cmd_context;    //typically just guint8, but let's room for expansion/improvement
    guint32 ioctl_command;  //should be more generic, but IOCTL is currently the only user
    guint32 req_frame_num;
    guint32 rsp_frame_num;
    nstime_t req_time;
} wirego_pkt_info_t;

/* List contains request data  */
typedef struct {
    wmem_list_t *request_frame_data;
} wirego_conversation;


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
