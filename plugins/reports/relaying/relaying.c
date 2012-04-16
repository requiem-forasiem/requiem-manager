/*****
*
* Copyright (C) 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
* Author: Yoann Vandoorselaere <yoannv@gmail.com>
*
* This file is part of the Requiem-Manager program.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2, or (at your option)
* any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; see the file COPYING.  If not, write to
* the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*
*****/

#include "config.h"

#include <stdio.h>
#include <stdlib.h>

#include "requiem-manager.h"


int relaying_LTX_requiem_plugin_version(void);
int relaying_LTX_manager_plugin_init(requiem_plugin_entry_t *plugin, void *data);


typedef struct {
        requiem_connection_pool_t *conn_pool;
} relaying_plugin_t;



static requiem_msgbuf_t *msgbuf = NULL;
extern requiem_client_t *manager_client;



static int send_msgbuf(requiem_msgbuf_t *msgbuf, requiem_msg_t *msg)
{
        requiem_connection_pool_t *pool = requiem_msgbuf_get_data(msgbuf);

        requiem_connection_pool_broadcast(pool, msg);

        return 0;
}



static int relaying_process(requiem_plugin_instance_t *pi, idmef_message_t *idmef)
{
        int ret;
        relaying_plugin_t *plugin = requiem_plugin_instance_get_plugin_data(pi);

        if ( ! plugin->conn_pool )
                return 0;

        if ( ! msgbuf ) {
                ret = requiem_msgbuf_new(&msgbuf);
                if ( ret < 0 )
                        return ret;

                requiem_msgbuf_set_callback(msgbuf, send_msgbuf);
        }

        requiem_msgbuf_set_data(msgbuf, plugin->conn_pool);

        idmef_message_write(idmef, msgbuf);
        requiem_msgbuf_mark_end(msgbuf);

        return 0;
}



static int relaying_activate(requiem_option_t *opt, const char *optarg, requiem_string_t *err, void *context)
{
        relaying_plugin_t *new;

        new = calloc(1, sizeof(*new));
        if ( ! new )
                return requiem_error_from_errno(errno);

        requiem_plugin_instance_set_plugin_data(context, new);

        return 0;
}



static int relaying_set_manager(requiem_option_t *opt, const char *optarg, requiem_string_t *err, void *context)
{
        int ret;
        requiem_client_profile_t *cp;
        relaying_plugin_t *plugin = requiem_plugin_instance_get_plugin_data(context);

        if ( ! plugin->conn_pool ) {
                cp = requiem_client_get_profile(manager_client);

                ret = requiem_connection_pool_new(&plugin->conn_pool, cp, REQUIEM_CONNECTION_PERMISSION_IDMEF_WRITE);
                if ( ! plugin->conn_pool )
                        return ret;

                requiem_connection_pool_set_flags(plugin->conn_pool, requiem_connection_pool_get_flags(plugin->conn_pool)
                                                  | REQUIEM_CONNECTION_POOL_FLAGS_RECONNECT);
                requiem_client_set_flags(manager_client, requiem_client_get_flags(manager_client) | REQUIEM_CLIENT_FLAGS_ASYNC_SEND);
        }

        ret = requiem_connection_pool_set_connection_string(plugin->conn_pool, optarg);
        if ( ret < 0 )
                return ret;

        ret = requiem_connection_pool_init(plugin->conn_pool);
        if ( ret < 0 )
                return ret;

        return 0;
}




static int relaying_get_manager(requiem_option_t *opt, requiem_string_t *out, void *context)
{
        relaying_plugin_t *plugin = requiem_plugin_instance_get_plugin_data(context);

        if ( ! plugin->conn_pool )
                return 0;

        requiem_string_sprintf(out, "%s", requiem_connection_pool_get_connection_string(plugin->conn_pool));

        return 0;
}



static void relaying_destroy(requiem_plugin_instance_t *pi, requiem_string_t *out)
{
        relaying_plugin_t *plugin = requiem_plugin_instance_get_plugin_data(pi);

        if ( plugin->conn_pool )
                requiem_connection_pool_destroy(plugin->conn_pool);

        free(plugin);
}



int relaying_LTX_manager_plugin_init(requiem_plugin_entry_t *pe, void *rootopt)
{
        int ret;
        requiem_option_t *opt;
        static manager_report_plugin_t relaying_plugin;
        int hook = REQUIEM_OPTION_TYPE_CLI|REQUIEM_OPTION_TYPE_CFG|REQUIEM_OPTION_TYPE_WIDE;

        ret = requiem_option_add(rootopt, &opt, hook, 0, "relaying",
                                 "Relaying plugin option", REQUIEM_OPTION_ARGUMENT_OPTIONAL,
                                 relaying_activate, NULL);
        if ( ret < 0 )
                return ret;

        requiem_plugin_set_activation_option(pe, opt, NULL);

        ret = requiem_option_add(opt, NULL, hook, 'p', "parent-managers",
                                 "List of managers address:port pair where messages should be sent to",
                                 REQUIEM_OPTION_ARGUMENT_REQUIRED, relaying_set_manager, relaying_get_manager);
        if ( ret < 0 )
                return ret;

        requiem_plugin_set_name(&relaying_plugin, "Relaying");
        requiem_plugin_set_destroy_func(&relaying_plugin, relaying_destroy);

        manager_report_plugin_set_running_func(&relaying_plugin, relaying_process);

        requiem_plugin_entry_set_plugin(pe, (void *) &relaying_plugin);

        return 0;
}



int relaying_LTX_requiem_plugin_version(void)
{
        return REQUIEM_PLUGIN_API_VERSION;
}
