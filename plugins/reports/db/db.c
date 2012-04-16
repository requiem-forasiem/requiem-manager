/*****
*
* Copyright (C) 2002-2005,2006,2007 PreludeIDS Technologies. All Rights Reserved.
* Author: Nicolas Delon
* Author: Krzysztof Zaraska <kzaraska@student.uci.agh.edu.pl>
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
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>

#include <librequiem/idmef.h>
#include <librequiem/requiem-inttypes.h>
#include <librequiem/requiem-error.h>
#include <librequiem/idmef.h>
#include <librequiem/requiem-error.h>

#include <librequiemdb/requiemdb-sql-settings.h>
#include <librequiemdb/requiemdb-sql.h>
#include <librequiemdb/requiemdb-error.h>
#include <librequiemdb/requiemdb-path-selection.h>
#include <librequiemdb/requiemdb.h>

#include "requiem-manager.h"


#define DEFAULT_DATABASE_TYPE "mysql"


int db_LTX_requiem_plugin_version(void);
int db_LTX_manager_plugin_init(requiem_plugin_entry_t *pe, void *rootopt);


#define param_value(param) (param ? param : "")


typedef struct {
        char *type;
        char *log;
        char *host;
        char *file;
        char *port;
        char *name;
        char *user;
        char *pass;
        requiemdb_t *db;
} db_plugin_t;



REQUIEM_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, type)
REQUIEM_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, log)
REQUIEM_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, host)
REQUIEM_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, port)
REQUIEM_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, name)
REQUIEM_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, user)
REQUIEM_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, pass)
REQUIEM_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, file)


static int db_run(requiem_plugin_instance_t *pi, idmef_message_t *message)
{
        int ret;
        db_plugin_t *plugin = requiem_plugin_instance_get_plugin_data(pi);

        ret = requiemdb_insert_message(plugin->db, message);
        if ( ret < 0 )
                requiem_log(REQUIEM_LOG_WARN, "could not insert message into database: %s.\n", requiemdb_strerror(ret));

        if ( requiem_error_get_code(ret) == REQUIEMDB_ERROR_CONNECTION )
                ret = MANAGER_REPORT_PLUGIN_FAILURE_GLOBAL;
        else
                ret = MANAGER_REPORT_PLUGIN_FAILURE_SINGLE;

        return ret;
}



static void db_destroy(requiem_plugin_instance_t *pi, requiem_string_t *out)
{
        db_plugin_t *plugin = requiem_plugin_instance_get_plugin_data(pi);

        if ( plugin->type )
                free(plugin->type);

        if ( plugin->host )
                free(plugin->host);

        if ( plugin->file )
                free(plugin->file);

        if ( plugin->name )
                free(plugin->name);

        if ( plugin->user )
                free(plugin->user);

        if ( plugin->pass )
                free(plugin->pass);

        if ( plugin->port )
                free(plugin->port);

        if ( plugin->log )
                free(plugin->log);

        if ( plugin->db )
                requiemdb_destroy(plugin->db);

        free(plugin);

        requiemdb_deinit();
}



static int db_init(requiem_plugin_instance_t *pi, requiem_string_t *out)
{
        int ret;
        requiemdb_t *db;
        requiemdb_sql_t *sql;
        requiemdb_sql_settings_t *settings;
        db_plugin_t *plugin = requiem_plugin_instance_get_plugin_data(pi);

        ret = requiemdb_sql_settings_new(&settings);
        if ( ret < 0 )
                return ret;

        if ( plugin->host )
                requiemdb_sql_settings_set_host(settings, plugin->host);

        if ( plugin->file )
                requiemdb_sql_settings_set_file(settings, plugin->file);

        if ( plugin->port )
                requiemdb_sql_settings_set_port(settings, plugin->port);

        if ( plugin->user )
                requiemdb_sql_settings_set_user(settings, plugin->user);

        if ( plugin->pass )
                requiemdb_sql_settings_set_pass(settings, plugin->pass);

        if ( plugin->name )
                requiemdb_sql_settings_set_name(settings, plugin->name);

        ret = requiemdb_sql_new(&sql, plugin->type, settings);
        if ( ret < 0 ) {
                requiem_string_sprintf(out, "error initializing librequiemdb SQL interface: %s", requiemdb_strerror(ret));
                requiemdb_sql_settings_destroy(settings);
                return ret;
        }

        if ( ! plugin->log )
                requiemdb_sql_disable_query_logging(sql);
        else {
                ret = requiemdb_sql_enable_query_logging(sql, (strcmp(plugin->log, "-") == 0) ? NULL : plugin->log);
                if ( ret < 0 ) {
                        requiemdb_sql_destroy(sql);
                        requiem_string_sprintf(out, "could not enable queries logging with log file '%s': %s",
                                               plugin->log, requiemdb_strerror(ret));
                        return ret;
                }
        }

        ret = requiemdb_new(&db, sql, NULL, NULL, 0);
        if ( ret < 0 ) {
                requiemdb_sql_destroy(sql);
                requiem_string_sprintf(out, "could not initialize librequiemdb: %s", requiemdb_strerror(ret));
                return ret;
        }

        if ( plugin->db )
                requiemdb_destroy(plugin->db);

        plugin->db = db;

        return 0;
}



static int db_activate(requiem_option_t *opt, const char *optarg, requiem_string_t *err, void *context)
{
        int ret;
        db_plugin_t *new;

        ret = requiemdb_init();
        if ( ret < 0 ) {
                requiem_log(REQUIEM_LOG_ERR, "error initializing librequiemdb: %s", requiemdb_strerror(ret));
                return ret;
        }

        new = calloc(1, sizeof(*new));
        if ( ! new )
                return requiem_error_from_errno(errno);

        new->type = strdup(DEFAULT_DATABASE_TYPE);
        if ( ! new->type ) {
                free(new);
                return requiem_error_from_errno(errno);
        }

        requiem_plugin_instance_set_plugin_data(context, new);

        return 0;
}




int db_LTX_manager_plugin_init(requiem_plugin_entry_t *pe, void *rootopt)
{
        int ret;
        requiem_option_t *opt;
        static manager_report_plugin_t db_plugin;
        int hook = REQUIEM_OPTION_TYPE_CLI|REQUIEM_OPTION_TYPE_CFG|REQUIEM_OPTION_TYPE_WIDE;

        ret = requiem_option_add(rootopt, &opt, hook, 0, "db", "Options for the librequiemdb plugin",
                                 REQUIEM_OPTION_ARGUMENT_OPTIONAL, db_activate, NULL);
        if ( ret < 0 )
                return ret;

        requiem_plugin_set_activation_option(pe, opt, db_init);

        ret = requiem_option_add(opt, NULL, hook, 't', "type", "Type of database (mysql/pgsql)",
                                 REQUIEM_OPTION_ARGUMENT_REQUIRED, db_set_type, db_get_type);
        if ( ret < 0 )
                return ret;

        ret = requiem_option_add(opt, NULL, hook, 'l', "log",
                                 "Log all queries in a file, should be only used for debugging purpose",
                                 REQUIEM_OPTION_ARGUMENT_OPTIONAL, db_set_log, db_get_log);
        if ( ret < 0 )
                return ret;

        ret = requiem_option_add(opt, NULL, hook, 'h', REQUIEMDB_SQL_SETTING_HOST,
                                 "The host where the database server is running (in case of client/server database)",
                                 REQUIEM_OPTION_ARGUMENT_REQUIRED,  db_set_host, db_get_host);
        if ( ret < 0 )
                return ret;

        ret = requiem_option_add(opt, NULL, hook, 'f', REQUIEMDB_SQL_SETTING_FILE,
                                 "The file where the database is stored (in case of file based database)",
                                 REQUIEM_OPTION_ARGUMENT_REQUIRED,  db_set_file, db_get_file);
        if ( ret < 0 )
                return ret;

        ret = requiem_option_add(opt, NULL, hook, 'p', REQUIEMDB_SQL_SETTING_PORT,
                                 "The port where the database server is listening (in case of client/server database)",
                                 REQUIEM_OPTION_ARGUMENT_REQUIRED, db_set_port, db_get_port);
        if ( ret < 0 )
                return ret;

        ret = requiem_option_add(opt, NULL, hook, 'd', REQUIEMDB_SQL_SETTING_NAME,
                                 "The name of the database where the alerts will be stored",
                                 REQUIEM_OPTION_ARGUMENT_REQUIRED, db_set_name, db_get_name);
        if ( ret < 0 )
                return ret;

        ret = requiem_option_add(opt, NULL, hook, 'u', REQUIEMDB_SQL_SETTING_USER,
                                 "User of the database (in case of client/server database)",
                                 REQUIEM_OPTION_ARGUMENT_REQUIRED, db_set_user, db_get_user);
        if ( ret < 0 )
                return ret;

        ret = requiem_option_add(opt, NULL, hook, 'P', REQUIEMDB_SQL_SETTING_PASS,
                                 "Password for the user (in case of client/server database)",
                                 REQUIEM_OPTION_ARGUMENT_REQUIRED, db_set_pass, db_get_pass);
        if ( ret < 0 )
                return ret;

        requiem_plugin_set_name(&db_plugin, "db");
        requiem_plugin_set_destroy_func(&db_plugin, db_destroy);
        manager_report_plugin_set_running_func(&db_plugin, db_run);

        requiem_plugin_entry_set_plugin(pe, (void *) &db_plugin);

        return 0;
}



int db_LTX_requiem_plugin_version(void)
{
        return REQUIEM_PLUGIN_API_VERSION;
}
