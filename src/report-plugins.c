/*****
*
* Copyright (C) 1998-2007,2008 PreludeIDS Technologies. All Rights Reserved.
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
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>

#include <librequiem/requiem.h>
#include <librequiem/requiem-timer.h>
#include <librequiem/requiem-failover.h>

#include "requiem-manager.h"
#include "report-plugins.h"
#include "filter-plugins.h"
#include "pmsg-to-idmef.h"


#define FAILOVER_RETRY_TIMEOUT 10 * 60
#define MANAGER_PLUGIN_SYMBOL  "manager_plugin_init"


static requiem_msgbuf_t *msgbuf;
static REQUIEM_LIST(report_plugins_instance);


typedef struct {
        requiem_bool_t failover_enabled;
        requiem_timer_t timer;

        requiem_failover_t *failover;
        requiem_failover_t *failed_failover;
} plugin_failover_t;



static int report_plugin_run_single(requiem_plugin_instance_t *pi, plugin_failover_t *pf, idmef_message_t *idmef);



static void get_failover_filename(requiem_plugin_instance_t *pi, char *buf, size_t size)
{
        requiem_plugin_generic_t *plugin = requiem_plugin_instance_get_plugin(pi);

        snprintf(buf, size, MANAGER_FAILOVER_DIR "/%s[%s]",
                 plugin->name, requiem_plugin_instance_get_name(pi));
}



static int recover_from_failover(requiem_plugin_instance_t *pi, plugin_failover_t *pf, size_t *totsize)
{
        ssize_t size;
        int ret, count = 0;
        idmef_message_t *idmef;
        requiem_msg_t *msg = NULL;

        *totsize = 0;

        do {
                size = requiem_failover_get_saved_msg(pf->failover, &msg);
                if ( size < 0 )
                        requiem_perror((requiem_error_t) size, "could not retrieve saved message from disk");

                if ( size == 0 )
                        break;

                *totsize += size;

                ret = pmsg_to_idmef(&idmef, msg);
                if ( ret < 0 )
                        break;

                ret = report_plugin_run_single(pi, pf, idmef);
                if ( ret < 0 && ret != MANAGER_REPORT_PLUGIN_FAILURE_SINGLE )
                        break;

                requiem_msg_destroy(msg);

                count++;

        } while ( 1 );

        return count;
}




static int try_recovering_from_failover(requiem_plugin_instance_t *pi, plugin_failover_t *pf)
{
        int ret;
        size_t totsize;
        const char *text;
        requiem_string_t *err;
        requiem_plugin_generic_t *plugin;
        unsigned int available, count = 0;

        ret = requiem_string_new(&err);
        if ( ret < 0 ) {
                requiem_perror(ret, "error creating object");
                return -1;
        }

        ret = requiem_plugin_instance_call_commit_func(pi, err);
        if ( ret < 0 ) {
                if ( ! requiem_string_is_empty(err) )
                        requiem_log(REQUIEM_LOG_WARN, "error recovering from failover: %s.\n", requiem_string_get_string(err));
                else
                        requiem_log(REQUIEM_LOG_WARN, "error recovering from failover: %s.\n", requiem_strerror(ret));

                requiem_string_destroy(err);
                return -1;
        }
        requiem_string_destroy(err);

        available = requiem_failover_get_available_msg_count(pf->failover);
        if ( ! available )
                return 0;

        plugin = requiem_plugin_instance_get_plugin(pi);

        requiem_log(REQUIEM_LOG_WARN, "Plugin %s[%s]: flushing %u message (%lu erased due to quota)...\n",
                    plugin->name, requiem_plugin_instance_get_name(pi),
                    available, requiem_failover_get_deleted_msg_count(pf->failover));

        count = recover_from_failover(pi, pf, &totsize);

        if ( count != available )
                text = "failed recovering";
        else {
                text = "recovered";
                pf->failover_enabled = FALSE;
        }

        requiem_log(REQUIEM_LOG_WARN, "Plugin %s[%s]: %s from failover: %u/%u message flushed (%" REQUIEM_PRIu64 " bytes).\n",
                    plugin->name, requiem_plugin_instance_get_name(pi), text, count, available, (uint64_t) totsize);

        return (count == available) ? 0 : -1;
}




static void failover_timer_expire_cb(void *data)
{
        int ret;
        plugin_failover_t *pf;
        requiem_plugin_instance_t *pi = data;

        pf = requiem_plugin_instance_get_data(pi);

        ret = try_recovering_from_failover(pi, pf);
        if ( ret < 0 )
                requiem_timer_reset(&pf->timer);
        else
                requiem_timer_destroy(&pf->timer);
}



static int setup_plugin_failover(requiem_plugin_instance_t *pi)
{
        int ret;
        plugin_failover_t *pf;
        char filename[PATH_MAX];
        requiem_plugin_generic_t *plugin = requiem_plugin_instance_get_plugin(pi);

        get_failover_filename(pi, filename, sizeof(filename));

        if ( ! requiem_plugin_instance_has_commit_func(pi) ) {
                requiem_log(REQUIEM_LOG_WARN, "plugin %s does not support failover.\n", plugin->name);
                return -1;
        }

        pf = calloc(1, sizeof(*pf));
        if ( ! pf ) {
                requiem_log(REQUIEM_LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        ret = requiem_failover_new(&pf->failover, filename);
        if ( ret < 0 ) {
                requiem_perror(ret, "could not create failover object in %s", filename);
                free(pf);
                return -1;
        }

        snprintf(filename + strlen(filename), sizeof(filename) - strlen(filename), "/invalid");

        ret = requiem_failover_new(&pf->failed_failover, filename);
        if ( ret < 0 ) {
                requiem_perror(ret, "could not create failover object in %s", filename);
                requiem_failover_destroy(pf->failover);
                free(pf);
                return -1;
        }

        requiem_plugin_instance_set_data(pi, pf);

        try_recovering_from_failover(pi, pf);
        if ( pf->failover_enabled ) {
                requiem_failover_destroy(pf->failover);
                requiem_failover_destroy(pf->failed_failover);
                free(pf);
                return -1;
        }

        return 0;
}



/*
 *
 */
static int subscribe(requiem_plugin_instance_t *pi)
{
        requiem_plugin_generic_t *plugin = requiem_plugin_instance_get_plugin(pi);

        requiem_log(REQUIEM_LOG_INFO, "Subscribing %s[%s] to active reporting plugins.\n",
                    plugin->name, requiem_plugin_instance_get_name(pi));

        requiem_plugin_instance_add(pi, &report_plugins_instance);

        return 0;
}


static void unsubscribe(requiem_plugin_instance_t *pi)
{
        requiem_plugin_generic_t *plugin = requiem_plugin_instance_get_plugin(pi);

        requiem_log(REQUIEM_LOG_DEBUG, "Unsubscribing %s[%s] from active reporting plugins.\n",
                    plugin->name, requiem_plugin_instance_get_name(pi));

        requiem_plugin_instance_del(pi);
}



static void failover_init(requiem_plugin_instance_t *pi, plugin_failover_t *pf)
{
        requiem_plugin_generic_t *pg = requiem_plugin_instance_get_plugin(pi);

        pf->failover_enabled = TRUE;

        requiem_log(REQUIEM_LOG_WARN, "Plugin %s[%s]: failure. Enabling failover.\n",
                    pg->name, requiem_plugin_instance_get_name(pi));

        requiem_timer_set_data(&pf->timer, pi);
        requiem_timer_set_expire(&pf->timer, FAILOVER_RETRY_TIMEOUT);
        requiem_timer_set_callback(&pf->timer, failover_timer_expire_cb);

        requiem_timer_init(&pf->timer);
}




static int save_msgbuf(requiem_msgbuf_t *msgbuf, requiem_msg_t *msg)
{
        int ret;
        requiem_failover_t *pf = requiem_msgbuf_get_data(msgbuf);

        ret = requiem_failover_save_msg(pf, msg);
        if ( ret < 0 )
                requiem_perror(ret, "error saving message to disk");

        return ret;
}




static void save_idmef_message(requiem_failover_t *pf, idmef_message_t *msg)
{
        /*
         * this is a message we generated ourself...
         */
        requiem_msgbuf_set_data(msgbuf, pf);
        idmef_message_write(msg, msgbuf);
        requiem_msgbuf_mark_end(msgbuf);
}



static int report_plugin_run_single(requiem_plugin_instance_t *pi, plugin_failover_t *pf, idmef_message_t *idmef)
{
        int ret;

        ret = requiem_plugin_run(pi, manager_report_plugin_t, run, pi, idmef);
        if ( ret < 0 && pf ) {
                if ( ret == MANAGER_REPORT_PLUGIN_FAILURE_SINGLE )
                        save_idmef_message(pf->failed_failover, idmef);
                else {
                        failover_init(pi, pf);
                        save_idmef_message(pf->failover, idmef);
                }
        }

        return ret;
}



/*
 * Start all plugins of kind 'list'.
 */
void report_plugins_run(idmef_message_t *idmef)
{
        int ret;
        requiem_list_t *tmp;
        plugin_failover_t *pf;
        requiem_plugin_generic_t *pg;
        requiem_plugin_instance_t *pi;

        ret = filter_plugins_run_by_category(idmef, MANAGER_FILTER_CATEGORY_REPORTING);
        if ( ret < 0 )
                return;

        requiem_list_for_each(&report_plugins_instance, tmp) {

                pi = requiem_linked_object_get_object(tmp);
                pg = requiem_plugin_instance_get_plugin(pi);
                pf = requiem_plugin_instance_get_data(pi);

                ret = filter_plugins_run_by_plugin(idmef, pi);
                if ( ret < 0 )
                        continue;

                if ( pf && pf->failover_enabled ) {
                        save_idmef_message(pf->failover, idmef);
                        continue;
                }

                report_plugin_run_single(pi, pf, idmef);
         }
}




/*
 * Close all report plugins.
 */
void report_plugins_close(void)
{
        requiem_list_t *tmp, *bkp;
        requiem_plugin_instance_t *pi;

        requiem_list_for_each_safe(&report_plugins_instance, tmp, bkp) {
                pi = requiem_linked_object_get_object(tmp);
                requiem_plugin_instance_unsubscribe(pi);
        }
}



/*
 * Open the plugin directory (dirname),
 * and try to load all plugins located in it.
 */
int report_plugins_init(const char *dirname, void *data)
{
        int ret, count;

        ret = access(dirname, F_OK);
        if ( ret < 0 ) {
                if ( errno == ENOENT )
                        return 0;

                requiem_log(REQUIEM_LOG_ERR, "could not access %s: %s.\n", dirname, strerror(errno));
                return -1;
        }

        count = requiem_plugin_load_from_dir(NULL, dirname, MANAGER_PLUGIN_SYMBOL, data, subscribe, unsubscribe);

        /*
         * don't return an error if the report directory doesn't exist.
         * this could happen as it's normal to not use report plugins on
         * certain system.
         */
        if ( count < 0 && errno != ENOENT ) {
                requiem_perror(count, "could not load plugin subsystem: %s", requiem_strerror(count));
                return -1;
        }

        ret = requiem_msgbuf_new(&msgbuf);
        if ( ret < 0 ) {
                requiem_perror(ret, "could not create message buffer: %s", requiem_strerror(ret));
                return -1;
        }

        requiem_msgbuf_set_callback(msgbuf, save_msgbuf);

        return count;
}




/**
 * report_plugins_available:
 *
 * Returns: 0 if there is active REPORT plugins, -1 otherwise.
 */
requiem_bool_t report_plugins_available(void)
{
        return requiem_list_is_empty(&report_plugins_instance);
}



int report_plugin_activate_failover(const char *plugin)
{
        int ret;
        char pname[256], iname[256];
        requiem_plugin_instance_t *pi;

        ret = sscanf(plugin, "%255[^[][%255[^]]", pname, iname);

        pi = requiem_plugin_search_instance_by_name(NULL, pname, (ret == 2) ? iname : NULL);
        if ( ! pi ) {
                requiem_log(REQUIEM_LOG_WARN, "couldn't find plugin %s.\n", plugin);
                return -1;
        }

        return setup_plugin_failover(pi);
}
