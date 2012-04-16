/*****
*
* Copyright (C) 2004,2005,2006,2007 PreludeIDS Technologies. All Rights Reserved.
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
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <librequiem/idmef.h>
#include <librequiem/idmef-message-print.h>

#include "requiem-manager.h"


int debug_LTX_requiem_plugin_version(void);
int debug_LTX_manager_plugin_init(requiem_plugin_entry_t *pe, void *data);


typedef struct {
        requiem_list_t list;
        idmef_path_t *path;
} debug_object_t;


typedef struct {
        char *logfile;
        requiem_io_t *fd;
        requiem_list_t path_list;
} debug_plugin_t;


struct iterator_data {
        debug_object_t *object;
        debug_plugin_t *plugin;
};


static int iterator(idmef_value_t *val, void *extra)
{
        int ret;
        requiem_string_t *out;
        struct iterator_data *data = extra;

        ret = requiem_string_new(&out);
        if ( ret < 0 ) {
                requiem_perror(ret, "error creating string object");
                return -1;
        }

        ret = requiem_string_sprintf(out, "%s: ", idmef_path_get_name(data->object->path, -1));
        if ( ret < 0 ) {
                requiem_perror(ret, "error writing string");
                return -1;
        }

        ret = idmef_value_to_string(val, out);
        if ( ret < 0 ) {
                requiem_perror(ret, "error converting generic value to string");
                return -1;
        }

        requiem_string_cat(out, "\n");

        requiem_io_write(data->plugin->fd, requiem_string_get_string(out), requiem_string_get_len(out));
        requiem_string_destroy(out);

        return 0;
}


static int debug_run(requiem_plugin_instance_t *pi, idmef_message_t *msg)
{
        int ret;
        idmef_value_t *val;
        requiem_list_t *tmp;
        debug_object_t *entry;
        struct iterator_data cbdata;
        debug_plugin_t *plugin = requiem_plugin_instance_get_plugin_data(pi);

        if ( requiem_list_is_empty(&plugin->path_list) ) {
                idmef_message_print(msg, plugin->fd);
                return 0;
        }

        requiem_list_for_each(&plugin->path_list, tmp) {
                entry = requiem_list_entry(tmp, debug_object_t, list);

                ret = idmef_path_get(entry->path, msg, &val);
                if ( ret < 0 ) {
                        requiem_perror(ret, "error getting value for object '%s'", idmef_path_get_name(entry->path, -1));
                        continue;
                }

                if ( ret == 0 )
                        continue; /* no match */

                cbdata.object = entry;
                cbdata.plugin = plugin;

                idmef_value_iterate(val, iterator, &cbdata);
                idmef_value_destroy(val);
        }

        return 0;
}


static void destroy_filter_path(debug_plugin_t *plugin)
{
        debug_object_t *object;
        requiem_list_t *tmp, *bkp;

        requiem_list_for_each_safe(&plugin->path_list, tmp, bkp) {
                object = requiem_list_entry(tmp, debug_object_t, list);

                requiem_list_del(&object->list);
                idmef_path_destroy(object->path);

                free(object);
        }
}


static int set_filter_path(debug_plugin_t *plugin, const char *path)
{
        int ret = 0;
        debug_object_t *elem;
        char *ptr, *start, *dup;

        start = dup = strdup(path);
        if ( ! dup )
                return requiem_error_from_errno(errno);

        destroy_filter_path(plugin);

        while ( (ptr = strsep(&dup, ", \t")) ) {
                if ( *ptr == '\0' )
                        continue;

                elem = malloc(sizeof(*elem));
                if ( ! elem ) {
                        ret = requiem_error_from_errno(errno);
                        break;
                }

                ret = idmef_path_new_fast(&elem->path, ptr);
                if ( ret < 0 ) {
                        free(elem);
                        break;
                }

                requiem_list_add_tail(&plugin->path_list, &elem->list);
        }

        free(start);
        return ret;
}


static int debug_set_object(requiem_option_t *option, const char *arg, requiem_string_t *err, void *context)
{
        debug_plugin_t *plugin = requiem_plugin_instance_get_plugin_data(context);
        return set_filter_path(plugin, arg);
}



static int debug_set_logfile(requiem_option_t *option, const char *arg, requiem_string_t *err, void *context)
{
        FILE *fd;
        char *old;
        debug_plugin_t *plugin = requiem_plugin_instance_get_plugin_data(context);

        if ( strcmp(arg, "-") == 0 )
                fd = stdout;

        else {
                fd = fopen(arg, "a+");
                if ( ! fd ) {
                        requiem_string_sprintf(err, "error opening %s for writing: %s", arg, strerror(errno));
                        return -1;
                }
        }

        old = plugin->logfile;
        plugin->logfile = strdup(arg);
        if ( ! plugin->logfile ) {
                if ( fd != stdout )
                        fclose(fd);

                return requiem_error_from_errno(errno);
        }

        if ( old )
                free(old);

        if ( requiem_io_get_fdptr(plugin->fd) != stdout )
                fclose(requiem_io_get_fdptr(plugin->fd));

        requiem_io_set_file_io(plugin->fd, fd);

        return 0;
}



static int debug_get_logfile(requiem_option_t *opt, requiem_string_t *out, void *context)
{
        debug_plugin_t *plugin;
        plugin = requiem_plugin_instance_get_plugin_data(context);
        return requiem_string_set_ref(out, plugin->logfile);
}



static int debug_new(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        int ret;
        debug_plugin_t *new;

        new = malloc(sizeof(*new));
        if ( ! new )
                return requiem_error_from_errno(errno);

        ret = requiem_io_new(&new->fd);
        if ( ret < 0 ) {
                free(new);
                return ret;
        }

        new->logfile = strdup("-");
        if ( ! new->logfile ) {
                requiem_io_destroy(new->fd);
                free(new);
                return requiem_error_from_errno(errno);
        }

        requiem_io_set_file_io(new->fd, stdout);

        requiem_list_init(&new->path_list);
        requiem_plugin_instance_set_plugin_data(context, new);

        return 0;
}



static void debug_destroy(requiem_plugin_instance_t *pi, requiem_string_t *err)
{
        FILE *fd;
        debug_plugin_t *plugin = requiem_plugin_instance_get_plugin_data(pi);

        fd = requiem_io_get_fdptr(plugin->fd);
        if ( fd != stdout )
                requiem_io_close(plugin->fd);

        requiem_io_destroy(plugin->fd);

        destroy_filter_path(plugin);

        free(plugin->logfile);
        free(plugin);
}



int debug_LTX_manager_plugin_init(requiem_plugin_entry_t *pe, void *rootopt)
{
        int ret;
        requiem_option_t *opt;
        static manager_report_plugin_t debug_plugin;
        int hook = REQUIEM_OPTION_TYPE_CLI|REQUIEM_OPTION_TYPE_CFG|REQUIEM_OPTION_TYPE_WIDE;

        ret = requiem_option_add(rootopt, &opt, hook, 0, "debug", "Option for the debug plugin",
                                 REQUIEM_OPTION_ARGUMENT_OPTIONAL, debug_new, NULL);
        if ( ret < 0 )
                return ret;

        requiem_plugin_set_activation_option(pe, opt, NULL);

        ret = requiem_option_add(opt, NULL, hook, 'o', "object",
                                 "Name of IDMEF object to print (no object provided will print the entire message)",
                                 REQUIEM_OPTION_ARGUMENT_REQUIRED, debug_set_object, NULL);
        if ( ret < 0 )
                return ret;

        ret = requiem_option_add(opt, NULL, hook, 'l', "logfile",
                                 "Specify output file to use (default to stdout)",
                                 REQUIEM_OPTION_ARGUMENT_REQUIRED, debug_set_logfile, debug_get_logfile);
        if ( ret < 0 )
                return ret;

        requiem_plugin_set_name(&debug_plugin, "Debug");
        requiem_plugin_set_destroy_func(&debug_plugin, debug_destroy);
        manager_report_plugin_set_running_func(&debug_plugin, debug_run);

        requiem_plugin_entry_set_plugin(pe, (void *) &debug_plugin);

        return 0;
}



int debug_LTX_requiem_plugin_version(void)
{
        return REQUIEM_PLUGIN_API_VERSION;
}
