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
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>

#include <librequiem/requiem.h>
#include <librequiem/requiem-log.h>

#include "requiem-manager.h"
#include "server-generic.h"
#include "sensor-server.h"
#include "manager-options.h"
#include "decode-plugins.h"
#include "report-plugins.h"
#include "filter-plugins.h"
#include "idmef-message-scheduler.h"
#include "reverse-relaying.h"
#include "manager-auth.h"

#define MANAGER_MODEL "Requiem Manager"
#define MANAGER_CLASS "Concentrator"
#define MANAGER_MANUFACTURER "https://github.com/requiem-forasiem"
#define DEFAULT_ANALYZER_NAME "requiem-manager"

extern manager_config_t config;

requiem_client_t *manager_client;
struct ev_loop *manager_event_loop;

static char **global_argv;
static volatile sig_atomic_t got_signal = 0;



/*
 * all function called here should be signal safe.
 */
static RETSIGTYPE handle_signal(int sig)
{
        size_t i;

        /*
         * stop the sensor server.
         */
        for ( i = 0; i < config.nserver; i++ )
                sensor_server_stop(config.server[i]);

        got_signal = sig;
}



#if ! ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
static void restart_manager(void)
{
        int ret;

        requiem_log(REQUIEM_LOG_INFO, "Restarting Requiem Manager (%s).\n", global_argv[0]);

        ret = execvp(global_argv[0], global_argv);
        if ( ret < 0 )
                requiem_log(REQUIEM_LOG_ERR, "Error restarting Requiem Manager (%s).\n", global_argv[0]);
}
#endif



static int fill_analyzer_infos(void)
{
        int ret;
        requiem_string_t *str;
        idmef_analyzer_t *local = NULL;

        local = requiem_client_get_analyzer(manager_client);
        assert(local);

        ret = requiem_string_new_constant(&str, VERSION);
        if ( ret < 0 )
                return ret;
        idmef_analyzer_set_version(local, str);

        ret = requiem_string_new_constant(&str, MANAGER_MODEL);
        if ( ret < 0 )
                return ret;
        idmef_analyzer_set_model(local, str);

        ret = requiem_string_new_constant(&str, MANAGER_CLASS);
        if ( ret < 0 )
                return ret;
        idmef_analyzer_set_class(local, str);

        ret = requiem_string_new_constant(&str, MANAGER_MANUFACTURER);
        if ( ret < 0 )
                return ret;
        idmef_analyzer_set_manufacturer(local, str);

        return 0;
}



static void heartbeat_cb(requiem_client_t *client, idmef_message_t *idmef)
{
        idmef_message_process(idmef);
}



static void sig_cb(struct ev_loop *loop, struct ev_signal *s, int revent)
{
#if ! ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
        if ( s->signum == SIGHUP )
                signal(SIGHUP, SIG_IGN);
#endif

        handle_signal(s->signum);
        ev_unloop(manager_event_loop, EVUNLOOP_ALL);

        return;
}


static void add_signal(int signo, struct sigaction *action)
{
        ev_signal *s = malloc(sizeof(*s));
        ev_signal_init(s, sig_cb, signo);
        ev_signal_start(manager_event_loop, s);
}


static const char *get_restart_string(void)
{
#if ! ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
        if ( got_signal == SIGHUP )
                return "will restart";
#endif

        return "terminating";
}


int main(int argc, char **argv)
{
        int ret;
        struct sigaction action;
        requiem_option_t *manager_root_optlist;

        requiem_init(&argc, argv);

        manager_event_loop = ev_default_loop_init(EVFLAG_AUTO);
        if ( ! manager_event_loop ) {
                requiem_log(REQUIEM_LOG_ERR, "error initializing libev.\n");
                return -1;
        }


        global_argv = argv;
        requiem_option_new_root(&manager_root_optlist);

        /*
         * make sure we ignore sighup until acceptable.
         */
#ifdef SA_INTERRUPT
        action.sa_flags = SA_INTERRUPT;
#else
        action.sa_flags = 0;
#endif

#if ! ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
        action.sa_handler = SIG_IGN;
        sigemptyset(&action.sa_mask);
        sigaction(SIGHUP, &action, NULL);
#endif

        /*
         * Initialize plugin first.
         */
        REQUIEM_PLUGIN_SET_PRELOADED_SYMBOLS();

        ret = report_plugins_init(REPORT_PLUGIN_DIR, manager_root_optlist);
        if ( ret < 0 )
                return -1;
        requiem_log(REQUIEM_LOG_DEBUG, "Initialized %d reporting plugins.\n", ret);

        ret = decode_plugins_init(DECODE_PLUGIN_DIR, manager_root_optlist);
        if ( ret < 0 )
                return -1;
        requiem_log(REQUIEM_LOG_DEBUG, "Initialized %d decoding plugins.\n", ret);

        ret = filter_plugins_init(FILTER_PLUGIN_DIR, manager_root_optlist);
        if ( ret < 0 )
                return -1;
        requiem_log(REQUIEM_LOG_DEBUG, "Initialized %d filtering plugins.\n", ret);


        ret = manager_options_init(manager_root_optlist, &argc, argv);
        if ( ret < 0 )
                return -1;

        ret = requiem_client_new(&manager_client, DEFAULT_ANALYZER_NAME);
        if ( ret < 0 ) {
                requiem_perror(ret, "error creating requiem-client object");
                return -1;
        }

        fill_analyzer_infos();
        requiem_client_set_heartbeat_cb(manager_client, heartbeat_cb);
        requiem_client_set_flags(manager_client, requiem_client_get_flags(manager_client) & ~REQUIEM_CLIENT_FLAGS_CONNECT);
        requiem_client_set_config_filename(manager_client, config.config_file);

        ret = requiem_client_init(manager_client);
        if ( ret < 0 ) {
                requiem_perror(ret, "error initializing requiem-client");
                return ret;
        }

        ret = manager_options_read(manager_root_optlist, &argc, argv);
        if ( ret < 0 )
                return -1;

        ret = requiem_client_start(manager_client);
        if ( ret < 0 ) {
                requiem_perror(ret, "error starting requiem-client");
                return -1;
        }

        ret = reverse_relay_init();
        if ( ret < 0 )
                return -1;

        /*
         * start server
         */
        ret = manager_auth_init(manager_client, config.tls_options, config.dh_bits, config.dh_regenerate);
        if ( ret < 0 ) {
                if ( ret != -2 )
                        requiem_log(REQUIEM_LOG_WARN, "%s\n", requiem_client_get_setup_error(manager_client));

                return -1;
        }

        /*
         * requiem_client_start() should send it's initial heartbeat
         * before the scheduler start handling IDMEF messages, so that we don't refcount
         * the shared manager_client analyzer object from two different thread.
         */
        ret = idmef_message_scheduler_init();
        if ( ret < 0 ) {
                requiem_log(REQUIEM_LOG_ERR, "couldn't initialize alert scheduler.\n");
                return -1;
        }

        /*
         * setup signal handling
         */
#if ! ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
        sigaction(SIGPIPE, &action, NULL);
#endif

        action.sa_handler = handle_signal;
        add_signal(SIGINT, &action);
        add_signal(SIGTERM, &action);
        add_signal(SIGABRT, &action);

#if ! ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
        add_signal(SIGQUIT, &action);
        add_signal(SIGHUP, &action);
#endif

        server_generic_start(config.server, config.nserver);

        /*
         * we won't get there unless a signal is caught.
         */
        if ( got_signal )
                requiem_log(REQUIEM_LOG_WARN, "signal %d received, %s requiem-manager.\n",
                            got_signal, get_restart_string());

        idmef_message_scheduler_exit();
        requiem_client_destroy(manager_client, REQUIEM_CLIENT_EXIT_STATUS_FAILURE);

        report_plugins_close();

        /*
         * De-Initialize the Requiem library. This has the side effect of flushing
         * the Requiem asynchronous stack.
         */
        requiem_deinit();

#if ! ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
        if ( got_signal == SIGHUP )
                restart_manager();
#endif

        if ( config.pidfile )
                unlink(config.pidfile);

        exit(0);
}

