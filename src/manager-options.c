/*****
*
* Copyright (C) 1999-2005,2006,2007 PreludeIDS Technologies. All Rights Reserved.
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
#include <unistd.h>
#include <ctype.h>
#include <netdb.h>
#include <arpa/inet.h>

#if ! ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
# include <pwd.h>
# include <grp.h>
#endif

#include <librequiem/requiem.h>
#include <librequiem/daemonize.h>
#include <librequiem/requiem-log.h>

#include "bufpool.h"
#include "server-generic.h"
#include "sensor-server.h"
#include "manager-options.h"
#include "report-plugins.h"
#include "reverse-relaying.h"


#define DEFAULT_MANAGER_ADDR "0.0.0.0"
#define DEFAULT_MANAGER_PORT 4690


manager_config_t config;
extern requiem_client_t *manager_client;


static int set_conf_file(requiem_option_t *opt, const char *optarg, requiem_string_t *err, void *context)
{
        config.config_file = strdup(optarg);
        return 0;
}


static int print_version(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        fprintf(stderr, "requiem-manager %s\n", VERSION);
        exit(0);
}


static int set_daemon_mode(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        int ret;

        ret = requiem_daemonize(config.pidfile);
        if ( ret < 0 )
                return ret;

        requiem_log_set_flags(requiem_log_get_flags() | REQUIEM_LOG_FLAGS_SYSLOG);
        ev_default_fork();

        return 0;
}



static int set_debug_mode(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        requiem_log_t priority = REQUIEM_LOG_DEBUG;

        if ( arg )
                priority = atoi(arg);

        requiem_log_set_debug_level(priority);

        return 0;
}


static int set_pidfile(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        config.pidfile = strdup(arg);
        return 0;
}



static server_generic_t *add_server(void)
{
        config.nserver++;

        config.server = realloc(config.server, sizeof(*config.server) * config.nserver);
        if ( ! config.server )
                return NULL;

        config.server[config.nserver - 1] = sensor_server_new();
        if ( ! config.server[config.nserver - 1] )
                return NULL;

        return config.server[config.nserver - 1];
}


static void del_server(void)
{
        server_generic_destroy(config.server[config.nserver - 1]);

        config.nserver--;
        config.server = realloc(config.server, sizeof(*config.server) * config.nserver);
}

static int add_server_default(void)
{
        char buf[128];
        server_generic_t *server;
        int ret, prev_family = AF_UNSPEC;
        struct addrinfo *ai, *ai_start, hints;

        memset(&hints, 0, sizeof(hints));

        hints.ai_flags = AI_PASSIVE;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_family = PF_UNSPEC;

#ifdef AI_ADDRCONFIG
        /*
         * Only look up addresses using address types for which a local
         * interface is configured.
         */
        hints.ai_flags |= AI_ADDRCONFIG;
#endif

        snprintf(buf, sizeof(buf), "%u", DEFAULT_MANAGER_PORT);

        ret = getaddrinfo(NULL, buf, &hints, &ai);
        if ( ret != 0 ) {
                requiem_log(REQUIEM_LOG_ERR, "error getting default machine address: %s.\n",
                            (ret == EAI_SYSTEM) ? strerror(errno) : gai_strerror(ret));
                return -1;
        }

        for ( ai_start = ai; ai != NULL; ai = ai->ai_next ) {
                if ( ! inet_ntop(ai->ai_family, requiem_sockaddr_get_inaddr(ai->ai_addr), buf, sizeof(buf)) ) {
                        requiem_log(REQUIEM_LOG_ERR, "address to string translation failed: %s.\n", strerror(errno));
                        break;
                }

                server = add_server();
                if ( ! server )
                        break;

                ret = server_generic_bind_numeric(server, ai->ai_addr, ai->ai_addrlen, DEFAULT_MANAGER_PORT);
                if ( ret < 0 ) {
                        char buf[128];

                        /*
                         * More information on this at:
                         * http://lists.debian.org/debian-ipv6/2001/01/msg00031.html
                         */
                        if ( requiem_error_get_code(ret) == REQUIEM_ERROR_EADDRINUSE &&
                             prev_family != AF_UNSPEC && ai->ai_family != prev_family ) {
                                ret = 0;
                                del_server();
                                continue;
                        }

                        inet_ntop(ai->ai_family, requiem_sockaddr_get_inaddr(ai->ai_addr), buf, sizeof(buf));
                        requiem_perror(ret, "error initializing server on %s:%u", buf, DEFAULT_MANAGER_PORT);
                        break;
                }

                prev_family = ai->ai_family;
        }

        if ( config.nserver == 0 ) {
                requiem_log(REQUIEM_LOG_WARN, "could not find any address to listen on.\n");
                return -1;
        }

        freeaddrinfo(ai_start);

        return ret;
}



static int set_reverse_relay(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        int ret;

        if ( config.nserver == 0 ) {
                ret = add_server_default();
                if ( ret < 0 )
                        return -1; /* avoid duplicate option error */
        }

        return reverse_relay_create_initiator(arg);
}




static int set_listen_address(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        int ret;
        char *ptr;
        server_generic_t *server;
        unsigned int port = DEFAULT_MANAGER_PORT;

        if ( strncmp(arg, "unix", 4) != 0 ) {

                ptr = strrchr(arg, ':');
                if ( ptr ) {
                        *ptr = '\0';
                        port = atoi(ptr + 1);
                }
        }

        server = add_server();
        if ( ! server )
                return -1;

        ret = server_generic_bind(server, arg, port);
        if ( ret < 0 )
                requiem_perror(ret, "error initializing server on %s:%u", arg, port);

        return ret;
}



static int set_report_plugin_failover(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        int ret;

        ret = report_plugin_activate_failover(arg);
        if ( ret == 0 )
                requiem_log(REQUIEM_LOG_INFO, "Failover capability enabled for reporting plugin %s.\n", arg);

        return ret;
}



static int set_connection_timeout(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        config.connection_timeout = atoi(arg);
        return 0;
}



static int set_dh_bits(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        config.dh_bits = atoi(arg);
        return 0;
}


static int set_dh_regenerate(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        config.dh_regenerate = atoi(arg) * 60 * 60;
        return 0;
}


static int set_tls_options(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        config.tls_options = strdup(arg);
        return 0;
}


static char *const2char(const char *val)
{
        union {
                const char *ro;
                char *rw;
        } uval;

        uval.ro = val;

        return uval.rw;
}


static int set_sched_priority(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        unsigned int i;
        char *name, *prio, *value = const2char(arg);
        struct {
                const char *name;
                unsigned int priority;
        } tbl[] = {
                { "high", 5 },
                { "medium", 3 },
                { "low", 2 }
        };

        while ( (name = strsep(&value, " ")) ) {
                prio = strchr(name, ':');
                if ( ! prio ) {
                        requiem_log(REQUIEM_LOG_ERR, "could not find colon delimiter in: '%s'.\n", name);
                        return -1;
                }

                *prio++ = 0;

                for ( i = 0; i < sizeof(tbl) / sizeof(*tbl); i++ ) {
                        if ( strcmp(name, tbl[i].name) == 0 ) {
                                tbl[i].priority = atoi(prio);
                                break;
                        }
                }

                if ( i == sizeof(tbl) / sizeof(*tbl) ) {
                        requiem_log(REQUIEM_LOG_ERR, "priority '%s' does not exist.\n", name);
                        *prio = ':';
                        return -1;
                }

                *prio = ':';
        }

        idmef_message_scheduler_set_priority(tbl[0].priority, tbl[1].priority, tbl[2].priority);
        return 0;
}


static int set_sched_buffer_size(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        char *eptr = NULL;
        unsigned long int value;

        value = strtoul(arg, &eptr, 10);
        if ( value == ULONG_MAX || eptr == arg ) {
                requiem_log(REQUIEM_LOG_ERR, "Invalid buffer size specified: '%s'.\n", arg);
                return -1;
        }

        if ( *eptr == 'K' || *eptr == 'k' )
                value = value * 1024;

        else if ( *eptr == 'M' || *eptr == 'm' )
                value = value * 1024 * 1024;

        else if ( *eptr == 'G' || *eptr == 'g' )
                value = value * 1024 * 1024 * 1024;

        else if ( eptr != arg ) {
                requiem_log(REQUIEM_LOG_ERR, "Invalid buffer suffix specified: '%s'.\n", arg);
                return -1;
        }

        bufpool_set_disk_threshold(value);
        return 0;
}



#if ! ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
static int set_user(requiem_option_t *opt, const char *optarg, requiem_string_t *err, void *context)
{
        int ret;
        uid_t uid;
        const char *p;
        struct passwd *pw;

        for ( p = optarg; isdigit((int) *p); p++ );

        if ( *p == 0 )
                uid = atoi(optarg);
        else {
                pw = getpwnam(optarg);
                if ( ! pw ) {
                        requiem_log(REQUIEM_LOG_ERR, "could not lookup user '%s'.\n", optarg);
                        return -1;
                }

                uid = pw->pw_uid;
        }

        ret = setuid(uid);
        if ( ret < 0 ) {
                requiem_log(REQUIEM_LOG_ERR, "change to UID %d failed: %s.\n", (int) uid, strerror(errno));
                return ret;
        }

        return 0;
}


static int set_group(requiem_option_t *opt, const char *optarg, requiem_string_t *err, void *context)
{
        int ret;
        gid_t gid;
        const char *p;
        struct group *grp;

        for ( p = optarg; isdigit((int) *p); p++ );

        if ( *p == 0 )
                gid = atoi(optarg);
        else {
                grp = getgrnam(optarg);
                if ( ! grp ) {
                        requiem_log(REQUIEM_LOG_ERR, "could not lookup group '%s'.\n", optarg);
                        return -1;
                }

                gid = grp->gr_gid;
        }

        ret = setgid(gid);
        if ( ret < 0 ) {
                requiem_log(REQUIEM_LOG_ERR, "change to GID %d failed: %s.\n", (int) gid, strerror(errno));
                return ret;
        }

        ret = setgroups(1, &gid);
        if ( ret < 0 ) {
                requiem_log(REQUIEM_LOG_ERR, "removal of ancillary groups failed: %s.\n", strerror(errno));
                return ret;
        }

        return 0;
}
#endif



static int print_help(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        requiem_option_print(NULL, REQUIEM_OPTION_TYPE_CLI, 25, stderr);
        return requiem_error(REQUIEM_ERROR_EOF);
}



int manager_options_init(requiem_option_t *rootopt, int *argc, char **argv)
{
        int ret;
        requiem_string_t *err;
        requiem_option_t *init_first, *opt;
        requiem_option_warning_t old_warnings;

        /* Default */
        memset(&config, 0, sizeof(config));

        config.dh_regenerate = 24 * 60 * 60;
        config.connection_timeout = 10;
        config.config_file = REQUIEM_MANAGER_CONF;
        config.tls_options = NULL;

        requiem_option_new_root(&init_first);

        requiem_option_add(init_first, &opt, REQUIEM_OPTION_TYPE_CLI, 'h', "help",
                           "Print this help", REQUIEM_OPTION_ARGUMENT_NONE, print_help, NULL);
        requiem_option_set_priority(opt, REQUIEM_OPTION_PRIORITY_IMMEDIATE);

        requiem_option_add(rootopt, &opt, REQUIEM_OPTION_TYPE_CLI, 0, "config",
                           "Configuration file to use", REQUIEM_OPTION_ARGUMENT_REQUIRED,
                           set_conf_file, NULL);
        requiem_option_set_priority(opt, REQUIEM_OPTION_PRIORITY_IMMEDIATE);

        requiem_option_add(rootopt, &opt, REQUIEM_OPTION_TYPE_CLI, 'v', "version",
                           "Print version number", REQUIEM_OPTION_ARGUMENT_NONE, print_version, NULL);
        requiem_option_set_priority(opt, REQUIEM_OPTION_PRIORITY_IMMEDIATE);

        requiem_option_add(rootopt, &opt, REQUIEM_OPTION_TYPE_CLI, 'D', "debug-level",
                           "Run in debug mode", REQUIEM_OPTION_ARGUMENT_OPTIONAL, set_debug_mode, NULL);
        requiem_option_set_priority(opt, REQUIEM_OPTION_PRIORITY_IMMEDIATE);

        requiem_option_add(rootopt, &opt, REQUIEM_OPTION_TYPE_CLI|REQUIEM_OPTION_TYPE_CFG, 'd',
                           "daemon", "Run in daemon mode", REQUIEM_OPTION_ARGUMENT_NONE, set_daemon_mode, NULL);
        requiem_option_set_priority(opt, REQUIEM_OPTION_PRIORITY_FIRST);

        requiem_option_add(rootopt, &opt, REQUIEM_OPTION_TYPE_CLI|REQUIEM_OPTION_TYPE_CFG, 'P',
                           "pidfile", "Write Requiem PID to pidfile", REQUIEM_OPTION_ARGUMENT_REQUIRED,
                           set_pidfile, NULL);

        /*
         * we want this option to be processed before -d.
         */
        requiem_option_set_priority(opt, REQUIEM_OPTION_PRIORITY_IMMEDIATE);


#if ! ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
        requiem_option_add(rootopt, NULL, REQUIEM_OPTION_TYPE_CFG, 0, "user",
                           "Set the user ID used by requiem-manager", REQUIEM_OPTION_ARGUMENT_REQUIRED, set_user, NULL);

        requiem_option_add(rootopt, &opt, REQUIEM_OPTION_TYPE_CFG, 0, "group",
                           "Set the group ID used by requiem-manager", REQUIEM_OPTION_ARGUMENT_REQUIRED, set_group, NULL);
        requiem_option_set_priority(opt, REQUIEM_OPTION_PRIORITY_FIRST);
#endif

        requiem_option_add(rootopt, NULL, REQUIEM_OPTION_TYPE_CFG, 0, "connection-timeout",
                           "Number of seconds a client has to successfully authenticate (default 10)",
                           REQUIEM_OPTION_ARGUMENT_REQUIRED, set_connection_timeout, NULL);

        requiem_option_add(rootopt, NULL, REQUIEM_OPTION_TYPE_CFG, 0, "tls-options",
                           "TLS ciphers, key exchange methods, protocols, macs, and compression options",
                           REQUIEM_OPTION_ARGUMENT_REQUIRED, set_tls_options, NULL);

        requiem_option_add(rootopt, NULL, REQUIEM_OPTION_TYPE_CFG, 0, "dh-parameters-regenerate",
                           "How often to regenerate the Diffie Hellman parameters (in hours)",
                           REQUIEM_OPTION_ARGUMENT_REQUIRED, set_dh_regenerate, NULL);

        requiem_option_add(rootopt, NULL, REQUIEM_OPTION_TYPE_CFG, 0, "dh-prime-length",
                           "Size of the Diffie Hellman prime (768, 1024, 2048, 3072 or 4096)",
                           REQUIEM_OPTION_ARGUMENT_REQUIRED, set_dh_bits, NULL);

        requiem_option_add(rootopt, NULL, REQUIEM_OPTION_TYPE_CFG, 0, "sched-priority",
                           NULL, REQUIEM_OPTION_ARGUMENT_REQUIRED, set_sched_priority, NULL);

        requiem_option_add(rootopt, NULL, REQUIEM_OPTION_TYPE_CFG, 0, "sched-buffer-size",
                           NULL, REQUIEM_OPTION_ARGUMENT_REQUIRED, set_sched_buffer_size, NULL);

        requiem_option_add(rootopt, &opt, REQUIEM_OPTION_TYPE_CLI|REQUIEM_OPTION_TYPE_CFG, 'c', "child-managers",
                           "List of managers address:port pair where messages should be gathered from",
                           REQUIEM_OPTION_ARGUMENT_REQUIRED, set_reverse_relay, NULL);
        /*
         * necessary since the reverse relay need to be setup only once one
         * server object has been created.
         */
        requiem_option_set_priority(opt, REQUIEM_OPTION_PRIORITY_LAST);

        requiem_option_add(rootopt, NULL, REQUIEM_OPTION_TYPE_CLI|REQUIEM_OPTION_TYPE_CFG, 'l', "listen",
                           "Address the sensors server should listen on (addr:port)",
                           REQUIEM_OPTION_ARGUMENT_REQUIRED, set_listen_address, NULL);

        requiem_option_add(rootopt, &opt, REQUIEM_OPTION_TYPE_CLI|REQUIEM_OPTION_TYPE_CFG, 'f', "failover",
                           "Enable failover for specified report plugin",
                           REQUIEM_OPTION_ARGUMENT_REQUIRED, set_report_plugin_failover, NULL);

        requiem_option_set_priority(opt, REQUIEM_OPTION_PRIORITY_LAST);


        /*
         * Some plugin might require manager_client to be already initialized,
         * for example the relaying plugin. We need to process theses option
         * first so that --help will be recognized even throught the initialization
         * fail.
         *
         * We can't delay the error checking of manager_client initialization either since
         * requiem_client_init() also need to know the configuration file that will be used.
         */

        requiem_option_set_warnings(0, &old_warnings);

        ret = requiem_option_read(init_first, &config.config_file, argc, argv, &err, NULL);
        if ( ret < 0 && requiem_error_get_code(ret) != REQUIEM_ERROR_EOF )
                requiem_perror(ret, "error processing requiem-manager options");

        requiem_option_set_warnings(old_warnings, NULL);

        return ret;
}



int manager_options_read(requiem_option_t *manager_root_optlist, int *argc, char **argv)
{
        int ret;
        requiem_string_t *err;

        ret = requiem_option_read(manager_root_optlist, &config.config_file, argc, argv, &err, manager_client);
        if ( ret < 0 ) {
                if ( requiem_error_get_code(ret) == REQUIEM_ERROR_EOF )
                        return -1;

                if ( err )
                        requiem_log(REQUIEM_LOG_WARN, "Option error: %s.\n", requiem_string_get_string(err));
                else
                        requiem_perror(ret, "error processing options");

                return -1;
        }

        while ( ret < *argc )
                requiem_log(REQUIEM_LOG_WARN, "Unhandled command line argument: '%s'.\n", argv[ret++]);

        if ( config.nserver == 0 )
                ret = add_server_default();

        return ret;
}
