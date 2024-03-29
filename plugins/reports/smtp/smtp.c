/*****
*
* Copyright (C) 2008 PreludeIDS Technologies. All Rights Reserved.
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
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <librequiem/requiem.h>
#include <librequiem/requiem-timer.h>
#include <librequiem/idmef-message-print.h>

#ifdef HAVE_LIBREQUIEMDB
# include <librequiemdb/requiemdb.h>
#endif

#include "requiem-manager.h"


#define DEFAULT_KEEPALIVE_SECONDS 60

#define DEFAULT_SMTP_PORT   "25"
#define DEFAULT_MAIL_SENDER "requiem-manager"


#ifndef MIN
# define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif


int smtp_LTX_requiem_plugin_version(void);
int smtp_LTX_manager_plugin_init(requiem_plugin_entry_t *pe, void *data);


typedef enum {
        MAIL_FORMAT_TYPE_FIXED,
        MAIL_FORMAT_TYPE_PATH,
        MAIL_FORMAT_TYPE_IF,
} mail_format_type_t;


typedef struct {
        requiem_list_t list;
        requiem_list_t sublist;

        char *fixed;
        idmef_path_t *path;

        mail_format_type_t type;
} mail_format_t;


typedef enum {
        EXPECT_MESSAGE_TYPE_ALERT,
        EXPECT_MESSAGE_TYPE_HEARTBEAT,
        EXPECT_MESSAGE_TYPE_ANY
} expect_message_type_t;

typedef struct {
        requiem_list_t subject_content;
        requiem_list_t message_content;

        requiem_bool_t need_reconnect;

        requiem_io_t *fd;
        char *server;
        char *sender;
        char *recipients;
        struct addrinfo *ai_addr;
        requiem_timer_t keepalive_timer;

        expect_message_type_t expected_message;

#ifdef HAVE_LIBREQUIEMDB
        requiem_list_t correlation_content;
        char *type;
        char *log;
        char *host;
        char *port;
        char *name;
        char *user;
        char *pass;
        char *file;
        requiemdb_t *db;
#endif
} smtp_plugin_t;


REQUIEM_PLUGIN_OPTION_DECLARE_STRING_CB(smtp, smtp_plugin_t, sender);
REQUIEM_PLUGIN_OPTION_DECLARE_STRING_CB(smtp, smtp_plugin_t, server);
REQUIEM_PLUGIN_OPTION_DECLARE_STRING_CB(smtp, smtp_plugin_t, recipients);

#ifdef HAVE_LIBREQUIEMDB
REQUIEM_PLUGIN_OPTION_DECLARE_STRING_CB(db, smtp_plugin_t, type)
REQUIEM_PLUGIN_OPTION_DECLARE_STRING_CB(db, smtp_plugin_t, log)
REQUIEM_PLUGIN_OPTION_DECLARE_STRING_CB(db, smtp_plugin_t, host)
REQUIEM_PLUGIN_OPTION_DECLARE_STRING_CB(db, smtp_plugin_t, port)
REQUIEM_PLUGIN_OPTION_DECLARE_STRING_CB(db, smtp_plugin_t, name)
REQUIEM_PLUGIN_OPTION_DECLARE_STRING_CB(db, smtp_plugin_t, user)
REQUIEM_PLUGIN_OPTION_DECLARE_STRING_CB(db, smtp_plugin_t, pass)
REQUIEM_PLUGIN_OPTION_DECLARE_STRING_CB(db, smtp_plugin_t, file)
#endif


static char *strip_return(char *str)
{
        char *ptr;
        size_t len = strlen(str);

        if ( len == 0 )
                return str;

        ptr = str + len - 1;

        while ( *ptr == '\r' || *ptr == '\n' )
                *ptr-- = 0;

        return str;
}

static char *strip_return_constant(const char *str, char *buf, size_t size)
{
        char *end;
        size_t len;

        end = strchr(str, '\r');
        if ( ! end )
                return "invalid input string";

        len = MIN((size_t) (end - str), size - 1);
        strncpy(buf, str, len);
        buf[len] = 0;

        return buf;
}


static int read_reply(int expected, requiem_io_t *fd, char *buf, size_t size)
{
        char p[2];
        ssize_t ret;

        buf[0] = 0;

        do {
                ret = requiem_io_read(fd, buf, size - 1);
        } while ( ret < 0 && errno == EINTR );

        if ( ret < 0 ) {
                requiem_log(REQUIEM_LOG_WARN, "error reading server reply: %s.\n", strerror(errno));
                return ret;
        }

        if ( ret == 0 )
                return 0;

        buf[ret] = 0;

        p[0] = buf[0];
        p[1] = 0;

        requiem_log_debug(4, "SMTP[read(%" REQUIEM_PRId64 ")]: %s", (int64_t) ret, buf);

        return (! expected || atoi(p) == expected) ? 0 : -1;
}



static int send_command(smtp_plugin_t *plugin, int expected, char *buf)
{
        int ret;
        char rbuf[1024];

        if ( plugin->need_reconnect )
                return -1;

        do {
                ret = requiem_io_write(plugin->fd, buf, strlen(buf));
        } while ( ret < 0 && errno == EINTR );

        requiem_log_debug(4, "SMTP[write(%d)]: %s", ret, buf);

        if ( ret < 0 ) {
                requiem_io_close(plugin->fd);
                plugin->need_reconnect = TRUE;
                return ret;
        }

        if ( expected >= 0 ) {
                rbuf[0] = 0;

                ret = read_reply(expected, plugin->fd, rbuf, sizeof(rbuf));
                if ( ret < 0 ) {
                        char errbuf[1024];

                        requiem_log(REQUIEM_LOG_WARN, "SMTP(%s): unexpected server reply: %s",
                                    strip_return_constant(buf, errbuf, sizeof(errbuf)), rbuf);

                        requiem_io_close(plugin->fd);
                        plugin->need_reconnect = TRUE;
                }
        }

        return ret;
}



static int send_command_va(smtp_plugin_t *plugin, int expected, const char *fmt, ...)
{
        int ret;
        va_list ap;
        char wbuf[1024];

        va_start(ap, fmt);
        ret = vsnprintf(wbuf, sizeof(wbuf), fmt, ap);
        va_end(ap);

        if ( ret < 0 || (unsigned int) ret >= sizeof(wbuf) ) {
                requiem_log(REQUIEM_LOG_WARN, "buffer not large enough (%u bytes needed).\n", ret);
                return ret;
        }

        return send_command(plugin, expected, wbuf);
}


typedef struct {
        int count;
        mail_format_t *fmt;
        requiem_string_t *str;
} iterate_data_t;


static int iterate_cb(idmef_value_t *value, void *extra)
{
        int ret;
        iterate_data_t *data = extra;

        if ( idmef_value_is_list(value) )
                return idmef_value_iterate(value, iterate_cb, extra);

        if ( data->count++ > 0 )
                requiem_string_cat(data->str, ", ");

        ret = idmef_value_to_string(value, data->str);
        if ( ret < 0 )
                requiem_log(REQUIEM_LOG_ERR, "could not get value as string for path '%s': %s.\n",
                            idmef_path_get_name(data->fmt->path, -1), requiem_strerror(ret));

        return 0;
}


static int build_dynamic_string(requiem_string_t *str, requiem_list_t *head, idmef_message_t *idmef)
{
        int ret;
        mail_format_t *fmt;
        requiem_list_t *tmp;
        idmef_value_t *value;
        iterate_data_t data;

        requiem_list_for_each(head, tmp) {
                fmt = requiem_list_entry(tmp, mail_format_t, list);

                if ( fmt->fixed ) {
                        ret = requiem_string_cat(str, fmt->fixed);
                        if ( ret < 0 )
                                return ret;
                } else {
                        ret = idmef_path_get(fmt->path, idmef, &value);
                        if ( ret <= 0 ) {
                                if ( fmt->type == MAIL_FORMAT_TYPE_IF )
                                        continue;

                                if ( ret < 0 )
                                        requiem_log(REQUIEM_LOG_ERR, "could not retrieve path '%s': %s'.\n",
                                                    idmef_path_get_name(fmt->path, -1), requiem_strerror(ret));

                                continue;
                        }

                        if ( fmt->type == MAIL_FORMAT_TYPE_IF ) {
                                idmef_value_destroy(value);

                                ret = build_dynamic_string(str, &fmt->sublist, idmef);
                                if ( ret < 0 )
                                        return ret;

                                continue;
                        }

                        data.fmt = fmt;
                        data.count = 0;
                        data.str = str;

                        idmef_value_iterate(value, iterate_cb, &data);
                        idmef_value_destroy(value);
                }
        }

        return 0;

}



#ifdef HAVE_LIBREQUIEMDB
static int db_init(requiem_plugin_instance_t *pi, requiem_string_t *out)
{
        int ret;
        requiemdb_t *db;
        requiemdb_sql_t *sql;
        requiemdb_sql_settings_t *settings;
        smtp_plugin_t *plugin = requiem_plugin_instance_get_plugin_data(pi);

        ret = requiemdb_init();
        if ( ret < 0 )
                return ret;

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


static int send_correlation_alert_notice(smtp_plugin_t *plugin, int count)
{
        int ret;
        size_t len;
        char txt[1024], buf[1024], pad[1024];

        ret = snprintf(txt, sizeof(txt), "* %d alerts (retrieved from database) are tied to the event *", count);
        if ( ret < 0 || ret == sizeof(txt) )
                return -1;

        len = MIN(sizeof(pad) - 1, (size_t) ret);
        memset(pad, '*', len);
        pad[len] = 0;

        snprintf(buf, sizeof(buf), "\n\n%s\n%s\n%s\n\n", pad, txt, pad);
        return requiem_io_write(plugin->fd, buf, strlen(buf));
}


static int add_string_to_list(smtp_plugin_t *plugin, requiem_list_t *head, idmef_message_t *idmef)
{
        int ret;
        const char *cstr;
        requiem_list_t *tmp;
        requiem_string_t *cur, *str;

        ret = requiem_string_new(&str);
        if ( ret < 0 )
                return ret;

        ret = build_dynamic_string(str, &plugin->correlation_content, idmef);
        if ( ret < 0 || requiem_string_is_empty(str) ) {
                requiem_string_destroy(str);
                return ret;
        }

        cstr = requiem_string_get_string(str);

        requiem_list_for_each(head, tmp) {
                cur = requiem_linked_object_get_object(tmp);

                if ( strcmp(requiem_string_get_string(cur), cstr) == 0 ) {
                        requiem_string_destroy(str);
                        return 0;
                }
        }

        requiem_linked_object_add(head, (requiem_linked_object_t *) str);

        return 0;
}


static int retrieve_from_db(smtp_plugin_t *plugin, const char *criteria_str)
{
        int ret;
        uint64_t dbident;
        idmef_criteria_t *criteria;
        idmef_message_t *idmef;
        requiem_string_t *str;
        requiemdb_result_idents_t *results;
        requiem_list_t clist, *tmp, *bkp;

        ret = idmef_criteria_new_from_string(&criteria, criteria_str);
        if ( ret < 0 ) {
                requiem_log(REQUIEM_LOG_ERR, "error creating criteria: %s.\n", requiem_strerror(ret));
                return -1;
        }

        ret = requiemdb_get_alert_idents(plugin->db, criteria, -1, -1, 0, &results);
        idmef_criteria_destroy(criteria);
        if ( ret == 0 )
                return ret;

        if ( ret < 0 ) {
                requiem_log(REQUIEM_LOG_ERR, "error retrieving alert idents: %s.\n", requiemdb_strerror(ret));
                return -1;
        }

        send_correlation_alert_notice(plugin, ret);
        requiem_list_init(&clist);

        while ( requiemdb_result_idents_get_next(results, &dbident) ) {
                ret = requiemdb_get_alert(plugin->db, dbident, &idmef);
                if ( ret < 0 ) {
                        requiem_log(REQUIEM_LOG_ERR, "failure retrieving message ident %" REQUIEM_PRIu64 ".\n", dbident);
                        continue;
                }

                if ( requiem_list_is_empty(&plugin->correlation_content) )
                        idmef_message_print(idmef, plugin->fd);
                else
                        add_string_to_list(plugin, &clist, idmef);

                idmef_message_destroy(idmef);
        }

        requiemdb_result_idents_destroy(results);

        requiem_list_for_each_safe(&clist, tmp, bkp) {
                str = requiem_linked_object_get_object(tmp);
                requiem_io_write(plugin->fd, requiem_string_get_string(str), requiem_string_get_len(str));
                requiem_string_destroy(str);
        }

        return 0;
}



static requiem_string_t *get_sender_analyzerid(idmef_alert_t *alert)
{
        idmef_analyzer_t *analyzer = NULL;
        requiem_string_t *c_analyzerid = NULL, *id;

        while ( (analyzer = idmef_alert_get_next_analyzer(alert, analyzer)) ) {
                 id = idmef_analyzer_get_analyzerid(analyzer);
                 if ( id )
                         c_analyzerid = id;
        }

        return c_analyzerid;
}


static int send_correlation_alert_info(smtp_plugin_t *plugin, idmef_message_t *idmef)
{
        int ret;
        const char *sep;
        idmef_alert_t *alert;
        idmef_alertident_t *cident = NULL;
        idmef_correlation_alert_t *calert;
        requiem_string_t *criteria, *c_analyzerid = NULL, *analyzerid, *ident;

        alert = idmef_message_get_alert(idmef);
        if ( ! alert )
                return 0;

        calert = idmef_alert_get_correlation_alert(alert);
        if ( ! calert )
                return 0;

        ret = requiem_string_new(&criteria);
        if ( ret < 0 )
                return ret;

        while ( (cident = idmef_correlation_alert_get_next_alertident(calert, cident)) ) {
                analyzerid = idmef_alertident_get_analyzerid(cident);
                if ( ! analyzerid ) {
                        if ( ! c_analyzerid )
                                c_analyzerid = get_sender_analyzerid(alert);

                        analyzerid = c_analyzerid;
                }

                ident = idmef_alertident_get_alertident(cident);

                if ( ! analyzerid || ! ident )
                        continue;


                sep = (requiem_string_is_empty(criteria)) ? "" : " || ";

                requiem_string_sprintf(criteria, "%s(alert.analyzer.analyzerid == '%s' && alert.messageid == '%s')",
                                       sep, requiem_string_get_string(analyzerid), requiem_string_get_string(ident));
        }

        if ( ! requiem_string_is_empty(criteria) )
                ret = retrieve_from_db(plugin, requiem_string_get_string(criteria));

        requiem_string_destroy(criteria);

        return ret;
}

#endif

static int send_mail(smtp_plugin_t *plugin, const char *subject, requiem_string_t *body, idmef_message_t *idmef)
{
        int ret;
        long gmtoff;
        char *str, *ptr;
        time_t t = time(NULL);

        ret = send_command_va(plugin, 2, "MAIL FROM: %s\r\n", plugin->sender);
        if ( ret < 0 )
                return ret;

        str = plugin->recipients;
        do {
                ptr = strchr(str, ',');
                if ( ptr )
                        *ptr = 0;

                while ( *str == ' ' ) str++;

                ret = send_command_va(plugin, 2, "RCPT TO: %s\r\n", str);
                if ( ret < 0 )
                        return ret;

                if ( ptr ) {
                        *ptr = ',';
                        str = ptr + 1;
                }
        } while ( ptr );

        ret = send_command(plugin, 3, "DATA\r\n");
        if ( ret < 0 )
                return ret;

        str = strip_return(ctime(&t));

        ret = requiem_get_gmt_offset(&gmtoff);
        if ( ret < 0 )
                requiem_log(REQUIEM_LOG_WARN, "error retrieving gmt offset: %s.\n", requiem_strerror(ret));

        ret = send_command_va(plugin, -1, "Subject: %s\r\nFrom: %s\r\nTo: %s\r\nDate: %s %+.2d%.2d\r\n\r\n",
                              subject, plugin->sender, plugin->recipients, str, gmtoff / (60 * 60), gmtoff % (60 * 60));
        if ( ret < 0 )
                return ret;

        if ( body && ! requiem_string_is_empty(body) )
                requiem_io_write(plugin->fd, requiem_string_get_string(body), requiem_string_get_len(body));
        else
                idmef_message_print(idmef, plugin->fd);

#ifdef HAVE_LIBREQUIEMDB
        if ( plugin->db )
                send_correlation_alert_info(plugin, idmef);
#endif

        ret = send_command(plugin, 2, "\r\n.\r\n");
        if ( ret < 0 )
                return ret;

        return send_command(plugin, 2, "RSET\r\n");
}



static void keepalive_smtp_conn(void *data)
{
        int ret;
        smtp_plugin_t *plugin = data;

        ret = send_command(plugin, 2, "NOOP\r\n");
        if ( ret < 0 ) {
                requiem_timer_destroy(&plugin->keepalive_timer);
                return;
        }

        requiem_timer_reset(&plugin->keepalive_timer);
}


static int connect_mail_server_if_needed(smtp_plugin_t *plugin)
{
        int sock, ret;
        char buf[1024];
        struct addrinfo *ai = plugin->ai_addr;

        if ( ! plugin->need_reconnect )
                return 0;

        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if ( sock < 0 ) {
                requiem_log(REQUIEM_LOG_WARN, "SMTP: could not open socket: %s.\n", strerror(errno));
                return -1;
        }

        ret = connect(sock, ai->ai_addr, ai->ai_addrlen);
        if ( ret < 0 ) {
                requiem_log(REQUIEM_LOG_WARN, "SMTP: could not connect to %s: %s.\n", plugin->server, strerror(errno));
                close(sock);
                return -1;
        }

        requiem_log(REQUIEM_LOG_INFO, "SMTP: connection to %s succeeded.\n", plugin->server);
        requiem_io_set_sys_io(plugin->fd, sock);

        ret = read_reply(0, plugin->fd, buf, sizeof(buf));
        if ( ret < 0 )
                return ret;

        if ( gethostname(buf, sizeof(buf)) < 0 )
                strcpy(buf, "localhost");

        plugin->need_reconnect = FALSE;

        ret = send_command_va(plugin, 2, "HELO %s\r\n", buf);
        if ( ret < 0 )
                return ret;

        if ( requiem_timer_get_expire(&plugin->keepalive_timer) )
                requiem_timer_reset(&plugin->keepalive_timer);
        else
                requiem_timer_destroy(&plugin->keepalive_timer);

        return 0;
}



static int get_subject(smtp_plugin_t *smtp, idmef_message_t *idmef, requiem_string_t *out)
{
        idmef_alert_t *alert;
        requiem_string_t *str;
        idmef_classification_t *class;

        if ( ! requiem_list_is_empty(&smtp->subject_content) )
                return build_dynamic_string(out, &smtp->subject_content, idmef);

        else if ( idmef_message_get_heartbeat(idmef) )
                return requiem_string_set_constant(out, "Requiem Heartbeat");

        alert = idmef_message_get_alert(idmef);
        if ( ! alert )
                return requiem_string_set_constant(out, "Unhandled message type");

        class = idmef_alert_get_classification(alert);
        if ( ! class )
                return requiem_string_set_constant(out, "Requiem Alert");

        str = idmef_classification_get_text(class);
        if ( ! str )
                return requiem_string_set_constant(out, "Requiem Alert");

        return requiem_string_set_ref(out, requiem_string_get_string_or_default(str, "Requiem Alert"));
}



static int smtp_run(requiem_plugin_instance_t *pi, idmef_message_t *idmef)
{
        int ret;
        requiem_string_t *subject, *body = NULL;
        smtp_plugin_t *plugin = requiem_plugin_instance_get_plugin_data(pi);

        if ( (plugin->expected_message == EXPECT_MESSAGE_TYPE_ALERT && ! idmef_message_get_alert(idmef)) ||
             (plugin->expected_message == EXPECT_MESSAGE_TYPE_HEARTBEAT && ! idmef_message_get_heartbeat(idmef)) )
                return 0;

        ret = connect_mail_server_if_needed(plugin);
        if ( ret < 0 )
                return ret;

        ret = requiem_string_new(&subject);
        if ( ret < 0 )
                return ret;

        ret = get_subject(plugin, idmef, subject);
        if ( ret < 0 )
                goto out;

        if ( ! requiem_list_is_empty(&plugin->message_content) ) {
                ret = requiem_string_new(&body);
                if ( ret < 0 )
                        goto out;

                ret = build_dynamic_string(body, &plugin->message_content, idmef);
                if ( ret < 0 )
                        goto out;
        }

        ret = send_mail(plugin, requiem_string_get_string(subject), body, idmef);

out:
        requiem_string_destroy(subject);
        if ( body )
                requiem_string_destroy(body);

        return ret;
}



static int smtp_init(requiem_plugin_instance_t *pi, requiem_string_t *out)
{
        int ret;
        char *port;
        struct addrinfo hints;
        smtp_plugin_t *plugin = requiem_plugin_instance_get_plugin_data(pi);

        if ( ! plugin->sender )
                return requiem_error_verbose(REQUIEM_ERROR_GENERIC, "SMTP: No sender specified");

        if ( ! plugin->server )
                return requiem_error_verbose(REQUIEM_ERROR_GENERIC, "SMTP: No server specified");

        if ( ! plugin->recipients )
                return requiem_error_verbose(REQUIEM_ERROR_GENERIC, "SMTP: No recipients specified");

        port = strrchr(plugin->server, ':');
        if ( port ) {
                *port = 0;
                port++;
        }

        memset(&hints, 0, sizeof(hints));

        hints.ai_flags = AI_PASSIVE;
        hints.ai_family = PF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        if ( plugin->ai_addr ) {
                freeaddrinfo(plugin->ai_addr);
                plugin->ai_addr = NULL;
        }

        ret = getaddrinfo(plugin->server, port ? port : DEFAULT_SMTP_PORT, &hints, &plugin->ai_addr);
        if ( ret < 0 )
                return requiem_error_verbose(REQUIEM_ERROR_GENERIC, "SMTP: could not resolve '%s': %s", plugin->server, gai_strerror(ret));

        if ( port ) *port = ':';

        ret = connect_mail_server_if_needed(plugin);
        if ( ret < 0 )
                return requiem_error_verbose(REQUIEM_ERROR_GENERIC, "SMTP: could not connect to '%s': %s", plugin->server, strerror(errno));

#ifdef HAVE_LIBREQUIEMDB
        if ( plugin->type ) {
                ret = db_init(pi, out);
                if ( ret < 0 )
                        return ret;
        }

        if ( ! requiem_list_is_empty(&plugin->correlation_content) && ! plugin->db )
                return requiem_error_verbose(REQUIEM_ERROR_GENERIC, "SMTP: correlation template require database configuration");
#endif

        return 0;
}



static int smtp_new(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        int ret;
        smtp_plugin_t *new;

        new = calloc(sizeof(*new), 1);
        if ( ! new )
                return requiem_error_from_errno(errno);

        new->sender = strdup(DEFAULT_MAIL_SENDER);
        if ( ! new->sender ) {
                requiem_string_sprintf(err, "error duplicating sender address");
                free(new);
                return -1;
        }

        new->need_reconnect = TRUE;
        requiem_list_init(&new->subject_content);
        requiem_list_init(&new->message_content);
        new->expected_message = EXPECT_MESSAGE_TYPE_ANY;

#ifdef HAVE_LIBREQUIEMDB
        requiem_list_init(&new->correlation_content);
#endif

        requiem_timer_init_list(&new->keepalive_timer);
        requiem_timer_set_data(&new->keepalive_timer, new);
        requiem_timer_set_callback(&new->keepalive_timer, keepalive_smtp_conn);
        requiem_timer_set_expire(&new->keepalive_timer, DEFAULT_KEEPALIVE_SECONDS);

        ret = requiem_io_new(&new->fd);
        if ( ret < 0 )
                return ret;

        requiem_plugin_instance_set_plugin_data(context, new);

        return 0;
}


static int smtp_set_keepalive(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        smtp_plugin_t *plugin = requiem_plugin_instance_get_plugin_data(context);
        requiem_timer_set_expire(&plugin->keepalive_timer, atoi(arg));
        return 0;
}



static mail_format_t *new_mail_format(requiem_list_t *head)
{
        mail_format_t *fmt;

        fmt = calloc(1, sizeof(*fmt));
        if ( ! fmt )
                return NULL;

        requiem_list_init(&fmt->sublist);
        requiem_list_add_tail(head, &fmt->list);

        return fmt;
}



static int new_mail_format_from_string(requiem_list_t *head, requiem_string_t *str)
{
        mail_format_t *fmt;

        if ( requiem_string_is_empty(str) )
                return 0;

        fmt = new_mail_format(head);
        if ( ! fmt )
                return -1;

        requiem_string_get_string_released(str, &fmt->fixed);

        return 0;
}



static int parse_path(smtp_plugin_t *plugin, mail_format_t **fmt,
                      requiem_list_t *head, requiem_string_t *str, const char **in)
{
        int ret;
        size_t i = 0;
        idmef_path_t *path;
        char path_s[1024], *ptr;

        ptr = path_s;
        while ( i < sizeof(path_s) - 1 &&
                (isalnum(**in) || **in == '(' || **in == ')' || **in == '.' || **in == '-' || **in == '_' || **in == '*') ) {
                path_s[i++] = **in;
                (*in)++;
        }

        path_s[i] = 0;

        new_mail_format_from_string(head, str);
        requiem_string_clear(str);

        if ( strncmp(path_s, "alert", 5) == 0 ) {
                if ( plugin->expected_message == EXPECT_MESSAGE_TYPE_HEARTBEAT )
                        return requiem_error_verbose(REQUIEM_ERROR_GENERIC, "cannot mix alert and heartbeat toplevel message.\n");

                plugin->expected_message = EXPECT_MESSAGE_TYPE_ALERT;
        } else {
                if ( plugin->expected_message == EXPECT_MESSAGE_TYPE_ALERT )
                        return requiem_error_verbose(REQUIEM_ERROR_GENERIC, "cannot mix alert and heartbeat toplevel message.\n");

                plugin->expected_message = EXPECT_MESSAGE_TYPE_HEARTBEAT;
        }

        ret = idmef_path_new_fast(&path, path_s);
        if ( ret < 0 )
                return ret;

        *fmt = new_mail_format(head);
        (*fmt)->path = path;

        return 0;
}


static int set_formated_text(smtp_plugin_t *plugin, requiem_list_t *content_list, const char *input)
{
        int ret;
        requiem_string_t *str;
        mail_format_t *fmt = NULL;

        requiem_string_new(&str);
        while ( *input ) {
                if ( strncmp(input, "#if ", 4) == 0 ) {
                        char *end;

                        end = strstr(input, "#end if");
                        if ( ! end )
                                return requiem_error_verbose(REQUIEM_ERROR_GENERIC, "Unterminated #if: missing #endif block");;

                        input = strpbrk(input, "$\n");
                        if ( ! input || *input != '$' )
                                return requiem_error_verbose(REQUIEM_ERROR_GENERIC, "'#if' operator lack condition");

                        input += 1;

                        ret = parse_path(plugin, &fmt, content_list, str, &input);
                        if ( ret < 0 )
                                return ret;

                        input = strchr(input, '\n');
                        if ( ! input )
                                return requiem_error_verbose(REQUIEM_ERROR_GENERIC, "Missing carriage return after '#if'");

                        fmt->type = MAIL_FORMAT_TYPE_IF;

                        *end = 0;
                        ret = set_formated_text(plugin, &fmt->sublist, input + 1);
                        *end = '#';

                        input = strchr(end, '\n');
                        if ( ! input )
                                return requiem_error_verbose(REQUIEM_ERROR_GENERIC, "Missing carriage return after '#end if'");

                        input += 1;
                }

                else if ( *input != '$' )
                        requiem_string_ncat(str, input++, 1);

                else {
                        input += 1;

                        ret = parse_path(plugin, &fmt, content_list, str, &input);
                        if ( ret < 0 )
                                return ret;
                }
        }

        new_mail_format_from_string(content_list, str);
        requiem_string_destroy(str);

        return 0;
}


static int smtp_set_subject(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        smtp_plugin_t *plugin = requiem_plugin_instance_get_plugin_data(context);
        return set_formated_text(plugin, &plugin->subject_content, arg);
}



static int set_template(smtp_plugin_t *plugin, const char *fname, requiem_list_t *content)
{
        int ret;
        FILE *fd;
        char buf[8192];
        requiem_string_t *str;

        fd = fopen(fname, "r");
        if ( ! fd ) {
                requiem_log(REQUIEM_LOG_ERR, "could not open mail template '%s': %s.\n", fname, strerror(errno));
                return -1;
        }

        ret = requiem_string_new(&str);
        if ( ret < 0 ) {
                fclose(fd);
                return ret;
        }

        while ( fgets(buf, sizeof(buf), fd) )
                requiem_string_cat(str, buf);

        fclose(fd);

        ret = set_formated_text(plugin, content, requiem_string_get_string(str));
        requiem_string_destroy(str);

        return ret;
}

static int smtp_set_template(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        smtp_plugin_t *plugin = requiem_plugin_instance_get_plugin_data(context);
        return set_template(plugin, arg, &plugin->message_content);
}


#ifdef HAVE_LIBREQUIEMDB
static int smtp_set_correlation_template(requiem_option_t *opt, const char *arg, requiem_string_t *err, void *context)
{
        smtp_plugin_t *plugin = requiem_plugin_instance_get_plugin_data(context);
        return set_template(plugin, arg, &plugin->correlation_content);
}
#endif


static int smtp_get_keepalive(requiem_option_t *opt, requiem_string_t *out, void *context)
{
        smtp_plugin_t *plugin = requiem_plugin_instance_get_plugin_data(context);
        return requiem_string_sprintf(out, "%d", requiem_timer_get_expire(&plugin->keepalive_timer));
}



static void destroy_mail_format(requiem_list_t *head)
{
        mail_format_t *format;
        requiem_list_t *tmp, *bkp;

        requiem_list_for_each_safe(head, tmp, bkp) {
                format = requiem_list_entry(tmp, mail_format_t, list);

                destroy_mail_format(&format->sublist);

                if ( format->path )
                        idmef_path_destroy(format->path);

                if ( format->fixed )
                        free(format->fixed);

                requiem_list_del(&format->list);
        }
}



static void smtp_destroy(requiem_plugin_instance_t *pi, requiem_string_t *err)
{
        smtp_plugin_t *plugin = requiem_plugin_instance_get_plugin_data(pi);

        destroy_mail_format(&plugin->subject_content);
        destroy_mail_format(&plugin->message_content);

        if ( plugin->server )
                free(plugin->server);

        if ( plugin->sender )
                free(plugin->sender);

        if ( plugin->recipients )
                free(plugin->recipients);

        if ( plugin->ai_addr )
                freeaddrinfo(plugin->ai_addr);

#ifdef HAVE_LIBREQUIEMDB
        destroy_mail_format(&plugin->correlation_content);

        if ( plugin->type )
                free(plugin->type);

        if ( plugin->log )
                free(plugin->log);

        if ( plugin->host )
                free(plugin->host);

        if ( plugin->port )
                free(plugin->port);

        if ( plugin->name )
                free(plugin->name);

        if ( plugin->user )
                free(plugin->user);

        if ( plugin->pass )
                free(plugin->pass);

        if ( plugin->file )
                free(plugin->file);

        if ( plugin->db )
                requiemdb_destroy(plugin->db);
#endif

        requiem_timer_destroy(&plugin->keepalive_timer);

        if ( ! plugin->need_reconnect )
                requiem_io_close(plugin->fd);

        requiem_io_destroy(plugin->fd);

        free(plugin);
}



int smtp_LTX_manager_plugin_init(requiem_plugin_entry_t *pe, void *rootopt)
{
        int ret;
        requiem_option_t *opt;
        static manager_report_plugin_t smtp_plugin;
        int hook = REQUIEM_OPTION_TYPE_CLI|REQUIEM_OPTION_TYPE_CFG|REQUIEM_OPTION_TYPE_WIDE;

        ret = requiem_option_add(rootopt, &opt, hook, 0, "smtp", "Option for the smtp plugin",
                                 REQUIEM_OPTION_ARGUMENT_OPTIONAL, smtp_new, NULL);
        if ( ret < 0 )
                return ret;

        requiem_plugin_set_activation_option(pe, opt, smtp_init);

        ret = requiem_option_add(opt, NULL, hook, 's', "sender", "Specify send address to use",
                                 REQUIEM_OPTION_ARGUMENT_REQUIRED, smtp_set_sender, smtp_get_sender);
        if ( ret < 0 )
                return ret;

        ret = requiem_option_add(opt, NULL, hook, 'r', "recipients", "Specify recipient address to use",
                                 REQUIEM_OPTION_ARGUMENT_REQUIRED, smtp_set_recipients, smtp_get_recipients);
        if ( ret < 0 )
                return ret;


        ret = requiem_option_add(opt, NULL, hook, 'm', "smtp-server", "Specify SMTP server to use",
                                 REQUIEM_OPTION_ARGUMENT_REQUIRED, smtp_set_server, smtp_get_server);
        if ( ret < 0 )
                return ret;

        ret = requiem_option_add(opt, NULL, hook, 'k', "keepalive", "Specify how often to send keepalive probe (default 60)",
                                 REQUIEM_OPTION_ARGUMENT_REQUIRED, smtp_set_keepalive, smtp_get_keepalive);
        if ( ret < 0 )
                return ret;

        ret = requiem_option_add(opt, NULL, hook, 0, "subject", "Specify message subject (IDMEF path are allowed in the subject string, example: $alert.classification.text)",
                                 REQUIEM_OPTION_ARGUMENT_REQUIRED, smtp_set_subject, NULL);
        if ( ret < 0 )
                return ret;

        ret = requiem_option_add(opt, NULL, hook, 0, "template", "Specify a message template to use with alert",
                                 REQUIEM_OPTION_ARGUMENT_REQUIRED, smtp_set_template, NULL);
        if ( ret < 0 )
                return ret;

#ifdef HAVE_LIBREQUIEMDB
        hook = hook & ~REQUIEM_OPTION_TYPE_CLI;

        ret = requiem_option_add(opt, NULL, hook, 0, "correlated-alert-template", "Specify a message template",
                                 REQUIEM_OPTION_ARGUMENT_REQUIRED, smtp_set_correlation_template, NULL);
        if ( ret < 0 )
                return ret;

        ret = requiem_option_add(opt, NULL, hook, 0, "dbtype", "Type of database (mysql/pgsql)",
                                 REQUIEM_OPTION_ARGUMENT_REQUIRED, db_set_type, db_get_type);
        if ( ret < 0 )
                return ret;

        ret = requiem_option_add(opt, NULL, hook, 0, "dblog",
                                 "Log all queries in a file, should be only used for debugging purpose",
                                 REQUIEM_OPTION_ARGUMENT_OPTIONAL, db_set_log, db_get_log);
        if ( ret < 0 )
                return ret;

        ret = requiem_option_add(opt, NULL, hook, 0, "dbhost",
                                 "The host where the database server is running (in case of client/server database)",
                                 REQUIEM_OPTION_ARGUMENT_REQUIRED,  db_set_host, db_get_host);
        if ( ret < 0 )
                return ret;

        ret = requiem_option_add(opt, NULL, hook, 0, "dbfile",
                                 "The file where the database is stored (in case of file based database)",
                                 REQUIEM_OPTION_ARGUMENT_REQUIRED,  db_set_file, db_get_file);
        if ( ret < 0 )
                return ret;

        ret = requiem_option_add(opt, NULL, hook, 0, "dbport",
                                 "The port where the database server is listening (in case of client/server database)",
                                 REQUIEM_OPTION_ARGUMENT_REQUIRED, db_set_port, db_get_port);
        if ( ret < 0 )
                return ret;

        ret = requiem_option_add(opt, NULL, hook, 0, "dbname",
                                 "The name of the database where the alerts will be stored",
                                 REQUIEM_OPTION_ARGUMENT_REQUIRED, db_set_name, db_get_name);
        if ( ret < 0 )
                return ret;

        ret = requiem_option_add(opt, NULL, hook, 0, "dbuser",
                                 "User of the database (in case of client/server database)",
                                 REQUIEM_OPTION_ARGUMENT_REQUIRED, db_set_user, db_get_user);
        if ( ret < 0 )
                return ret;

        ret = requiem_option_add(opt, NULL, hook, 0, "dbpass",
                                 "Password for the user (in case of client/server database)",
                                 REQUIEM_OPTION_ARGUMENT_REQUIRED, db_set_pass, db_get_pass);
        if ( ret < 0 )
                return ret;
#endif

        requiem_plugin_set_name(&smtp_plugin, "SMTP");
        requiem_plugin_set_destroy_func(&smtp_plugin, smtp_destroy);
        manager_report_plugin_set_running_func(&smtp_plugin, smtp_run);

        requiem_plugin_entry_set_plugin(pe, (void *) &smtp_plugin);

        return 0;
}



int smtp_LTX_requiem_plugin_version(void)
{
        return REQUIEM_PLUGIN_API_VERSION;
}
