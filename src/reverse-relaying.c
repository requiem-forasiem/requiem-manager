/*****
*
* Copyright (C) 2004-2007,2008 PreludeIDS Technologies. All Rights Reserved.
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
#include <fcntl.h>

#include <librequiem/requiem.h>
#include <librequiem/requiem-log.h>
#include <librequiem/requiem-failover.h>
#include <librequiem/requiem-connection-pool.h>

#include "glthread/lock.h"

#include "reverse-relaying.h"
#include "server-generic.h"
#include "sensor-server.h"
#include "manager-options.h"

#include "sensor-server.h"



struct reverse_relay_receiver {
        requiem_list_t list;


        uint64_t analyzerid;

        unsigned int count;

        requiem_failover_t *failover;
        server_generic_client_t *client;
};


typedef struct {
        requiem_list_t list;

        uint64_t analyzerid;
        requiem_msg_t *msg;
} mqueue_t;


static requiem_msgbuf_t *msgbuf;
static REQUIEM_LIST(mqueue_list);
static gl_lock_t mqueue_mutex = gl_lock_initializer;


static REQUIEM_LIST(receiver_list);
static gl_lock_t receiver_list_mutex = gl_lock_initializer;

extern manager_config_t config;
extern requiem_client_t *manager_client;
static requiem_connection_pool_t *initiator = NULL;


static int connection_event_cb(requiem_connection_pool_t *pool,
                               requiem_connection_pool_event_t event, requiem_connection_t *cnx)
{
        int ret;
        server_generic_client_t *client;

        if ( ! (event & REQUIEM_CONNECTION_POOL_EVENT_ALIVE) )
                return 0;

#if (defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__
        ret = fcntl(requiem_io_get_fd(requiem_connection_get_fd(cnx)), F_SETFL, O_NONBLOCK);
        if ( ret < 0 )
                return requiem_error_verbose(REQUIEM_ERROR_GENERIC, "could not set non blocking mode for client: %s", strerror(errno));
#endif

        ret = sensor_server_add_client(config.server[0], &client, cnx);
        if ( ret < 0 )
                requiem_log(REQUIEM_LOG_WARN, "error adding new client to reverse relay list.\n");

        requiem_connection_set_data(cnx, client);

        return 0;
}



static reverse_relay_receiver_t *get_next_receiver(requiem_list_t **iter)
{
        requiem_list_t *tmp;
        reverse_relay_receiver_t *rrr = NULL;

        /*
         * Locking here is not required since the list is never
         * modified by the worker thread. We only protect writing
         * of the list, and reading it from the worker thread.
         */
        requiem_list_for_each_continue_safe(&receiver_list, tmp, *iter) {
                rrr = requiem_list_entry(tmp, reverse_relay_receiver_t, list);
                break;
        }

        return rrr;
}




int reverse_relay_set_receiver_alive(reverse_relay_receiver_t *rrr, server_generic_client_t *client)
{
        ssize_t size;
        int ret, state;
        requiem_msg_t *msg;
        requiem_failover_t *failover = rrr->failover;

        size = requiem_failover_get_saved_msg(failover, &msg);
        if ( size == 0 )
                rrr->client = client;

        if ( size < 0 ) {
                requiem_perror((requiem_error_t) size, "could not retrieve saved message from disk");
                return -1;
        }

        if ( size > 0 ) {
                rrr->count++;

                state = server_generic_client_get_state(client);
                if ( ! (state & SERVER_GENERIC_CLIENT_STATE_FLUSHING) )
                        server_generic_client_set_state(client, state | SERVER_GENERIC_CLIENT_STATE_FLUSHING);

                ret = sensor_server_write_client(client, msg);
                if ( ret < 0 ) {
                        if ( requiem_error_get_code(ret) == REQUIEM_ERROR_EAGAIN )
                                return 0;

                        return ret;
                }

                server_generic_notify_write_enable(client);
                return 1;
        }

        if ( rrr->count ) {
                server_generic_log_client(client, REQUIEM_LOG_INFO,
                                          "flushed %u messages received while analyzer was offline.\n", rrr->count);
                rrr->count = 0;
        }

        server_generic_client_set_state(client, server_generic_client_get_state(client) & ~SERVER_GENERIC_CLIENT_STATE_FLUSHING);

        return 0;
}



int reverse_relay_set_initiator_dead(requiem_connection_t *cnx)
{
        int ret = -1;

        if ( initiator )
                ret = requiem_connection_pool_set_connection_dead(initiator, cnx);

        return ret;
}



void reverse_relay_set_receiver_dead(reverse_relay_receiver_t *rrr)
{
        rrr->client = NULL;
}



int reverse_relay_new_receiver(reverse_relay_receiver_t **rrr, server_generic_client_t *client, uint64_t analyzerid)
{
        int ret;
        char fname[PATH_MAX];
        reverse_relay_receiver_t *new;

        new = malloc(sizeof(*new));
        if ( ! new )
                return -1;

        new->count = 0;
        new->client = client;
        new->analyzerid = analyzerid;

        requiem_client_profile_get_backup_dirname(requiem_client_get_profile(manager_client), fname, sizeof(fname));
        snprintf(fname + strlen(fname), sizeof(fname) - strlen(fname), "/%" REQUIEM_PRIu64, analyzerid);

        ret = requiem_failover_new(&new->failover, fname);
        if ( ret < 0 ) {
                requiem_perror(ret, "could not create failover");
                free(new);
                return -1;
        }

        gl_lock_lock(receiver_list_mutex);
        requiem_list_add_tail(&receiver_list, &new->list);
        gl_lock_unlock(receiver_list_mutex);
        *rrr = new;

        return 0;
}



reverse_relay_receiver_t *reverse_relay_search_receiver(uint64_t analyzerid)
{
        requiem_list_t *iter = NULL;
        reverse_relay_receiver_t *item;

        while ( (item = get_next_receiver(&iter)) ) {

                if ( analyzerid == item->analyzerid )
                        return item;
        }

        return NULL;
}


static int send_msgbuf(requiem_msgbuf_t *msgbuf, requiem_msg_t *msg)
{
        mqueue_t *mq;

        mq = malloc(sizeof(*mq));
        if ( ! mq ) {
                requiem_log(REQUIEM_LOG_ERR, "memory exhausted: %s.\n", strerror(errno));
                return -1;
        }

        mq->msg = msg;
        mq->analyzerid = *(uint64_t *) requiem_msgbuf_get_data(msgbuf);

        gl_lock_lock(mqueue_mutex);
        requiem_list_add_tail(&mqueue_list, &mq->list);
        gl_lock_unlock(mqueue_mutex);

        return 0;
}



static int get_issuer_analyzerid(idmef_message_t *idmef, uint64_t *analyzerid)
{
        idmef_alert_t *alert;
        idmef_message_type_t type;
        idmef_heartbeat_t *heartbeat;
        idmef_analyzer_t *analyzer = NULL;
        requiem_string_t *id, *last = NULL;

        type = idmef_message_get_type(idmef);

        if ( type == IDMEF_MESSAGE_TYPE_ALERT ) {
                alert = idmef_message_get_alert(idmef);

                while ( (analyzer = idmef_alert_get_next_analyzer(alert, analyzer)) ) {
                        id = idmef_analyzer_get_analyzerid(analyzer);
                        if ( id )
                                last = id;
                }
        }

        else if ( type == IDMEF_MESSAGE_TYPE_HEARTBEAT ) {
                heartbeat = idmef_message_get_heartbeat(idmef);

                while ( (analyzer = idmef_heartbeat_get_next_analyzer(heartbeat, analyzer)) ) {
                        id = idmef_analyzer_get_analyzerid(analyzer);
                        if ( id )
                                last = id;
                }

        }

        else return -1;

        if ( last && requiem_string_get_string(last) )
                *analyzerid = strtoull(requiem_string_get_string(last), NULL, 10);
        else
                *analyzerid = 0;

        return 0;
}



static mqueue_t *mqueue_get_next(void)
{
        mqueue_t *q = NULL;

        gl_lock_lock(mqueue_mutex);

        if ( requiem_list_is_empty(&mqueue_list) )
                goto out;

        q = requiem_list_entry(mqueue_list.next, mqueue_t, list);
        requiem_list_del(&q->list);

out:
        gl_lock_unlock(mqueue_mutex);
        return q;
}



void reverse_relay_send_receiver(idmef_message_t *idmef)
{
        int ret;
        uint64_t analyzerid;
        requiem_bool_t empty;

        /*
         * If there is no receiver, no need to queue the message.
         */
        gl_lock_lock(receiver_list_mutex);
        empty = requiem_list_is_empty(&receiver_list);
        gl_lock_unlock(receiver_list_mutex);

        if ( empty )
                return;

        /*
         * Create a new item in the message queue, containing
         * the message to be sent, as well as the analyzerid of the
         * emitter.
         */
        ret = get_issuer_analyzerid(idmef, &analyzerid);
        if ( ret < 0 )
                return;

        /*
         * Convert from idmef_message_t to requiem_msg_t,
         * this will trigger the msgbuf callback where an mqueue_t
         * object will be created, and attached to the list of message
         * to be emited.
         */
        requiem_msgbuf_set_data(msgbuf, &analyzerid);
        idmef_message_write(idmef, msgbuf);
        requiem_msgbuf_mark_end(msgbuf);

        /*
         * Finally, restart the main server event loop so that it
         * take into account the event to be written, and call
         * reverse_relay_send_prepared().
         */
        server_generic_notify_event();
}



void reverse_relay_send_prepared(void)
{
        int ret;
        mqueue_t *mq;
        requiem_list_t *iter = NULL;
        reverse_relay_receiver_t *receiver;

        while ( (mq = mqueue_get_next()) ) {

                while ( (receiver = get_next_receiver(&iter)) ) {

                        if ( mq->analyzerid == receiver->analyzerid )
                                continue;

                        if ( receiver->client )
                                sensor_server_write_client(receiver->client, requiem_msg_ref(mq->msg));
                        else {
                                ret = requiem_failover_save_msg(receiver->failover, mq->msg);
                                if ( ret < 0 )
                                        requiem_perror(ret, "could not save message to disk");
                        }
                }

                requiem_msg_destroy(mq->msg);
                free(mq);
        }
}


static void destroy_current_initiator(void)
{
        sensor_fd_t *client;
        requiem_list_t *tmp;
        requiem_connection_t *cnx;

        requiem_list_for_each(requiem_connection_pool_get_connection_list(initiator), tmp) {
                cnx = requiem_linked_object_get_object(tmp);

                client = requiem_connection_get_data(cnx);
                if ( client ) {
                        client->cnx = NULL;
                        client->fd = NULL;
                        server_generic_remove_client(config.server[0], (server_generic_client_t *) client);
                }
        }

        requiem_connection_pool_destroy(initiator);
        initiator = NULL;
}



int reverse_relay_create_initiator(const char *arg)
{
        int ret;
        requiem_client_profile_t *cp;

        cp = requiem_client_get_profile(manager_client);

        if ( initiator )
                destroy_current_initiator();

        ret = requiem_connection_pool_new(&initiator, cp, REQUIEM_CONNECTION_PERMISSION_IDMEF_READ);
        if ( ret < 0 )
                goto out;

        requiem_connection_pool_set_flags(initiator, REQUIEM_CONNECTION_POOL_FLAGS_RECONNECT);
        requiem_connection_pool_set_event_handler(initiator, REQUIEM_CONNECTION_POOL_EVENT_DEAD |
                                                  REQUIEM_CONNECTION_POOL_EVENT_ALIVE, connection_event_cb);

        ret = requiem_connection_pool_set_connection_string(initiator, arg);
        if ( ret < 0 ) {
                requiem_connection_pool_destroy(initiator);
                goto out;
        }

        ret = requiem_connection_pool_init(initiator);
        if ( ret < 0 ) {
                requiem_connection_pool_destroy(initiator);
                goto out;
        }

 out:
        return ret;
}



int reverse_relay_init(void)
{
        int ret;

        ret = requiem_msgbuf_new(&msgbuf);
        if ( ! msgbuf ) {
                requiem_perror(ret, "error creating reverse relay msgbuf");
                return -1;
        }

        requiem_msgbuf_set_callback(msgbuf, send_msgbuf);
        requiem_msgbuf_set_flags(msgbuf, REQUIEM_MSGBUF_FLAGS_ASYNC);

        return 0;
}
