/*****
*
* Copyright (C) 2001-2007,2008 PreludeIDS Technologies. All Rights Reserved.
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
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <gnutls/gnutls.h>

#include <librequiem/requiem.h>
#include <librequiem/requiem-log.h>
#include <librequiem/requiem-message-id.h>
#include <librequiem/requiem-ident.h>
#include <librequiem/requiem-extract.h>
#include <librequiem/requiem-connection.h>
#include <librequiem/requiem-connection-pool.h>
#include <librequiem/requiem-option-wide.h>

#include "server-generic.h"
#include "sensor-server.h"
#include "idmef-message-scheduler.h"
#include "manager-options.h"
#include "reverse-relaying.h"

#define TARGET_UNREACHABLE "Destination agent is unreachable"
#define TARGET_PROHIBITED  "Destination agent is administratively prohibited"


extern requiem_client_t *manager_client;

static REQUIEM_LIST(sensors_cnx_list);
static uint32_t global_instance_id = 0;


static sensor_fd_t *search_client(requiem_list_t *head, uint64_t analyzerid, uint32_t instance_id)
{
        sensor_fd_t *client;
        requiem_list_t *tmp;

        requiem_list_for_each(head, tmp) {
                client = requiem_list_entry(tmp, sensor_fd_t, list);

                if ( client->ident == analyzerid && (! instance_id || instance_id == client->instance_id) )
                        return client;
        }

        return NULL;
}



static int write_client(sensor_fd_t *dst, requiem_msg_t *msg)
{
        int ret;

        ret = requiem_msg_write(msg, dst->fd);
        if ( ret < 0 && requiem_error_get_code(ret) == REQUIEM_ERROR_EAGAIN ) {

                requiem_linked_object_add(&dst->write_msg_list, (requiem_linked_object_t *) msg);
                server_generic_notify_write_enable((server_generic_client_t *) dst);

                return ret;
        }

        if ( ret != 0 )
                requiem_log(REQUIEM_LOG_ERR, "could not write msg: %s.\n", requiem_strerror(ret));

        requiem_msg_destroy(msg);

        return ret;
}



static int forward_message_to_analyzerid(sensor_fd_t *client, uint64_t analyzerid, uint32_t instance_no, requiem_msg_t *msg)
{
        int ret = 0;
        uint8_t tag;
        sensor_fd_t *target;

        tag = requiem_msg_get_tag(msg);

        target = search_client(&sensors_cnx_list, analyzerid, instance_no);
        if ( ! target )
                return -1;

        /*
         * if we are connected to the client, we need write permission. If the
         * client connected to us, then read permission need to be set.
         */
        if ( requiem_msg_get_tag(msg) == REQUIEM_MSG_OPTION_REQUEST ) {
                /*
                 * We forward an option request to a client.
                 *
                 * If the client connected to us (->cnx == NULL), we need to check it has READ  permission.
                 * If we connected to the client (->cnx != NULL), we need to check if we have WRITE permission.
                 */
                if ( (! (target->permission & REQUIEM_CONNECTION_PERMISSION_ADMIN_WRITE) && target->we_connected) ||
                     (! (target->permission & REQUIEM_CONNECTION_PERMISSION_ADMIN_READ ) && ! target->we_connected) ) {
                        ret = -2;
                        server_generic_log_client((server_generic_client_t *) client, REQUIEM_LOG_WARN,
                                                  "%" REQUIEM_PRIu64 " credentials forbids admin request.\n", target->ident);
                        goto out;
                }
        }

        sensor_server_write_client((server_generic_client_t *) target, msg);
 out:
        return ret;
}




static int get_msg_target_ident(sensor_fd_t *client, requiem_msg_t *msg,
                                uint64_t **target_ptr, uint32_t *hop_ptr, uint32_t **instance_ptr, int direction)
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        uint64_t ident;
        uint32_t hop = 0, tmp, target_len = 0;

        *target_ptr = NULL;
        *instance_ptr = NULL;

        while ( requiem_msg_get(msg, &tag, &len, &buf) == 0 ) {

                if ( tag == REQUIEM_MSG_OPTION_TARGET_INSTANCE_ID ) {
                        if ( len != sizeof(uint32_t) )
                                return -1;

                        *instance_ptr = buf;
                }

                if ( tag == REQUIEM_MSG_OPTION_TARGET_ID ) {

                        if ( *target_ptr || (len % sizeof(uint64_t)) != 0 || len < 2 * sizeof(uint64_t) )
                                break;

                        target_len = len;
                        *target_ptr = buf;
                }

                if ( tag != REQUIEM_MSG_OPTION_HOP )
                        continue;

                if ( ! *target_ptr || ! *instance_ptr )
                        break;

                ret = requiem_extract_uint32_safe(&hop, buf, len);
                if ( ret < 0 )
                        break;

                if ( hop == 0 )
                        break;

                ret = (direction == REQUIEM_MSG_OPTION_REQUEST) ? hop - 1 : hop + 1;
                if ( ret < 0 || (size_t) ret >= (target_len / sizeof(uint64_t)) )
                        break;

                ident = requiem_extract_uint64(&(*target_ptr)[ret]);
                if ( ident != client->ident )
                        return requiem_error_verbose(REQUIEM_ERROR_GENERIC, "client attempt to mask source identifier");

                hop = (direction == REQUIEM_MSG_OPTION_REQUEST) ? hop + 1 : hop - 1;
                if ( ret < 0 || (size_t) ret >= (target_len / sizeof(uint64_t)) )
                        break;

                if ( hop == (target_len / sizeof(uint64_t)) ) {
                        *hop_ptr = (hop - 1);
                        return 0; /* we are the target */
                }

                tmp = htonl(hop);
                memcpy(buf, &tmp, sizeof(tmp));

                if ( hop >= (target_len / sizeof(uint64_t)) )
                        break;

                *hop_ptr = hop;
                return 0;
        }

        return requiem_error_verbose(REQUIEM_ERROR_GENERIC, "message does not carry a valid target: closing connection");
}



static int send_unreachable_message(server_generic_client_t *client, uint64_t *ident_list,
                                    uint32_t hop, const char *error, size_t size)
{
        ssize_t ret;
        requiem_msg_t *msg;

        ret = requiem_msg_new(&msg, 3,
                              size +
                              sizeof(uint32_t) +
                              hop * sizeof(uint64_t), REQUIEM_MSG_OPTION_REPLY, 0);
        if ( ret < 0 )
                return -1;

        requiem_msg_set(msg, REQUIEM_MSG_OPTION_ERROR, size, error);
        requiem_msg_set(msg, REQUIEM_MSG_OPTION_TARGET_ID, hop * sizeof(uint64_t), ident_list);

        /*
         * cancel the hop increment done previously, and position on target.
         * this function is only supposed to be called for failed request (not failed reply).
         */

        hop -= 2;
        requiem_msg_set(msg, REQUIEM_MSG_OPTION_HOP, sizeof(hop), &hop);

        return sensor_server_write_client(client, msg);
}



static int process_request_cb(requiem_msgbuf_t *msgbuf, requiem_msg_t *msg)
{
        int ret;
        ret = sensor_server_write_client(requiem_msgbuf_get_data(msgbuf), msg);
        if ( ret < 0 && requiem_error_get_code(ret) == REQUIEM_ERROR_EAGAIN )
                return 0; /* message is queued */

        return ret;
}



static int process_option_request(requiem_client_t *dst, sensor_fd_t *src, requiem_msg_t *msg)
{
        int ret;
        requiem_msgbuf_t *buf;

        ret = requiem_msgbuf_new(&buf);
        if ( ret < 0 )
                return ret;

        requiem_msgbuf_set_data(buf, src);
        requiem_msgbuf_set_callback(buf, process_request_cb);
        requiem_msgbuf_set_flags(buf, REQUIEM_MSGBUF_FLAGS_ASYNC);

        /*
         * Stop report plugin processing for safety.
         */
        idmef_message_scheduler_stop_processing();
        ret = requiem_option_process_request(dst, msg, buf);
        idmef_message_scheduler_start_processing();

        requiem_msgbuf_destroy(buf);

        return ret;
}



static int request_sensor_option(server_generic_client_t *client, requiem_msg_t *msg)
{
        int ret;
        uint64_t ident;
        uint64_t *target_route;
        uint32_t target_hop, *instance_id;
        sensor_fd_t *sclient = (sensor_fd_t *) client;
        requiem_client_profile_t *cp = requiem_client_get_profile(manager_client);

        ret = get_msg_target_ident(sclient, msg, &target_route,
                                   &target_hop, &instance_id, REQUIEM_MSG_OPTION_REQUEST);
        if ( ret < 0 )
                return ret;

        /*
         * We receive an option request from client.
         *
         * If the client connected to us (->cnx == NULL), we need to check it has WRITE  permission.
         * If we connected to the client (->cnx != NULL), we need to check it has READ   permission.
         */
        if ( (! (sclient->permission & REQUIEM_CONNECTION_PERMISSION_ADMIN_WRITE) && ! sclient->we_connected) ||
             (! (sclient->permission & REQUIEM_CONNECTION_PERMISSION_ADMIN_READ ) &&   sclient->we_connected) ) {
                server_generic_log_client(client, REQUIEM_LOG_WARN, "insufficient credentials to emit admin request.\n");
                send_unreachable_message(client, target_route, target_hop, TARGET_PROHIBITED, sizeof(TARGET_PROHIBITED));
                requiem_msg_destroy(msg);
                return 0;
        }

        ident = requiem_extract_uint64(&target_route[target_hop]);
        if ( ident == requiem_client_profile_get_analyzerid(cp) ) {
                requiem_msg_recycle(msg);
                ret = process_option_request(manager_client, sclient, msg);
                requiem_msg_destroy(msg);
                return ret;
        }

        *instance_id = htonl(sclient->instance_id);

        ret = forward_message_to_analyzerid(sclient, ident, 0, msg);
        if ( ret == -1 ) {
                send_unreachable_message(client, target_route, target_hop, TARGET_UNREACHABLE, sizeof(TARGET_UNREACHABLE));
                requiem_msg_destroy(msg);
        }

        if ( ret == -2 ) {
                send_unreachable_message(client, target_route, target_hop, TARGET_PROHIBITED, sizeof(TARGET_PROHIBITED));
                requiem_msg_destroy(msg);
        }

        return 0;
}



static int reply_sensor_option(sensor_fd_t *client, requiem_msg_t *msg)
{
        int ret;
        uint64_t *target_route, ident;
        uint32_t target_hop, *instance_no;

        ret = get_msg_target_ident(client, msg, &target_route, &target_hop, &instance_no, REQUIEM_MSG_OPTION_REPLY);
        if ( ret < 0 )
                return ret;

        ident = requiem_extract_uint64(&target_route[target_hop]);

        /*
         * The one replying the option doesn't care about client presence or not.
         */
        ret = forward_message_to_analyzerid(client, ident, requiem_extract_uint32(instance_no), msg);
        if ( ret < 0 )
                requiem_msg_destroy(msg);

        return 0;
}



static int handle_declare_receiver(sensor_fd_t *sclient)
{
        int ret;
        server_generic_client_t *client = (server_generic_client_t *) sclient;

        if ( ! sclient->ident )
                return -1;

        sclient->rrr = reverse_relay_search_receiver(sclient->ident);
        if ( ! sclient->rrr ) {
                /*
                 * First time a child relay with this address connect here.
                 * Add it to the manager list. Type of the created connection is -parent-
                 * because *we* are sending the alert to the child.
                 */
                ret = reverse_relay_new_receiver(&sclient->rrr, client, sclient->ident);
                if ( ret < 0 )
                        return ret;
        }

        server_generic_log_client(client, REQUIEM_LOG_INFO,
                                  "client requested forward of IDMEF message.\n");

        return reverse_relay_set_receiver_alive(sclient->rrr, client);
}




static int handle_declare_client(sensor_fd_t *cnx)
{
        cnx->queue = idmef_message_scheduler_queue_new(manager_client);
        if ( ! cnx->queue )
                return -1;

        cnx->instance_id = ++global_instance_id;
        requiem_list_add_tail(&sensors_cnx_list, &cnx->list);

        return 0;
}



static int handle_capability(sensor_fd_t *cnx, requiem_msg_t *msg)
{
        int ret;
        void *nul;
        uint32_t len;
        uint8_t permission;

        requiem_msg_get(msg, &permission, &len, &nul);

        if ( permission & REQUIEM_CONNECTION_PERMISSION_IDMEF_READ ) {

                if ( ! (cnx->permission & REQUIEM_CONNECTION_PERMISSION_IDMEF_READ) ) {
                        server_generic_log_client((server_generic_client_t *) cnx, REQUIEM_LOG_WARN,
                                                  "insufficient credentials to read IDMEF message: closing connection.\n");
                        return -1;
                }

                ret = handle_declare_receiver(cnx);
                if ( ret < 0 )
                        return ret;
        }

        requiem_msg_destroy(msg);

        return 0;
}



static int handle_msg(sensor_fd_t *client, requiem_msg_t *msg, uint8_t tag)
{
        int ret;

        if ( tag == REQUIEM_MSG_IDMEF ) {
                /*
                 * We receive a message from a client
                 *
                 * If the client connected to us (->cnx == NULL), we need to check it has WRITE  permission.
                 * If we connected to the client (->cnx != NULL), we need to check we have READ   permission.
                 */
                if ( (! (client->permission & REQUIEM_CONNECTION_PERMISSION_IDMEF_WRITE) && ! client->we_connected) ||
                     (! (client->permission & REQUIEM_CONNECTION_PERMISSION_IDMEF_READ ) &&   client->we_connected) ) {
                        server_generic_log_client((server_generic_client_t *) client, REQUIEM_LOG_WARN,
                                                  "insufficient credentials to write IDMEF message.\n");
                        requiem_msg_destroy(msg);
                        return -1;
                }

                ret = idmef_message_schedule(client->queue, msg);
        }

        else if ( tag == REQUIEM_MSG_OPTION_REQUEST )
                ret = request_sensor_option((server_generic_client_t *) client, msg);

        else if ( tag == REQUIEM_MSG_OPTION_REPLY )
                ret = reply_sensor_option(client, msg);

        else if ( tag == REQUIEM_MSG_CONNECTION_CAPABILITY )
                ret = handle_capability(client, msg);

        else {
                /* unknown message, ignore silently for backward compatibility */
                requiem_msg_destroy(msg);
                return 0;
        }

        if ( ret < 0 ) {
                requiem_msg_destroy(msg);
                server_generic_log_client((server_generic_client_t *) client, REQUIEM_LOG_WARN,
                                          "error processing peer message: %s.\n", requiem_strerror(ret));
                return -1;
        }

        return ret;
}



static int read_connection_cb(server_generic_client_t *client)
{
        int ret;
        requiem_msg_t *msg;
        sensor_fd_t *cnx = (sensor_fd_t *) client;

        ret = requiem_msg_read(&cnx->msg, cnx->fd);
        if ( ret < 0 ) {
                requiem_error_code_t code = requiem_error_get_code(ret);

                if ( code == REQUIEM_ERROR_EAGAIN )
                        return 0;

                cnx->msg = NULL;
                if ( code != REQUIEM_ERROR_EOF )
                        server_generic_log_client((server_generic_client_t *) cnx, REQUIEM_LOG_WARN, "%s.\n", requiem_strerror(ret));

                return -1;
        }

        msg = cnx->msg;
        cnx->msg = NULL;

        ret = handle_msg(cnx, msg, requiem_msg_get_tag(msg));
        if ( ret < 0 )
                return ret;

        return 1;
}



static int write_connection_cb(server_generic_client_t *client)
{
        int ret = 1;
        requiem_list_t *tmp;
        requiem_msg_t *cur = NULL;
        sensor_fd_t *sclient = (sensor_fd_t *) client;

        requiem_list_for_each(&sclient->write_msg_list, tmp) {
                cur = requiem_linked_object_get_object(tmp);
                requiem_linked_object_del((requiem_linked_object_t *) cur);

                ret = write_client(sclient, cur);
                if ( ret < 0 && requiem_error_get_code(ret) == REQUIEM_ERROR_EAGAIN ) {
                        ret = 0;
                        goto out;
                }

                break;
        }

        if ( requiem_list_is_empty(&sclient->write_msg_list) ) {
                server_generic_notify_write_disable(client);
                if ( server_generic_client_get_state(client) & SERVER_GENERIC_CLIENT_STATE_FLUSHING )
                        ret = reverse_relay_set_receiver_alive(sclient->rrr, client);
                else
                        ret = 0;
        }

out:
        return ret; /* We yet have other message to process */
}



static int do_close_cnx(server_generic_client_t *ptr, sensor_fd_t *cnx)
{
        int ret;
        void *fd_ptr;
        requiem_error_code_t code;

         do {
                 ret = requiem_connection_close(cnx->cnx);
                 if ( ret == 0 )
                         break;

                 code = requiem_error_get_code(ret);
                 if ( code == REQUIEM_ERROR_EAGAIN ) {

                         fd_ptr = requiem_io_get_fdptr(requiem_connection_get_fd(cnx->cnx));
                         if ( fd_ptr && gnutls_record_get_direction(fd_ptr) == 1 )
                                 server_generic_notify_write_enable(ptr);

                         return -1;
                 }

                 server_generic_log_client(ptr, REQUIEM_LOG_WARN, "%s.\n", requiem_strerror(ret));

         } while ( ret < 0 && ! requiem_io_is_error_fatal(requiem_connection_get_fd(cnx->cnx), ret));

         return 0;
}



static int close_connection_cb(server_generic_client_t *ptr)
{
        int ret;
        requiem_msg_t *msg;
        requiem_list_t *tmp, *bkp;
        sensor_fd_t *cnx = (sensor_fd_t *) ptr;

        if ( cnx->rrr )
                reverse_relay_set_receiver_dead(cnx->rrr);

        else if ( cnx->cnx ) {
                cnx->fd = NULL;
                reverse_relay_set_initiator_dead(cnx->cnx);

                ret = do_close_cnx(ptr, cnx);
                if ( ret < 0 )
                        return -1;
        }


        if ( ! requiem_list_is_empty(&cnx->list) )
                requiem_list_del(&cnx->list);

        requiem_list_for_each_safe(&cnx->write_msg_list, tmp, bkp) {
                msg = requiem_linked_object_get_object(tmp);
                requiem_linked_object_del((requiem_linked_object_t *) msg);
                requiem_msg_destroy(msg);
        }

        /*
         * If cnx->msg is not NULL, it mean the sensor
         * closed the connection without finishing to send
         * a message. Destroy the unfinished message.
         */
        if ( cnx->msg )
                requiem_msg_destroy(cnx->msg);

        if ( cnx->queue )
                idmef_message_scheduler_queue_destroy(cnx->queue);

        return 0;
}




static int accept_connection_cb(server_generic_client_t *ptr)
{
        int ret;
        sensor_fd_t *fd = (sensor_fd_t *) ptr;

        fd->we_connected = FALSE;
        requiem_list_init(&fd->list);
        requiem_list_init(&fd->write_msg_list);

        ret = handle_declare_client(fd);
        if ( ret < 0 )
                return -1;

        return 1; /* more data might be available, the caller shall keep reading */
}



server_generic_t *sensor_server_new(void)
{
        server_generic_t *server;

        server = server_generic_new(sizeof(sensor_fd_t), accept_connection_cb,
                                    read_connection_cb, write_connection_cb, close_connection_cb);
        if ( ! server ) {
                requiem_log(REQUIEM_LOG_WARN, "error creating a generic server.\n");
                return NULL;
        }

        return server;
}



void sensor_server_stop(server_generic_t *server)
{
        server_generic_stop(server);
}




int sensor_server_add_client(server_generic_t *server, server_generic_client_t **client, requiem_connection_t *cnx)
{
        sensor_fd_t *cdata;

        cdata = calloc(1, sizeof(*cdata));
        if ( ! cdata ) {
                requiem_log(REQUIEM_LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        *client = (server_generic_client_t *) cdata;

        cdata->queue = idmef_message_scheduler_queue_new(manager_client);
        if ( ! cdata->queue ) {
                free(cdata);
                return -1;
        }

        cdata->state |= SERVER_GENERIC_CLIENT_STATE_ACCEPTED;
        cdata->fd = requiem_connection_get_fd(cnx);

        cdata->cnx = cnx;
        cdata->rrr = NULL;
        cdata->we_connected = TRUE;

        cdata->server = server;

        requiem_list_init(&cdata->write_msg_list);
        cdata->ident = requiem_connection_get_peer_analyzerid(cnx);

        server_generic_client_set_permission((server_generic_client_t *)cdata, requiem_connection_get_permission(cnx));
        requiem_list_add(&sensors_cnx_list, &cdata->list);

        return server_generic_process_requests(server, (server_generic_client_t *) cdata);
}


int sensor_server_write_client(server_generic_client_t *client, requiem_msg_t *msg)
{
        int ret;
        sensor_fd_t *dst = (sensor_fd_t *) client;

        if ( requiem_list_is_empty(&dst->write_msg_list) )
                ret = write_client(dst, msg);
        else {
                ret = 0;
                requiem_linked_object_add_tail(&dst->write_msg_list, (requiem_linked_object_t *) msg);
        }

        return ret;
}
