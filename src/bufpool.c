/*****
*
* Copyright (C) 2007 PreludeIDS Technologies. All Rights Reserved.
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

#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <assert.h>

#include <librequiem/requiem.h>
#include <librequiem/requiem-failover.h>

#include "glthread/lock.h"
#include "bufpool.h"

#define DISK_THRESHOLD_DEFAULT 1 * (1024 * 1024)


struct bufpool {
        requiem_list_t list;
        requiem_failover_t *failover;

        requiem_list_t msglist;
        char *filename;

        gl_lock_t mutex;

        size_t len;
        size_t count;
};


static REQUIEM_LIST(pool_list);
static size_t on_disk_threshold = DISK_THRESHOLD_DEFAULT;
static gl_lock_t mutex = gl_lock_initializer;
static gl_lock_t destroy_prevention = gl_lock_initializer;

static size_t mem_msglen = 0, mem_msgcount = 0;
static size_t disk_msglen = 0, disk_msgcount = 0;



/*
 * When adding a message to a queue, if the amount of memory used by
 * all queue reach on_disk_threshold, then we find the queue using most
 * memory, and flush it to disk.
 *
 * When the memory usage become normal again (no more EPS than the
 * manager can process, the failover is destroyed.
 */


static inline void inc_dlen(bufpool_t *bp, size_t len)
{
        gl_lock_lock(mutex);
        disk_msglen += len;
        disk_msgcount++;
        gl_lock_unlock(mutex);

        bp->count++;
}


static inline void dec_dlen(bufpool_t *bp, size_t len)
{
        gl_lock_lock(mutex);
        disk_msglen -= len;
        disk_msgcount--;
        gl_lock_unlock(mutex);

        bp->count--;
}

static inline void inc_len(bufpool_t *bp, size_t len)
{
        gl_lock_lock(mutex);
        mem_msglen += len;
        mem_msgcount++;
        gl_lock_unlock(mutex);

        bp->len += len;
        bp->count++;
}



static inline void dec_len(bufpool_t *bp, size_t len)
{
        gl_lock_lock(mutex);
        mem_msglen -= len;
        mem_msgcount--;
        gl_lock_unlock(mutex);

        bp->len -= len;
        bp->count--;
}



static int flush_bufpool_to_disk(bufpool_t *bp)
{
        int ret;
        requiem_msg_t *msg;
        requiem_list_t *tmp, *bkp;

        ret = requiem_failover_new(&bp->failover, bp->filename);
        if ( ret < 0 )
                return ret;

        requiem_list_for_each_safe(&bp->msglist, tmp, bkp) {
                msg = requiem_linked_object_get_object(tmp);
                requiem_linked_object_del((requiem_linked_object_t *) msg);

                ret = requiem_failover_save_msg(bp->failover, msg);
                if ( ret < 0 ) {
                        requiem_log(REQUIEM_LOG_ERR, "failover write failure: %s.\n", requiem_strerror(ret));
                        requiem_msg_destroy(msg);
                        break;
                }

                inc_dlen(bp, requiem_msg_get_len(msg));
                dec_len(bp, requiem_msg_get_len(msg));
                requiem_msg_destroy(msg);
        }

        gl_lock_lock(mutex);
        requiem_list_del_init(&bp->list);
        gl_lock_unlock(mutex);

        return ret;
}


static bufpool_t *evict_from_memory(void)
{
        int ret;
        size_t prev_len = 0;
        bufpool_t *bp = NULL, *evict = NULL;

        while ( 1 ) {
                gl_lock_lock(destroy_prevention);

                gl_lock_lock(mutex);
                bp = requiem_list_get_next(&pool_list, bp, bufpool_t, list);
                gl_lock_unlock(mutex);

                if ( ! bp ) {
                        gl_lock_unlock(destroy_prevention);
                        break;
                }

                gl_lock_lock(bp->mutex);
                gl_lock_unlock(destroy_prevention);

                if ( bp->failover ) {
                        gl_lock_unlock(bp->mutex);
                        continue;
                }

                if ( ! evict )
                        evict = bp;

                else if ( bp->len > prev_len ) {
                        gl_lock_unlock(evict->mutex);

                        evict = bp;
                        prev_len = bp->len;
                } else
                        gl_lock_unlock(bp->mutex);
        }


        if ( evict ) {
                ret = flush_bufpool_to_disk(evict);
                gl_lock_unlock(evict->mutex);
                return evict;
        }

        return NULL;
}


static inline size_t get_total_mem(void)
{
        size_t total;

        gl_lock_lock(mutex);
        total = mem_msglen;
        gl_lock_unlock(mutex);

        return total;
}


int bufpool_add_message(bufpool_t *bp, requiem_msg_t *msg)
{
        int ret = 0;
        bufpool_t *evicted;
        size_t len = requiem_msg_get_len(msg);

        while ( get_total_mem() + len >= on_disk_threshold ) {
                evicted = evict_from_memory();
                if ( evicted == NULL || evicted == bp )
                        break;
        }

        gl_lock_lock(bp->mutex);

        if ( ! bp->failover ) {
                requiem_linked_object_add_tail(&bp->msglist, (requiem_linked_object_t *) msg);
                inc_len(bp, len);
        }

        else {
                ret = requiem_failover_save_msg(bp->failover, msg);
                inc_dlen(bp, requiem_msg_get_len(msg));
                requiem_msg_destroy(msg);
        }

        gl_lock_unlock(bp->mutex);

        return ret;
}


static void failover_destroy(bufpool_t *bp)
{
        requiem_failover_destroy(bp->failover);
        bp->failover = NULL;

        gl_lock_lock(mutex);
        requiem_list_add_tail(&pool_list, &bp->list);
        gl_lock_unlock(mutex);
}



int bufpool_get_message(bufpool_t *bp, requiem_msg_t **out)
{
        int ret;
        requiem_list_t *tmp;
        requiem_msg_t *msg = NULL;

        gl_lock_lock(bp->mutex);

        requiem_list_for_each(&bp->msglist, tmp) {
                msg = requiem_linked_object_get_object(tmp);
                requiem_linked_object_del((requiem_linked_object_t *) msg);
                dec_len(bp, requiem_msg_get_len(msg));
                break;
        }

        if ( ! msg && bp->failover ) {
                ret = requiem_failover_get_saved_msg(bp->failover, &msg);
                if ( ret < 0 ) {
                        requiem_log(REQUIEM_LOG_ERR, "could not retrieve message from failover: %s.\n", requiem_strerror(ret));
                        failover_destroy(bp);
                }

                else if ( bp->count - 1 == 0 ) {
                        requiem_msg_t *tmsg;

                        ret = requiem_failover_get_saved_msg(bp->failover, &tmsg);
                        assert(ret == 0);

                        failover_destroy(bp);
                }

                if ( msg )
                        dec_dlen(bp, requiem_msg_get_len(msg));
        }

        assert(msg || bp->count == 0);
        gl_lock_unlock(bp->mutex);

        *out = msg;
        return (msg) ? 1 : 0;
}



int bufpool_new(bufpool_t **bp, const char *filename)
{
        *bp = malloc(sizeof(**bp));
        if ( ! *bp )
                return -1;

        (*bp)->len = 0;
        (*bp)->count = 0;
        (*bp)->failover = NULL;
        requiem_list_init(&(*bp)->msglist);

        (*bp)->filename = strdup(filename);
        if ( ! (*bp)->filename ) {
                free(*bp);
                return requiem_error_from_errno(errno);
        }

        gl_lock_init((*bp)->mutex);

        gl_lock_lock(mutex);
        requiem_list_add_tail(&pool_list, &(*bp)->list);
        gl_lock_unlock(mutex);

        return 0;
}


void bufpool_destroy(bufpool_t *bp)
{
        gl_lock_lock(destroy_prevention);
        gl_lock_lock(bp->mutex);
        gl_lock_unlock(destroy_prevention);

        gl_lock_lock(mutex);
        requiem_list_del(&bp->list);
        gl_lock_unlock(mutex);

        if ( bp->failover )
                requiem_failover_destroy(bp->failover);

        gl_lock_unlock(bp->mutex);
        gl_lock_destroy(bp->mutex);

        free(bp->filename);
        free(bp);
}


void bufpool_set_disk_threshold(size_t threshold)
{
        on_disk_threshold = threshold;
}


size_t bufpool_get_message_count(bufpool_t *bp)
{
        size_t count;

        gl_lock_lock(bp->mutex);
        count = bp->count;
        gl_lock_unlock(bp->mutex);

        return count;
}



void bufpool_print_stats(void)
{
        uint64_t dl, dc, ml, mc;

        gl_lock_lock(mutex);
        dl = disk_msglen;
        dc = disk_msgcount;
        ml = mem_msglen;
        mc = mem_msgcount;
        gl_lock_unlock(mutex);

        requiem_log(REQUIEM_LOG_INFO, "disk_len=%" REQUIEM_PRIu64 " disk_count=%" REQUIEM_PRIu64 " mem_len=%" REQUIEM_PRIu64 " mem_count=%" REQUIEM_PRIu64 "\n", dl, dc, ml, mc);
}
