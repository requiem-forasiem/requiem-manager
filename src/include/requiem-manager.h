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

#include <librequiem/requiem.h>
#include <librequiem/requiem-log.h>


/*
 * Report plugin entry structure.
 */
#define MANAGER_REPORT_PLUGIN_FAILURE_GLOBAL  -1
#define MANAGER_REPORT_PLUGIN_FAILURE_SINGLE  -2

typedef struct {
        REQUIEM_PLUGIN_GENERIC;
        int (*run)(requiem_plugin_instance_t *pi, idmef_message_t *message);
        void (*close)(requiem_plugin_instance_t *pi);
} manager_report_plugin_t;

#define manager_report_plugin_set_running_func(p, f) (p)->run = (f)
#define manager_report_plugin_set_closing_func(p, f) (p)->close = (f)


/*
 * Decode plugin entry structure
 */
typedef struct {
        REQUIEM_PLUGIN_GENERIC;
        unsigned int decode_id;
        int (*run)(requiem_msg_t *ac, idmef_message_t *idmef);
} manager_decode_plugin_t;


#define manager_decode_plugin_set_running_func(p, f) (p)->run = (f)



/*
 * Filter plugin entry structure.
 */
typedef enum {
        MANAGER_FILTER_CATEGORY_REPORTING         = 0,
        MANAGER_FILTER_CATEGORY_REVERSE_RELAYING  = 1,
        MANAGER_FILTER_CATEGORY_PLUGIN            = 2,
        MANAGER_FILTER_CATEGORY_END               = 3  /* should be the latest, do not remove */
} manager_filter_category_t;



typedef struct manager_filter_hook manager_filter_hook_t;


typedef struct {
        REQUIEM_PLUGIN_GENERIC;
        int (*run)(idmef_message_t *message, void *data);
} manager_filter_plugin_t;


#define manager_filter_plugin_set_running_func(p, f) (p)->run = (f)


int manager_filter_new_hook(manager_filter_hook_t **entry,
                            requiem_plugin_instance_t *pi,
                            manager_filter_category_t filtered_category,
                            requiem_plugin_instance_t *filtered_plugin, void *data);


void manager_filter_destroy_hook(manager_filter_hook_t *entry);
