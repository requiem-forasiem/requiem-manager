/*****
*
* Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
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

#ifndef _MANAGER_PCONFIG_H
#define _MANAGER_PCONFIG_H

#include "server-generic.h"

int manager_options_init(requiem_option_t *manager_root_optlist, int *argc, char **argv);

int manager_options_read(requiem_option_t *manager_root_optlist, int *argc, char **argv);

typedef struct manager_config {

        const char *pidfile;
        const char *config_file;
        const char *tls_options;

        int dh_bits;
        int dh_regenerate;
        int connection_timeout;

        size_t nserver;
        server_generic_t **server;
} manager_config_t;

#endif /* _MANAGER_PCONFIG_H */
