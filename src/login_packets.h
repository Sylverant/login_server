/*
    Sylverant Login Server
    Copyright (C) 2009, 2010 Lawrence Sebald

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License version 3
    as published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef LOGIN_PACKETS_H
#define LOGIN_PACKETS_H

#include <inttypes.h>
#include <netinet/in.h>

#include <sylverant/encryption.h>
#include <sylverant/quest.h>

#include "login.h"
#include "packets.h"

/* This must be placed into the copyright field in the BB welcome packet. */
const static char login_bb_welcome_copyright[] =
    "Phantasy Star Online Blue Burst Game Server. "
    "Copyright 1999-2004 SONICTEAM.";

/* This must be placed into the copyright field in the DC welcome packet. */
const static char login_dc_welcome_copyright[] =
    "DreamCast Port Map. Copyright SEGA Enterprises. 1999";

/* Send a Dreamcast Welcome packet to the given client. */
int send_dc_welcome(login_client_t *c, uint32_t svect, uint32_t cvect);

/* Send a large message packet to the given client. */
int send_large_msg(login_client_t *c, const char msg[]);

/* Send the Dreamcast security packet to the given client. */
int send_dc_security(login_client_t *c, uint32_t gc, uint8_t *data,
                     int data_len);

/* Send a redirect packet to the given client. */
int send_redirect(login_client_t *c, in_addr_t ip, uint16_t port);

/* Send a packet to clients connecting on the Gamecube port to sort out any PC
   clients that might end up there. This must be sent before encryption is set
   up! */
int send_selective_redirect(login_client_t *c);

/* Send a timestamp packet to the given client. */
int send_timestamp(login_client_t *c);

/* Send the list of ships to the client. */
int send_ship_list(login_client_t *c, uint16_t menu_code);

/* Send a information reply packet to the client. */
int send_info_reply(login_client_t *c, const char msg[]);

/* Send a simple (header-only) packet to the client. */
int send_simple(login_client_t *c, int type, int flags);

/* Send the quest list to a client. */
int send_quest_list(login_client_t *c, sylverant_quest_category_t *l);

/* Send a quest to a client. */
int send_quest(login_client_t *c, sylverant_quest_t *q);

#endif /* !LOGIN_PACKETS_H */
