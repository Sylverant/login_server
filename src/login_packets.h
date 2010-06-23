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

#include <sylverant/characters.h>
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

/* Values for the reason of an acknowledgement of a character. */
#define ACK_CREATE                          0
#define ACK_SELECT                          1
#define ACK_NONEXISTANT                     2

/* Send a Blue Burst Welcome packet to the given client. */
int send_bb_welcome(login_client_t *c, uint8_t svect[48], uint8_t cvect[48]);

/* Send a Dreamcast Welcome packet to the given client. */
int send_dc_welcome(login_client_t *c, uint32_t svect, uint32_t cvect);

/* Send a large message packet to the given client. */
int send_large_msg(login_client_t *c, const char msg[]);

/* Send the Dreamcast security packet to the given client. */
int send_dc_security(login_client_t *c, uint32_t gc, uint8_t *data,
                     int data_len);

/* Send a redirect packet to the given client. */
int send_redirect(login_client_t *c, in_addr_t ip, uint16_t port);

/* Send a timestamp packet to the given client. */
int send_timestamp(login_client_t *c);

/* Send a scrolling message packet to the given client. */
int send_scroll_msg(login_client_t *c, char msg[]);

/* Send a option reply packet to the given client. */
int send_optreply(login_client_t *c, uint8_t keys[420]);

/* Send a character ack to the given client. */
int send_char_ack(login_client_t *c, uint8_t slot, uint8_t reason);

/* Send character data to the given client. */
int send_char_data(login_client_t *c, sylverant_mini_char_t *ch);

/* Send a guild card checksum ack to the given client. */
int send_guild_ack(login_client_t *c, uint32_t ack);

/* Send a guild card checksum packet to the given client. */
int send_gc_checksum(login_client_t *c, uint32_t checksum);

/* Send guild card data to the given client. */
int send_gc_data(login_client_t *c, uint8_t *data, uint8_t idx);

/* Send the list of ships to the client. */
int send_ship_list(login_client_t *c);

/* Send a information reply packet to the client. */
int send_info_reply(login_client_t *c, const char msg[]);

/* Send a simple (header-only) packet to the client. */
int send_simple(login_client_t *c, int type, int flags);

/* Send the quest list to a client. */
int send_quest_list(login_client_t *c, sylverant_quest_category_t *l);

/* Send a quest to a client. */
int send_quest(login_client_t *c, sylverant_quest_t *q);

#endif /* !LOGIN_PACKETS_H */
