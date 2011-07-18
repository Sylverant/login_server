/*
    Sylverant Login Server
    Copyright (C) 2009, 2010, 2011 Lawrence Sebald

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

#include <stdint.h>
#include <netinet/in.h>

#include <sylverant/encryption.h>
#include <sylverant/quest.h>

#include "login.h"
#include "player.h"
#include "packets.h"

#define MENU_ID_INITIAL         0x00000000
#define MENU_ID_SHIP            0x00000001
#define MENU_ID_QUEST           0x00000004
#define MENU_ID_GM              0x00000007
#define MENU_ID_INFODESK        0x000000FF
#define MENU_ID_DATABASE        0x00040000

#define ITEM_ID_INIT_SHIP       0x00000000
#define ITEM_ID_INIT_DOWNLOAD   0x00000001
#define ITEM_ID_INIT_INFO       0x00000002
#define ITEM_ID_INIT_GM         0x00000003

#define ITEM_ID_GM_REFRESH_Q    0x00000000
#define ITEM_ID_GM_RESTART      0x00000001
#define ITEM_ID_GM_SHUTDOWN     0x00000002

/* This must be placed into the copyright field in the BB welcome packet. */
const static char login_bb_welcome_copyright[] =
    "Phantasy Star Online Blue Burst Game Server. "
    "Copyright 1999-2004 SONICTEAM.";

/* This must be placed into the copyright field in the DC welcome packet. */
const static char login_dc_welcome_copyright[] =
    "DreamCast Port Map. Copyright SEGA Enterprises. 1999";

/* Send a Dreamcast Welcome packet to the given client. */
int send_dc_welcome(login_client_t *c, uint32_t svect, uint32_t cvect);

/* Send a Blue Burst Welcome packet to the given client. */
int send_bb_welcome(login_client_t *c, const uint8_t svect[48],
                    const uint8_t cvect[48]);

/* Send a large message packet to the given client. */
int send_large_msg(login_client_t *c, const char msg[]);

/* Send a scrolling message packet to the given client. */
int send_scroll_msg(login_client_t *c, const char msg[]);

/* Send the Dreamcast security packet to the given client. */
int send_dc_security(login_client_t *c, uint32_t gc, const void *data,
                     int data_len);

/* Send the Blue Burst security packet to the given client. */
int send_bb_security(login_client_t *c, uint32_t gc, uint32_t err,
                     uint32_t team, const void *data, int data_len);

/* Send a redirect packet to the given client. */
int send_redirect(login_client_t *c, in_addr_t ip, uint16_t port);

#ifdef ENABLE_IPV6
/* Send a redirect packet (IPv6) to the given client. */
int send_redirect6(login_client_t *c, const uint8_t ip[16], uint16_t port);
#endif

/* Send a packet to clients connecting on the Gamecube port to sort out any PC
   clients that might end up there. This must be sent before encryption is set
   up! */
int send_selective_redirect(login_client_t *c);

/* Send a timestamp packet to the given client. */
int send_timestamp(login_client_t *c);

/* Send the initial menu to clients, with the options of "Ship Select" and
   "Download". */
int send_initial_menu(login_client_t *c);

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

/* Send an Episode 3 rank update to a client. */
int send_ep3_rank_update(login_client_t *c);

/* Send the Episode 3 card list to a client. */
int send_ep3_card_update(login_client_t *c);

/* Send a Blue Burst option reply to the client. */
int send_bb_option_reply(login_client_t *c, const uint8_t keys[420]);

/* Send a Blue Burst character acknowledgement to the client. */
int send_bb_char_ack(login_client_t *c, uint8_t slot, uint8_t code);

/* Send a Blue Burst checksum acknowledgement to the client. */
int send_bb_checksum_ack(login_client_t *c, uint32_t ack);

/* Send a Blue Burst guildcard header packet. */
int send_bb_guild_header(login_client_t *c, uint32_t checksum);

/* Send a Blue Burst guildcard chunk packet. */
int send_bb_guild_chunk(login_client_t *c, uint32_t chunk);

/* Send a prepared Blue Burst packet. */
int send_bb_pkt(login_client_t *c, bb_pkt_hdr_t *hdr);

/* Send a Blue Burst character preview packet. */
int send_bb_char_preview(login_client_t *c, const sylverant_bb_mini_char_t *mc,
                         uint8_t slot);

/* Send the content of the "Information" menu. */
int send_info_list(login_client_t *c);

/* Send a message box packet to the user. */
int send_message_box(login_client_t *c, const char *fmt, ...);

/* Send a message box containing an information file entry. */
int send_info_file(login_client_t *c, uint32_t entry);

/* Send the GM operations menu to the user. */
int send_gm_menu(login_client_t *c);

#endif /* !LOGIN_PACKETS_H */
