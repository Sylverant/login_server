/*
    Sylverant Login Server
    Copyright (C) 2009 Lawrence Sebald

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 3 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>

#include <sylverant/debug.h>
#include <sylverant/database.h>

#include "login.h"
#include "login_packets.h"

/* Handle a client's login request packet. */
static int handle_login(login_client_t *c, login_dclogin_pkt *pkt) {
    uint32_t gc;
    char query[256], dc_id[32], serial[32], access[32];
    void *result;
    char **row;

    sylverant_db_escape_str(&conn, dc_id, pkt->dc_id, 8);

    sprintf(query, "SELECT guildcard FROM dreamcast_clients WHERE dc_id='%s'",
            dc_id);

    /* If we can't query the database, fail. */
    if(sylverant_db_query(&conn, query)) {
        return -1;
    }

    result = sylverant_db_result_store(&conn);

    if((row = sylverant_db_result_fetch(result))) {
        /* We have seen this client before, save their guildcard for use. */
        gc = (uint32_t)strtoul(row[0], NULL, 0);
    }
    else {
        /* Assign a nice fresh new guildcard number to the client. */
        sprintf(query, "INSERT INTO guildcards (account_id) VALUES (NULL)");

        if(sylverant_db_query(&conn, query)) {
            return -1;
        }

        /* Grab the new guildcard for the user. */
        gc = (uint32_t)sylverant_db_insert_id(&conn);

        /* Escape the strings we haven't yet escaped. */
        sylverant_db_escape_str(&conn, serial, pkt->serial, 8);
        sylverant_db_escape_str(&conn, access, pkt->access_key, 8);

        /* Add the client into our database. */
        sprintf(query, "INSERT INTO dreamcast_clients (guildcard, "
                "serial_number, access_key, dc_id) VALUES ('%u', '%s', '%s', "
                "'%s')", gc, serial, access, dc_id);

        if(sylverant_db_query(&conn, query)) {
            return -1;
        }
    }

    return send_dc_security(c, gc, NULL, 0);
}

/* Handle a client's login request packet (yes, this function is the same as the
   one above, but it uses a different structure). */
static int handle_v2login(login_client_t *c, login_dcv2login_pkt *pkt) {
    uint32_t gc;
    char query[256], dc_id[32], serial[32], access[32];
    void *result;
    char **row;

    sylverant_db_escape_str(&conn, dc_id, pkt->dc_id, 8);

    sprintf(query, "SELECT guildcard FROM dreamcast_clients WHERE dc_id='%s'",
            dc_id);

    /* If we can't query the database, fail. */
    if(sylverant_db_query(&conn, query)) {
        return -1;
    }

    result = sylverant_db_result_store(&conn);

    if((row = sylverant_db_result_fetch(result))) {
        /* We have seen this client before, save their guildcard for use. */
        gc = (uint32_t)strtoul(row[0], NULL, 0);
    }
    else {
        /* Assign a nice fresh new guildcard number to the client. */
        sprintf(query, "INSERT INTO guildcards (account_id) VALUES (NULL)");

        if(sylverant_db_query(&conn, query)) {
            return -1;
        }

        /* Grab the new guildcard for the user. */
        gc = (uint32_t)sylverant_db_insert_id(&conn);

        /* Escape the strings we haven't yet escaped. */
        sylverant_db_escape_str(&conn, serial, pkt->serial, 8);
        sylverant_db_escape_str(&conn, access, pkt->access_key, 8);

        /* Add the client into our database. */
        sprintf(query, "INSERT INTO dreamcast_clients (guildcard, "
                "serial_number, access_key, dc_id) VALUES ('%u', '%s', '%s', "
                "'%s')", gc, serial, access, dc_id);

        if(sylverant_db_query(&conn, query)) {
            return -1;
        }
    }

    return send_dc_security(c, gc, NULL, 0);
}

/* Handle a client's ship select packet. */
static int handle_ship_select(login_client_t *c,
                              dc_login_ship_select_pkt *pkt) {
    extern int ship_transfer(login_client_t *c, uint32_t shipid);
    
    return ship_transfer(c, LE32(pkt->item_id));
}

/* Process one login packet. */
int process_dclogin_packet(login_client_t *c, void *pkt) {
    dc_pkt_header_t *dc = (dc_pkt_header_t *)pkt;
    pc_pkt_header_t *pc = (pc_pkt_header_t *)pkt;
    uint8_t type;

    if(c->type == CLIENT_TYPE_DC) {
        type = dc->pkt_type;
    }
    else {
        type = pc->pkt_type;
    }

    debug(DBG_LOG, "DC/PC: Receieved type 0x%02X\n", type);

    switch(type) {
        case LOGIN_DC_LOGIN0_TYPE:
            /* XXXX: Do something with this sometime. */
            return send_simple(c, LOGIN_DC_LOGIN0_TYPE, 1);

        case LOGIN_DC_LOGIN2_TYPE:
            /* XXXX: Do something with this sometime. */
            return send_simple(c, LOGIN_DC_LOGIN2_TYPE, 1);

        case LOGIN_CLIENT_LOGIN_TYPE:
            /* XXXX: Figure this all out sometime. */
            return handle_login(c, (login_dclogin_pkt *)pkt);

        case LOGIN_DCV2_LOGINA_TYPE:
            /* XXXX: You had to switch packets on me, didn't you Sega? */
            return handle_v2login(c, (login_dcv2login_pkt *)pkt);

        case LOGIN_DC_CHECKSUM_TYPE:
            /* XXXX: ??? */
            return send_simple(c, LOGIN_DC_CHECKSUM_REPLY_TYPE, 1);

        case LOGIN_TIMESTAMP_TYPE:
            /* XXXX: Actually, I've got nothing here. */
            return send_timestamp(c);

        case LOGIN_DC_SHIP_LIST_REQ_TYPE:
            /* XXXX: I don't have anything here either, but thought I'd be
               funny anyway. */
            return send_ship_list(c);

        case LOGIN_INFO_REQUEST_TYPE:
            /* XXXX: Actually send something relevant! */
            return send_info_reply(c, "Nothing here.");

        case LOGIN_SHIP_SELECT_TYPE:
            /* XXXX: This might actually work, at least if there's a ship. */
            return handle_ship_select(c, (dc_login_ship_select_pkt *)pkt);

        default:
            return -3;
    }

    return 0;
}
