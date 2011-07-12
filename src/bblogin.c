/*
    Sylverant Login Server
    Copyright (C) 2011 Lawrence Sebald

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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>

#include <openssl/sha.h>
#include <sylverant/debug.h>
#include <sylverant/database.h>

#include "login.h"
#include "player.h"
#include "packets.h"
#include "login_packets.h"

static int handle_bb_login(login_client_t *c, bb_login_93_pkt *pkt) {
    char query[256];
    int len;
    char tmp[32];
    void *result;
    char **row;
    uint8_t hash[32];
    uint32_t teamid = 0, priv, guildcard;

    /* Make sure the username string is sane... */
    len = strlen(pkt->username);
    if(len > 16 || strlen(pkt->password) > 16) {
        send_bb_security(c, 0, LOGIN_93BB_FORCED_DISCONNECT, 0, NULL, 0);
        return -1;
    }

    sylverant_db_escape_str(&conn, tmp, pkt->username, len);
    sprintf(query, "SELECT account_data.account_id, isbanned, teamid, "
            "privlevel, guildcard, blueburst_clients.password FROM "
            "account_data INNER JOIN blueburst_clients ON "
            "account_data.account_id = blueburst_clients.account_id WHERE "
            "blueburst_clients.username='%s'", tmp);

    /* Query the database for the user... */
    if(sylverant_db_query(&conn, query)) {
        send_bb_security(c, 0, LOGIN_93BB_UNKNOWN_ERROR, 0, NULL, 0);
        return -2;
    }

    result = sylverant_db_result_store(&conn);
    if(!result) {
        send_bb_security(c, 0, LOGIN_93BB_UNKNOWN_ERROR, 0, NULL, 0);
        return -2;
    }

    row = sylverant_db_result_fetch(result);
    if(!row) {
        send_bb_security(c, 0, LOGIN_93BB_NO_USER_RECORD, 0, NULL, 0);
        sylverant_db_result_free(result);
        return -3;
    }

    /* Make sure some simple checks pass first... */
    if(atoi(row[1])) {
        /* User is banned by account. */
        send_bb_security(c, 0, LOGIN_93BB_BANNED, 0, NULL, 0);
        sylverant_db_result_free(result);
        return -4;
    }

    /* If we've gotten this far, we have an account! Check the password. */
    sprintf(tmp, "%s_salt_%s", pkt->password, row[4]);
    SHA256((unsigned char *)tmp, strlen(tmp), hash);

    if(memcmp(hash, row[5], 32)) {
        /* Password check failed... */
        send_bb_security(c, 0, LOGIN_93BB_BAD_USER_PWD, 0, NULL, 0);
        sylverant_db_result_free(result);
        return -6;
    }

    /* Grab the rest of what we care about from the query... */
    errno = 0;
    teamid = (uint32_t)strtoul(row[2], NULL, 0);
    priv = (uint32_t)strtoul(row[3], NULL, 0);
    guildcard = (uint32_t)strtoul(row[4], NULL, 0);
    sylverant_db_result_free(result);

    if(errno) {
        send_bb_security(c, 0, LOGIN_93BB_UNKNOWN_ERROR, 0, NULL, 0);
        return -2;
    }

    /* Set up the security data (everything else is already 0'ed). */
    c->sec_data.magic = LE32(0xDEADBEEF);

    /* Send the security data packet */
    if(send_bb_security(c, guildcard, LOGIN_93BB_OK, teamid, &c->sec_data,
                        sizeof(bb_security_data_t))) {
        return -7;
    }

    /* Last step is to redirect them to the charater data port... */
    return send_redirect(c, cfg->server_ip, 12001);
}


int process_bblogin_packet(login_client_t *c, void *pkt) {
    bb_pkt_hdr_t *bb = (bb_pkt_hdr_t *)pkt;
    uint16_t type = LE16(bb->pkt_type);

    switch(type) {
        case LOGIN_93_TYPE:
            return handle_bb_login(c, (bb_login_93_pkt *)pkt);

        case TYPE_05:
            c->disconnected = 1;
            return 0;

        default:
            printf("Unknown packet (BB Login)!\n");
            print_packet(pkt, LE16(bb->pkt_len));
            return -1;
    }
}
