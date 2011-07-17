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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <sylverant/debug.h>
#include <sylverant/database.h>
#include <sylverant/quest.h>
#include <sylverant/md5.h>
#include <sylverant/items.h>

#include "login.h"
#include "player.h"
#include "login_packets.h"

mini18n_t langs[CLIENT_LANG_COUNT];

extern sylverant_dbconn_t conn;
extern sylverant_quest_list_t qlist[CLIENT_TYPE_COUNT][CLIENT_LANG_COUNT];
extern sylverant_limits_t *limits;

void print_packet(unsigned char *pkt, int len) {
    unsigned char *pos = pkt, *row = pkt;
    int line = 0, type = 0;

    /* Print the packet both in hex and ASCII. */
    while(pos < pkt + len) {
        if(type == 0) {
            printf("%02X ", *pos);
        }
        else {
            if(*pos >= 0x20 && *pos < 0x7F) {
                printf("%c", *pos);
            }
            else {
                printf(".");
            }
        }

        ++line;
        ++pos;

        if(line == 16) {
            if(type == 0) {
                printf("\t");
                pos = row;
                type = 1;
                line = 0;
            }
            else {
                printf("\n");
                line = 0;
                row = pos;
                type = 0;
            }
        }
    }

    /* Finish off the last row's ASCII if needed. */
    if(len & 0x1F) {
        /* Put spaces in place of the missing hex stuff. */
        while(line != 16) {
            printf("   ");
            ++line;
        }

        pos = row;
        printf("\t");

        /* Here comes the ASCII. */
        while(pos < pkt + len) {
            if(*pos >= 0x20 && *pos < 0x7F) {
                printf("%c", *pos);
            }
            else {
                printf(".");
            }
            
            ++pos;
        }

        printf("\n");
    }
}

/* Check if an IP has been IP banned from the server. */
static int is_ip_banned(login_client_t *c, time_t *until, char *reason) {
    char query[256];
    void *result;
    char **row;
    int rv = 0;
    struct sockaddr_in *addr = (struct sockaddr_in *)&c->ip_addr;

    /* XXXX: Need IPv6 bans too! */
    if(c->is_ipv6) {
        return 0;
    }

    /* Fill in the query. */
    sprintf(query, "SELECT enddate, reason FROM ip_bans NATURAL JOIN bans "
            "WHERE addr = '%u' AND enddate >= UNIX_TIMESTAMP() "
            "AND startdate <= UNIX_TIMESTAMP()",
            (unsigned int)addr->sin_addr.s_addr);

    /* If we can't query the database, fail. */
    if(sylverant_db_query(&conn, query)) {
        return -1;
    }

    /* Grab the results. */
    result = sylverant_db_result_store(&conn);

    /* If there is a result, then the user is banned. */
    if((row = sylverant_db_result_fetch(result))) {
        rv = 1;
        *until = (time_t)strtoul(row[0], NULL, 0);
        strcpy(reason, row[1]);
    }

    sylverant_db_result_free(result);
    return rv;
}

/* Check if a user is banned by guildcard. */
static int is_gc_banned(uint32_t gc, time_t *until, char *reason) {
    char query[256];
    void *result;
    char **row;
    int rv = 0;

    /* Fill in the query. */
    sprintf(query, "SELECT enddate, reason FROM guildcard_bans "
            "NATURAL JOIN bans WHERE guildcard = '%u' AND "
            "enddate >= UNIX_TIMESTAMP() AND "
            "startdate <= UNIX_TIMESTAMP()", (unsigned int)gc);

    /* If we can't query the database, fail. */
    if(sylverant_db_query(&conn, query)) {
        return -1;
    }

    /* Grab the results. */
    result = sylverant_db_result_store(&conn);

    /* If there is a result, then the user is banned. */
    if((row = sylverant_db_result_fetch(result))) {
        rv = 1;
        *until = (time_t)strtoul(row[0], NULL, 0);
        strcpy(reason, row[1]);
    }

    sylverant_db_result_free(result);
    return rv;
}

static int send_ban_msg(login_client_t *c, time_t until, const char *reason) {
    char string[256];
    struct tm cooked;

    /* Create the ban string. */
    sprintf(string, __(c, "\tEYou have been banned from this server.\n"
            "Reason:\n%s\n\nYour ban expires:\n"), reason);

    if((uint32_t)until == 0xFFFFFFFF) {
        strcat(string, __(c, "Never"));
    }
    else {
        gmtime_r(&until, &cooked);
        sprintf(string, "%s%02u:%02u UTC %u.%02u.%02u", string, cooked.tm_hour,
                cooked.tm_min, cooked.tm_year + 1900, cooked.tm_mon + 1,
                cooked.tm_mday);
    }

    return send_large_msg(c, string);
}

/* Check if a user is already online. */
static int is_gc_online(uint32_t gc) {
    char query[256];
    void *result;
    char **row;
    int rv = 0;

    /* Fill in the query. */
    sprintf(query, "SELECT guildcard FROM online_clients WHERE guildcard='%u'",
            (unsigned int)gc);

    /* If we can't query the database, fail. */
    if(sylverant_db_query(&conn, query)) {
        return -1;
    }

    /* Grab the results. */
    result = sylverant_db_result_store(&conn);

    /* If there is a result, then the user is already online. */
    if((row = sylverant_db_result_fetch(result))) {
        rv = 1;
    }

    sylverant_db_result_free(result);
    return rv;
}

/* Handle a client's login request packet. */
static int handle_login0(login_client_t *c, dc_login_90_pkt *pkt) {
    char query[256],  serial[32], access[32];
    void *result;
    char **row;
    uint8_t resp = LOGIN_90_OK;
    time_t banlen;
    int banned = is_ip_banned(c, &banlen, query);

    /* Make sure the user isn't IP banned. */
    if(banned == -1) {
        send_large_msg(c, __(c, "\tEInternal Server Error.\n"
                       "Please try again later."));
        return -1;
    }
    else if(banned) {
        send_ban_msg(c, banlen, query);
        return -1;
    }

    /* Escape all the important strings. */
    sylverant_db_escape_str(&conn, serial, pkt->serial, 8);
    sylverant_db_escape_str(&conn, access, pkt->access_key, 8);

    sprintf(query, "SELECT guildcard FROM dreamcast_clients WHERE "
            "serial_number='%s' AND access_key='%s'", serial, access);

    /* If we can't query the database, fail. */
    if(sylverant_db_query(&conn, query)) {
        send_large_msg(c, __(c, "\tEInternal Server Error.\n"
                       "Please try again later."));
        return -1;
    }

    result = sylverant_db_result_store(&conn);

    if(!(row = sylverant_db_result_fetch(result))) {
        /* We've not seen this client before, get them to send us a 0x92. */
        resp = LOGIN_90_NEW_USER;
    }

    sylverant_db_result_free(result);

    c->version = SYLVERANT_QUEST_V1;

    return send_simple(c, LOGIN_90_TYPE, resp);
}

static int handle_login3(login_client_t *c, dc_login_93_pkt *pkt) {
    uint32_t gc;
    char query[256], dc_id[32], serial[32], access[32];
    void *result;
    char **row;
    int banned;
    time_t banlen;

    c->language_code = pkt->language_code;

    /* Escape all the important strings. */
    sylverant_db_escape_str(&conn, dc_id, pkt->dc_id, 8);
    sylverant_db_escape_str(&conn, serial, pkt->serial, 8);
    sylverant_db_escape_str(&conn, access, pkt->access_key, 8);

    sprintf(query, "SELECT guildcard FROM dreamcast_clients WHERE dc_id='%s' "
            "AND serial_number='%s' AND access_key='%s'", dc_id, serial,
            access);

    /* If we can't query the database, fail. */
    if(sylverant_db_query(&conn, query)) {
        send_large_msg(c, __(c, "\tEInternal Server Error.\n"
                       "Please try again later."));
        return -1;
    }

    result = sylverant_db_result_store(&conn);

    if((row = sylverant_db_result_fetch(result))) {
        /* We have seen this client before, save their guildcard for use. */
        gc = (uint32_t)strtoul(row[0], NULL, 0);
        sylverant_db_result_free(result);
    }
    else {
        sylverant_db_result_free(result);

        /* Assign a nice fresh new guildcard number to the client. */
        sprintf(query, "INSERT INTO guildcards (account_id) VALUES (NULL)");

        if(sylverant_db_query(&conn, query)) {
            send_large_msg(c, __(c, "\tEInternal Server Error.\n"
                           "Please try again later."));
            return -1;
        }

        /* Grab the new guildcard for the user. */
        gc = (uint32_t)sylverant_db_insert_id(&conn);

        /* Add the client into our database. */
        sprintf(query, "INSERT INTO dreamcast_clients (guildcard, "
                "serial_number, access_key, dc_id) VALUES ('%u', '%s', '%s', "
                "'%s')", gc, serial, access, dc_id);

        if(sylverant_db_query(&conn, query)) {
            send_large_msg(c, __(c, "\tEInternal Server Error.\n"
                           "Please try again later."));
            return -1;
        }
    }

    /* Make sure the guildcard isn't banned. */
    banned = is_gc_banned(gc, &banlen, query);

    if(banned == -1) {
        send_large_msg(c, __(c, "\tEInternal Server Error.\n"
                       "Please try again later."));
        return -1;
    }
    else if(banned) {
        send_ban_msg(c, banlen, query);
        return -1;
    }

    /* Make sure the guildcard isn't online already. */
    banned = is_gc_online(gc);

    if(banned == -1) {
        send_large_msg(c, __(c, "\tEInternal Server Error.\n"
                             "Please try again later."));
        return -1;
    }
    else if(banned) {
        send_large_msg(c, __(c, "\tEYour guildcard is already online.\n"));
        return -1;
    }

    /* Check if the user is a GM or not. */
    sprintf(query, "SELECT privlevel FROM account_data NATURAL JOIN guildcards "
            "WHERE guildcard='%u'", gc);

    if(sylverant_db_query(&conn, query)) {
        send_large_msg(c, __(c, "\tEInternal Server Error.\n"
                       "Please try again later."));
        return -1;
    }

    result = sylverant_db_result_store(&conn);

    if(result) {
        if((row = sylverant_db_result_fetch(result))) {
            c->is_gm = atoi(row[0]);
        }

        sylverant_db_result_free(result);
    }

    return send_dc_security(c, gc, NULL, 0);
}

/* Handle a client's login request packet (yes, this function is the same as the
   one above, but it uses a different structure). */
static int handle_logina(login_client_t *c, dcv2_login_9a_pkt *pkt) {
    uint32_t gc;
    char query[256], dc_id[32], serial[32], access[32];
    void *result;
    char **row;
    time_t banlen;
    int banned = is_ip_banned(c, &banlen, query);

    /* Make sure the user isn't IP banned. */
    if(banned == -1) {
        return send_simple(c, LOGIN_9A_TYPE, LOGIN_9A_ERROR);
    }
    else if(banned) {
        send_ban_msg(c, banlen, query);
        return -1;
    }

    c->version = SYLVERANT_QUEST_V1 | SYLVERANT_QUEST_V2;

    /* Escape all the important strings. */
    sylverant_db_escape_str(&conn, dc_id, pkt->dc_id, 8);
    sylverant_db_escape_str(&conn, serial, pkt->serial, 8);
    sylverant_db_escape_str(&conn, access, pkt->access_key, 8);

    if(c->type != CLIENT_TYPE_PC) {
        sprintf(query, "SELECT guildcard FROM dreamcast_clients WHERE "
                "dc_id='%s' AND serial_number='%s' AND access_key='%s'", dc_id,
                serial, access);
    }
    else {
        sprintf(query, "SELECT guildcard FROM pc_clients WHERE "
                "serial_number='%s' AND access_key='%s'", serial, access);
    }

    /* If we can't query the database, fail. */
    if(sylverant_db_query(&conn, query)) {
        return send_simple(c, LOGIN_9A_TYPE, LOGIN_9A_ERROR);
    }

    result = sylverant_db_result_store(&conn);

    if((row = sylverant_db_result_fetch(result))) {
        /* We have seen this client before, save their guildcard for use. */
        gc = (uint32_t)strtoul(row[0], NULL, 0);
        sylverant_db_result_free(result);
    }
    else if(c->type == CLIENT_TYPE_PC) {
        /* If we're here, then that means either the PSOPC user is not
           registered or they've put their information in wrong. Disconnect them
           so that they can fix that problem. */
        sylverant_db_result_free(result);
        return send_simple(c, LOGIN_9A_TYPE, LOGIN_9A_BAD_SERIAL);
    }
    else {
        /* If we get here, we have a PSOv2 (DC) user that isn't known to the
           server yet. Give them a nice fresh guildcard. */
        sylverant_db_result_free(result);

        /* Assign a nice fresh new guildcard number to the client. */
        sprintf(query, "INSERT INTO guildcards (account_id) VALUES (NULL)");

        if(sylverant_db_query(&conn, query)) {
            return send_simple(c, LOGIN_9A_TYPE, LOGIN_9A_ERROR);
        }

        /* Grab the new guildcard for the user. */
        gc = (uint32_t)sylverant_db_insert_id(&conn);

        /* Add the client into our database. */
        sprintf(query, "INSERT INTO dreamcast_clients (guildcard, "
                "serial_number, access_key, dc_id) VALUES ('%u', '%s', '%s', "
                "'%s')", gc, serial, access, dc_id);

        if(sylverant_db_query(&conn, query)) {
            return send_simple(c, LOGIN_9A_TYPE, LOGIN_9A_ERROR);
        }
    }

    /* Make sure the guildcard isn't banned. */
    banned = is_gc_banned(gc, &banlen, query);

    if(banned == -1) {
        return send_simple(c, LOGIN_9A_TYPE, LOGIN_9A_ERROR);
    }
    else if(banned) {
        send_ban_msg(c, banlen, query);
        return -1;
    }

    /* Make sure the guildcard isn't online already. */
    banned = is_gc_online(gc);

    if(banned == -1) {
        return send_simple(c, LOGIN_9A_TYPE, LOGIN_9A_ERROR);
    }
    else if(banned) {
        send_large_msg(c, __(c, "\tEYour guildcard is already online.\n"));
        return -1;
    }

    /* Check if the user is a GM or not. */
    sprintf(query, "SELECT privlevel FROM account_data NATURAL JOIN guildcards "
            "WHERE guildcard='%u'", gc);

    if(sylverant_db_query(&conn, query)) {
        return send_simple(c, LOGIN_9A_TYPE, LOGIN_9A_ERROR);
    }

    result = sylverant_db_result_store(&conn);

    if(result) {
        if((row = sylverant_db_result_fetch(result))) {
            c->is_gm = atoi(row[0]);
        }

        sylverant_db_result_free(result);
    }

    c->guildcard = gc;

    /* Force them to send us a 0x9D so we have their language code, since this
       packet doesn't have it. */
    return send_simple(c, LOGIN_9A_TYPE, LOGIN_9A_OK2);
}

/* The next few functions look the same pretty much... All added for gamecube
   support. */
static int handle_gchlcheck(login_client_t *c, gc_hlcheck_pkt *pkt) {
    uint32_t account, gc;
    char query[256], serial[32], access[32];
    void *result;
    char **row;
    time_t banlen;
    int banned = is_ip_banned(c, &banlen, query);

    /* Make sure the user isn't IP banned. */
    if(banned == -1) {
        return send_simple(c, LOGIN_9A_TYPE, LOGIN_DB_CONN_ERROR);
    }
    else if(banned) {
        send_ban_msg(c, banlen, query);
        return send_simple(c, LOGIN_9A_TYPE, LOGIN_DB_SUSPENDED);
    }

    /* Escape all the important strings. */
    sylverant_db_escape_str(&conn, serial, pkt->serial, 8);
    sylverant_db_escape_str(&conn, access, pkt->access_key, 12);

    sprintf(query, "SELECT guildcard FROM gamecube_clients WHERE "
            "serial_number='%s' AND access_key='%s'", serial, access);

    /* If we can't query the database, fail. */
    if(sylverant_db_query(&conn, query)) {
        return send_simple(c, LOGIN_9A_TYPE, LOGIN_DB_CONN_ERROR);
    }

    result = sylverant_db_result_store(&conn);

    if((row = sylverant_db_result_fetch(result))) {
        gc = (uint32_t)strtoul(row[0], NULL, 0);
        sylverant_db_result_free(result);

        /* Make sure the guildcard isn't banned. */
        banned = is_gc_banned(gc, &banlen, query);

        if(banned == -1) {
            return send_simple(c, LOGIN_9A_TYPE, LOGIN_DB_CONN_ERROR);
        }
        else if(banned) {
            send_ban_msg(c, banlen, query);
            return send_simple(c, LOGIN_9A_TYPE, LOGIN_DB_SUSPENDED);
        }

        /* Make sure the guildcard isn't online already. */
        banned = is_gc_online(gc);

        if(banned == -1) {
            return send_simple(c, LOGIN_9A_TYPE, LOGIN_DB_CONN_ERROR);
        }
        else if(banned) {
            send_large_msg(c, __(c, "\tEYour guildcard is already online.\n"));
            return -1;
        }

        /* The client has at least registered, check the password...
           We need the account to do that though. */
        sprintf(query, "SELECT account_id FROM guildcards WHERE guildcard='%u'",
                gc);

        if(sylverant_db_query(&conn, query)) {
            return send_simple(c, LOGIN_9A_TYPE, LOGIN_DB_CONN_ERROR);
        }

        result = sylverant_db_result_store(&conn);

        if(!(row = sylverant_db_result_fetch(result))) {
            return send_simple(c, LOGIN_9A_TYPE, LOGIN_DB_CONN_ERROR);
        }

        account = (uint32_t)strtoul(row[0], NULL, 0);
        sylverant_db_result_free(result);

        sprintf(query, "SELECT privlevel FROM account_data WHERE "
                "account_id='%u'", account);

        /* If we can't query the DB, fail. */
        if(sylverant_db_query(&conn, query)) {
            return send_simple(c, LOGIN_9A_TYPE, LOGIN_DB_CONN_ERROR);
        }

        result = sylverant_db_result_store(&conn);

        if((row = sylverant_db_result_fetch(result))) {
            c->is_gm = atoi(row[0]);
            return send_simple(c, LOGIN_9A_TYPE, LOGIN_DB_OK);
        }
    }

    sylverant_db_result_free(result);

    /* If we get here, we didn't find them, bail out. */
    return send_simple(c, LOGIN_9A_TYPE, LOGIN_DB_CONN_ERROR);
}

static int handle_gcloginc(login_client_t *c, gc_login_9c_pkt *pkt) {
    uint32_t account, gc;
    char query[256], serial[32], access[32];
    void *result;
    char **row;
    unsigned char hash[16];
    int i;

    /* Escape all the important strings. */
    sylverant_db_escape_str(&conn, serial, pkt->serial, 8);
    sylverant_db_escape_str(&conn, access, pkt->access_key, 12);

    sprintf(query, "SELECT guildcard FROM gamecube_clients WHERE "
            "serial_number='%s' AND access_key='%s'", serial, access);

    /* If we can't query the database, fail. */
    if(sylverant_db_query(&conn, query)) {
        return -1;
    }

    result = sylverant_db_result_store(&conn);

    if((row = sylverant_db_result_fetch(result))) {
        /* The client has at least registered, check the password. */
        gc = (uint32_t)strtoul(row[0], NULL, 0);

        sylverant_db_result_free(result);

        /* We need the account to do that though... */
        sprintf(query, "SELECT account_id FROM guildcards WHERE guildcard='%u'",
                gc);

        if(sylverant_db_query(&conn, query)) {
            return -1;
        }

        result = sylverant_db_result_store(&conn);

        if(!(row = sylverant_db_result_fetch(result))) {
            return -1;
        }

        account = (uint32_t)strtoul(row[0], NULL, 0);
        sylverant_db_result_free(result);

        sprintf(query, "SELECT password, regtime FROM account_data WHERE "
                "account_id='%u'", account);

        /* If we can't query the DB, fail. */
        if(sylverant_db_query(&conn, query)) {
            return -1;
        }

        result = sylverant_db_result_store(&conn);

        if((row = sylverant_db_result_fetch(result))) {
            /* Check the password. */
            sprintf(query, "%s_%s_salt", pkt->password, row[1]);
            md5((unsigned char *)query, strlen(query), hash);

            query[0] = '\0';
            for(i = 0; i < 16; ++i) {
                sprintf(query, "%s%02x", query, hash[i]);
            }

            for(i = 0; i < strlen(row[0]); ++i) {
                row[0][i] = tolower(row[0][i]);
            }

            if(!strcmp(row[0], query)) {
                sylverant_db_result_free(result);
                return send_simple(c, LOGIN_9C_TYPE, LOGIN_9CGC_OK);
            }
            else {
                return send_simple(c, LOGIN_9C_TYPE, LOGIN_9CGC_BAD_PWD);
            }
        }
    }

    sylverant_db_result_free(result);

    /* If we get here, we didn't find them, bail out. */
    return -1;
}

static int handle_gclogine(login_client_t *c, gc_login_9e_pkt *pkt) {
    uint32_t gc;
    char query[256], serial[32], access[32];
    void *result;
    char **row;

    c->language_code = pkt->language_code;

    /* Escape all the important strings. */
    sylverant_db_escape_str(&conn, serial, pkt->serial, 8);
    sylverant_db_escape_str(&conn, access, pkt->access_key, 12);

    sprintf(query, "SELECT guildcard FROM gamecube_clients WHERE "
            "serial_number='%s' AND access_key='%s'", serial, access);

    /* If we can't query the database, fail. */
    if(sylverant_db_query(&conn, query)) {
        return -1;
    }

    result = sylverant_db_result_store(&conn);

    if((row = sylverant_db_result_fetch(result))) {
        /* Grab the client's guildcard number. */
        gc = (uint32_t)strtoul(row[0], NULL, 0);
        sylverant_db_result_free(result);

        return send_dc_security(c, gc, NULL, 0);
    }

    sylverant_db_result_free(result);

    /* If we get here, we didn't find them, bail out. */
    return -1;
}

static int handle_logind(login_client_t *c, dcv2_login_9d_pkt *pkt) {
    /* We made clients send this packet just specifically to grab the language
       code... All the real checking has been done elsewhere. */
    c->language_code = pkt->language_code;

    return send_dc_security(c, c->guildcard, NULL, 0);
}

/* Handle a client's ship select packet. */
static int handle_ship_select(login_client_t *c, dc_select_pkt *pkt) {
    sylverant_quest_list_t *l = &qlist[c->type][c->language_code];
    uint32_t menu_id = LE32(pkt->menu_id);
    uint32_t item_id = LE32(pkt->item_id);
    int rv;

    switch(menu_id & 0xFF) {
        /* Initial menu */
        case 0x00:
            if(item_id == ITEM_ID_INIT_SHIP) {
                /* Ship Select */
                return send_ship_list(c, 0);
            }
            else if(item_id == ITEM_ID_INIT_DOWNLOAD) {
                if(l->cat_count == 1) {
                    return send_quest_list(c, &l->cats[0]);
                }
            }
            else if(item_id == ITEM_ID_INIT_INFO) {
                return send_info_list(c);
            }

            return -1;

        /* Ship */
        case 0x01:
            if(item_id == 0) {
                /* A "Ship List" menu item */
                return send_ship_list(c, (uint16_t)(menu_id >> 8));
            }
            else {
                /* An actual ship */
                return ship_transfer(c, item_id);
            }

        /* Quest */
        case 0x04:
            /* Make sure the item is valid */
            if(item_id < l->cats[0].quest_count) {
                rv = send_quest(c, &l->cats[0].quests[item_id]);

                if(c->type == CLIENT_TYPE_PC) {
                    rv |= send_initial_menu(c);
                }

                return rv;
            }
            else {
                return -1;
            }

        /* Information Desk */
        case 0x07:
            if(item_id == 0xFFFFFFFF) {
                return send_initial_menu(c);
            }
            else {
                return send_info_file(c, item_id);
            }

        default:
            return -1;
    }
}

/* Check a player's character data for potential hackery. */
static int handle_char_data(login_client_t *c, dc_char_data_pkt *pkt) {
    int j, rv = 1;
    sylverant_iitem_t *item;
    player_t *pl = &pkt->data;
    uint32_t v;

    /* If we don't have a legit mode set, then everyone's legit! */
    if(!limits) {
        return 0;
    }

    switch(c->type) {
        case CLIENT_TYPE_DC:
        case CLIENT_TYPE_PC:
            v = ITEM_VERSION_V2;
            break;

        case CLIENT_TYPE_GC:
            v = ITEM_VERSION_GC;
            break;

        default:
            return -1;
    }

    /* Look through each item */
    for(j = 0; j < pl->v1.inv.item_count && rv; ++j) {
        item = (sylverant_iitem_t *)&pl->v1.inv.items[j];
        rv = sylverant_limits_check_item(limits, item, v);
    }

    /* If the person has banned items, boot them */
    if(!rv) {
        send_large_msg(c, __(c, "\tEYou have one or more banned items in\n"
                             "your inventory. Please remove them and\n"
                             "try again later."));
        return -1;
    }

    return 0;
}

static int handle_info_req(login_client_t *c, dc_select_pkt *pkt) {
    uint32_t menu_id = LE32(pkt->menu_id);
    uint32_t item_id = LE32(pkt->item_id);
    uint16_t menu_code;
    int ship_num;
    char str[256];
    void *result;
    char **row;

    switch(menu_id & 0xFF) {
        /* Ship */
        case 0x01:
            /* If its a list, say nothing */
            if(item_id == 0) {
                return send_info_reply(c, __(c, "\tENothing here."));
            }

            /* We should have a ship ID as the item_id at this point, so query
               the db for the info we want. */
            sprintf(str, "SELECT name, players, games, menu_code, ship_number "
                    "FROM online_ships WHERE ship_id='%lu'",
                    (unsigned long)item_id);

            /* Query for what we're looking for */
            if(sylverant_db_query(&conn, str)) {
                return -1;
            }

            if(!(result = sylverant_db_result_store(&conn))) {
                return -2;
            }

            /* If we don't have a row, then the ship is offline */
            if(!(row = sylverant_db_result_fetch(result))) {
                return send_info_reply(c, __(c, "\tE\tC4That ship is now\n"
                                             "offline."));
            }

            /* Parse out the menu code */
            menu_code = (uint16_t)atoi(row[3]);
            ship_num = atoi(row[4]);

            /* Send the info reply */
            if(!menu_code) {
                sprintf(str, "%02X:%s\n%s %s\n%s %s", ship_num, row[0], row[1],
                        __(c, "Users"), row[2], __(c, "Teams"));
            }
            else {
                sprintf(str, "%02X:%c%c/%s\n%s %s\n%s %s", ship_num,
                        (char)menu_code, (char)(menu_code >> 8), row[0], row[1],
                        __(c, "Users"), row[2], __(c, "Teams"));
            }

            sylverant_db_result_free(result);

            return send_info_reply(c, str);

        default:
            /* Ignore any other info requests. */
            return 0;
    }
}

/* Process one login packet. */
int process_dclogin_packet(login_client_t *c, void *pkt) {
    dc_pkt_hdr_t *dc = (dc_pkt_hdr_t *)pkt;
    pc_pkt_hdr_t *pc = (pc_pkt_hdr_t *)pkt;
    uint8_t type;
    uint16_t len;

    if(c->type == CLIENT_TYPE_DC || c->type == CLIENT_TYPE_GC ||
       c->type == CLIENT_TYPE_EP3) {
        type = dc->pkt_type;
        len = LE16(dc->pkt_len);
    }
    else {
        type = pc->pkt_type;
        len = LE16(pc->pkt_len);
    }

    switch(type) {
        case LOGIN_90_TYPE:
            /* XXXX: Hey! this does something now! */
            return handle_login0(c, (dc_login_90_pkt *)pkt);

        case LOGIN_92_TYPE:
            /* XXXX: Do something with this sometime. */
            return send_simple(c, LOGIN_92_TYPE, LOGIN_92_OK);

        case LOGIN_93_TYPE:
            /* XXXX: Figure this all out sometime. */
            return handle_login3(c, (dc_login_93_pkt *)pkt);

        case LOGIN_9A_TYPE:
            /* XXXX: You had to switch packets on me, didn't you Sega? */
            return handle_logina(c, (dcv2_login_9a_pkt *)pkt);

        case CHECKSUM_TYPE:
            /* XXXX: ??? */
            if(send_simple(c, CHECKSUM_REPLY_TYPE, 1)) {
                return -1;
            }

            return send_simple(c, CHAR_DATA_REQUEST_TYPE, 0);

        case TIMESTAMP_TYPE:
            /* XXXX: Actually, I've got nothing here. */
            return send_timestamp(c);

        case SHIP_LIST_REQ_TYPE:
            /* XXXX: We'll fall through the bottom of this... */
            if(c->type == CLIENT_TYPE_EP3) {
                if(send_ep3_rank_update(c)) {
                    return -1;
                }

                if(send_ep3_card_update(c)) {
                    return -1;
                }
            }

        case SHIP_LIST_TYPE:
            /* XXXX: I don't have anything here either, but thought I'd be
               funny anyway. */
            return send_initial_menu(c);

        case INFO_REQUEST_TYPE:
            /* XXXX: Relevance, at last! */
            return handle_info_req(c, (dc_select_pkt *)pkt);

        case MENU_SELECT_TYPE:
            /* XXXX: This might actually work, at least if there's a ship. */
            return handle_ship_select(c, (dc_select_pkt *)pkt);

        case GC_VERIFY_LICENSE_TYPE:
            /* XXXX: Why in the world do they duplicate so much data here? */
            return handle_gchlcheck(c, (gc_hlcheck_pkt *)pkt);

        case LOGIN_9C_TYPE:
            /* XXXX: Yep... check things here too. */
            return handle_gcloginc(c, (gc_login_9c_pkt *)pkt);

        case LOGIN_9E_TYPE:
            /* XXXX: One final check, and give them their guildcard. */
            return handle_gclogine(c, (gc_login_9e_pkt *)pkt);

        case LOGIN_9D_TYPE:
            /* XXXX: All this work for a language code... */
            return handle_logind(c, (dcv2_login_9d_pkt *)pkt);

        case CHAR_DATA_TYPE:
            /* XXXX: Gee, I can be mean, can't I? */
            return handle_char_data(c, (dc_char_data_pkt *)pkt);

        case GAME_COMMAND0_TYPE:
            /* XXXX: Added so screenshots work on the ship list... */
            return 0;

        case TYPE_05:
            /* XXXX: Why would you ask to disconnect? */
            c->disconnected = 1;
            return 0;

        case EP3_RANK_UPDATE_TYPE:
        case EP3_CARD_UPDATE_TYPE:
            /* XXXX: I have no idea what to do with these... */
            return 0;

        case GC_MSG_BOX_CLOSED_TYPE:
            /* XXXX: This will need work if I ever have an initial MOTD or
               something like that. */
            return send_info_list(c);

        default:
            print_packet((unsigned char *)pkt, len);
            return -3;
    }

    return 0;
}

/* Initialize mini18n support. */
void init_i18n(void) {
#ifdef HAVE_LIBMINI18N
	int i;
	char filename[256];

	for(i = 0; i < CLIENT_LANG_COUNT; ++i) {
		langs[i] = mini18n_create();

		if(langs[i]) {
			sprintf(filename, "l10n/login_server-%s.yts", language_codes[i]);

			/* Attempt to load the l10n file. */
			if(mini18n_load(langs[i], filename)) {
				/* If we didn't get it, clean up. */
				mini18n_destroy(langs[i]);
				langs[i] = NULL;
			}
			else {
				debug(DBG_LOG, "Read l10n file for %s\n", language_codes[i]);
			}
		}
	}
#endif
}

/* Clean up when we're done with mini18n. */
void cleanup_i18n(void) {
#ifdef HAVE_LIBMINI18N
	int i;

	/* Just call the destroy function... It'll handle null values fine. */
	for(i = 0; i < CLIENT_LANG_COUNT; ++i) {
		mini18n_destroy(langs[i]);
	}
#endif
}
