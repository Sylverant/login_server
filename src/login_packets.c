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
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <iconv.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <sylverant/config.h>
#include <sylverant/encryption.h>
#include <sylverant/database.h>
#include <sylverant/quest.h>

#include "login_packets.h"

extern sylverant_dbconn_t conn;
extern sylverant_config_t cfg;
extern sylverant_quest_list_t qlist[CLIENT_TYPE_COUNT][CLIENT_LANG_COUNT];
extern in_addr_t local_addr;
extern in_addr_t netmask;

uint8_t sendbuf[65536];

/* Send a raw packet away. */
static int send_raw(login_client_t *c, int len) {
    ssize_t rv, total = 0;
    void *tmp;

    /* Keep trying until the whole thing's sent. */
    if(!c->sendbuf_cur) {
        while(total < len) {
            rv = send(c->sock, sendbuf + total, len - total, 0);

            if(rv == -1 && errno != EAGAIN) {
                return -1;
            }
            else if(rv == -1) {
                break;
            }

            total += rv;
        }
    }

    rv = len - total;

    if(rv) {
        /* Move out any already transferred data. */
        if(c->sendbuf_start) {
            memmove(c->sendbuf, c->sendbuf + c->sendbuf_start,
                    c->sendbuf_cur - c->sendbuf_start);
            c->sendbuf_cur -= c->sendbuf_start;
        }

        /* See if we need to reallocate the buffer. */
        if(c->sendbuf_cur + rv > c->sendbuf_size) {
            tmp = realloc(c->sendbuf, c->sendbuf_cur + rv);

            /* If we can't allocate the space, bail. */
            if(tmp == NULL) {
                return -1;
            }

            c->sendbuf_size = c->sendbuf_cur + rv;
            c->sendbuf = (unsigned char *)tmp;
        }

        /* Copy what's left of the packet into the output buffer. */
        memcpy(c->sendbuf + c->sendbuf_cur, sendbuf + total, rv);
        c->sendbuf_cur += rv;
    }

    return 0;
}

/* Encrypt and send a packet away. */
static int crypt_send(login_client_t *c, int len) {
    /* Expand it to be a multiple of 8/4 bytes long */
    while(len & (c->hdr_size - 1)) {
        sendbuf[len++] = 0;
    }

    /* Encrypt the packet */
    CRYPT_CryptData(&c->server_cipher, sendbuf, len, 1);

    return send_raw(c, len);
}

/* Send a Dreamcast/PC Welcome packet to the given client. */
int send_dc_welcome(login_client_t *c, uint32_t svect, uint32_t cvect) {
    dc_welcome_pkt *pkt = (dc_welcome_pkt *)sendbuf;

    /* Scrub the buffer */
    memset(pkt, 0, sizeof(dc_welcome_pkt));

    /* Fill in the header */
    if(c->type == CLIENT_TYPE_DC || c->type == CLIENT_TYPE_GC) {
        pkt->hdr.dc.pkt_len = LE16(DC_WELCOME_LENGTH);
        pkt->hdr.dc.pkt_type = LOGIN_WELCOME_TYPE;
    }
    else {
        pkt->hdr.pc.pkt_len = LE16(DC_WELCOME_LENGTH);
        pkt->hdr.pc.pkt_type = LOGIN_WELCOME_TYPE;
    }

    /* Fill in the required message */
    memcpy(pkt->copyright, login_dc_welcome_copyright, 52);

    /* Fill in the encryption vectors */
    pkt->svect = LE32(svect);
    pkt->cvect = LE32(cvect);

    /* Send the packet away */
    return send_raw(c, DC_WELCOME_LENGTH);
}

static int send_large_msg_dc(login_client_t *c, const char msg[]) {
    dc_msg_box_pkt *pkt = (dc_msg_box_pkt *)sendbuf;
    int size = 4;
    iconv_t ic;
    size_t in, out;
    ICONV_CONST char *inptr;
    char *outptr;

    if(c->type == CLIENT_TYPE_DC || c->type == CLIENT_TYPE_GC) {
        if(msg[1] == 'J') {
            ic = iconv_open("SHIFT_JIS", "UTF-8");
        }
        else {
            ic = iconv_open("ISO-8859-1", "UTF-8");
        }
    }
    else {
        ic = iconv_open("UTF-16LE", "UTF-8");
    }

    if(ic == (iconv_t)-1) {
        perror("iconv_open");
        return -1;
    }

    /* Convert to the proper encoding */
    in = strlen(msg) + 1;
    out = 65524;
    inptr = (ICONV_CONST char *)msg;
    outptr = (char *)pkt->msg;
    iconv(ic, &inptr, &in, &outptr, &out);
    iconv_close(ic);

    /* Figure out how long the packet is */
    size += 65524 - out;

    /* Pad to a length divisible by 4 */
    while(size & 0x03) {
        sendbuf[size++] = 0;
    }

    /* Fill in the header */
    if(c->type == CLIENT_TYPE_DC || c->type == CLIENT_TYPE_GC) {
        pkt->hdr.dc.pkt_type = MSG_BOX_TYPE;
        pkt->hdr.dc.flags = 0;
        pkt->hdr.dc.pkt_len = LE16(size);
    }
    else {
        pkt->hdr.pc.pkt_type = MSG_BOX_TYPE;
        pkt->hdr.pc.flags = 0;
        pkt->hdr.pc.pkt_len = LE16(size);
    }

    /* Send the packet away */
    return crypt_send(c, size);
}

int send_large_msg(login_client_t *c, const char msg[]) {
    /* Call the appropriate function. */
    switch(c->type) {
        case CLIENT_TYPE_DC:
        case CLIENT_TYPE_GC:
        case CLIENT_TYPE_PC:
            return send_large_msg_dc(c, msg);
    }

    return -1;
}

/* Send the Dreamcast security packet to the given client. */
int send_dc_security(login_client_t *c, uint32_t gc, uint8_t *data,
                     int data_len) {
    dc_security_pkt *pkt = (dc_security_pkt *)sendbuf;

    /* Wipe the packet */
    memset(pkt, 0, sizeof(dc_security_pkt));

    /* Fill in the header */
    if(c->type == CLIENT_TYPE_DC || c->type == CLIENT_TYPE_GC) {
        pkt->hdr.dc.pkt_type = SECURITY_TYPE;
        pkt->hdr.dc.pkt_len = LE16((0x0C + data_len));
    }
    else {
        pkt->hdr.pc.pkt_type = SECURITY_TYPE;
        pkt->hdr.pc.pkt_len = LE16((0x0C + data_len));
    }

    /* Fill in the guildcard/tag */
    pkt->tag = LE32(0x00010000);
    pkt->guildcard = LE32(gc);

    /* Copy over any security data */
    if(data_len)
        memcpy(pkt->security_data, data, data_len);

    /* Send the packet away */
    return crypt_send(c, 0x0C + data_len);
}

/* Send a redirect packet to the given client. */
static int send_redirect_dc(login_client_t *c, in_addr_t ip, uint16_t port) {
    dc_redirect_pkt *pkt = (dc_redirect_pkt *)sendbuf;

    /* Wipe the packet */
    memset(pkt, 0, DC_REDIRECT_LENGTH);

    /* Fill in the header */
    if(c->type == CLIENT_TYPE_DC || c->type == CLIENT_TYPE_GC) {
        pkt->hdr.dc.pkt_type = REDIRECT_TYPE;
        pkt->hdr.dc.pkt_len = LE16(DC_REDIRECT_LENGTH);
    }
    else {
        pkt->hdr.pc.pkt_type = REDIRECT_TYPE;
        pkt->hdr.pc.pkt_len = LE16(DC_REDIRECT_LENGTH);
    }

    /* Fill in the IP and port */
    pkt->ip_addr = ip;
    pkt->port = LE16(port);

    /* Send the packet away */
    return crypt_send(c, DC_REDIRECT_LENGTH);
}

int send_redirect(login_client_t *c, in_addr_t ip, uint16_t port) {
    /* Call the appropriate function. */
    switch(c->type) {
        case CLIENT_TYPE_DC:
        case CLIENT_TYPE_PC:
        case CLIENT_TYPE_GC:
            return send_redirect_dc(c, ip, port);
    }

    return -1;
}

/* Send a packet to clients connecting on the Gamecube port to sort out any PC
   clients that might end up there. This must be sent before encryption is set
   up! */
int send_selective_redirect(login_client_t *c) {
    dc_redirect_pkt *pkt = (dc_redirect_pkt *)sendbuf;
    dc_pkt_hdr_t *hdr2 = (dc_pkt_hdr_t *)(sendbuf + 0x19);
    in_addr_t addr;

    /* Figure out the address to use */
    /* Figure out what address to send the client. */
    if(netmask && (c->ip_addr & netmask) == (local_addr & netmask)) {
        addr = local_addr;
    }
    else {
        addr = cfg.server_ip;
    }

    /* Wipe the packet */
    memset(pkt, 0, 0xB0);

    /* Fill in the redirect packet. PC users will parse this out as a type 0x19
       (Redirect) with size 0xB0. GC/DC users would parse it out as a type 0xB0
       (Ignored) with a size of 0x19. The second header takes care of the rest
       of the 0xB0 size. */
    pkt->hdr.pc.pkt_type = REDIRECT_TYPE;
    pkt->hdr.pc.pkt_len = LE16(0x00B0);
    pkt->ip_addr = addr;
    pkt->port = LE16(9300);

    /* Fill in the secondary header */
    hdr2->pkt_type = 0xB0;
    hdr2->pkt_len = LE16(0x0097);

    /* Send it away */
    return send_raw(c, 0xB0);
}

/* Send a timestamp packet to the given client. */
static int send_timestamp_dc(login_client_t *c) {
    dc_timestamp_pkt *pkt = (dc_timestamp_pkt *)sendbuf;
    struct timeval rawtime;
    struct tm cooked;

    /* Wipe the packet */
    memset(pkt, 0, DC_TIMESTAMP_LENGTH);

    /* Fill in the header */
    if(c->type == CLIENT_TYPE_DC || c->type == CLIENT_TYPE_GC) {
        pkt->hdr.dc.pkt_type = TIMESTAMP_TYPE;
        pkt->hdr.dc.pkt_len = LE16(DC_TIMESTAMP_LENGTH);
    }
    else {
        pkt->hdr.pc.pkt_type = TIMESTAMP_TYPE;
        pkt->hdr.pc.pkt_len = LE16(DC_TIMESTAMP_LENGTH);
    }

    /* Get the timestamp */
    gettimeofday(&rawtime, NULL);

    /* Get UTC */
    gmtime_r(&rawtime.tv_sec, &cooked);    

    /* Fill in the timestamp */
    sprintf(pkt->timestamp, "%u:%02u:%02u: %02u:%02u:%02u.%03u",
            cooked.tm_year + 1900, cooked.tm_mon + 1, cooked.tm_mday,
            cooked.tm_hour, cooked.tm_min, cooked.tm_sec,
            (unsigned)(rawtime.tv_usec / 1000));

    /* Send the packet away */
    return crypt_send(c, DC_TIMESTAMP_LENGTH);
}

int send_timestamp(login_client_t *c) {
    /* Call the appropriate function */
    switch(c->type) {
        case CLIENT_TYPE_DC:
        case CLIENT_TYPE_PC:
        case CLIENT_TYPE_GC:
            return send_timestamp_dc(c);
    }

    return -1;
}

/* Send the list of ships to the client. */
static int send_ship_list_dc(login_client_t *c, uint16_t menu_code) {
    dc_ship_list_pkt *pkt = (dc_ship_list_pkt *)sendbuf;
    char no_ship_msg[] = "No Ships";
    char query[256];
    uint32_t num_ships = 0;
    void *result;
    char **row;
    uint32_t ship_id, players;
    int i, len = 0x20, gm_only, flags;
    char tmp[3];

    /* Clear the base packet */
    memset(pkt, 0, sizeof(dc_ship_list_pkt));

    /* Fill in some basic stuff */
    pkt->hdr.pkt_type = BLOCK_LIST_TYPE;

    /* Fill in the "DATABASE/JP" entry */
    memset(&pkt->entries[0], 0, 0x1C);
    pkt->entries[0].menu_id = LE32(0x00040000);
    pkt->entries[0].item_id = 0;
    pkt->entries[0].flags = LE16(0x0004);
    strcpy(pkt->entries[0].name, "DATABASE/JP");
    pkt->entries[0].name[0x11] = 0x08;
    num_ships = 1;

    /* Figure out what ships we might exclude by flags */
    if(c->type == CLIENT_TYPE_GC) {
        flags = 0x80;
    }
    else {
        if(c->version == SYLVERANT_QUEST_V1) {
            flags = 0x10;
        }
        else {
            flags = 0x20;
        }
    }

    /* Get ready to query the database */
    sprintf(query, "SELECT ship_id, name, players, gm_only FROM online_ships "
            "WHERE menu_code='%hu' AND (flags & 0x%02x) = 0 ORDER BY ship_id",
            menu_code, flags);

    /* Query the database and see what we've got */
    if(sylverant_db_query(&conn, query)) {
        i = -1;
        goto out;
    }

    if((result = sylverant_db_result_store(&conn)) == NULL) {
        i = -2;
        goto out;
    }

    /* As long as we have some rows, go */
    while((row = sylverant_db_result_fetch(result))) {
        gm_only = atoi(row[3]);

        if(!gm_only || c->is_gm) {
            /* Clear out the ship information */
            memset(&pkt->entries[num_ships], 0, 0x1C);

            /* Grab info from the row */
            ship_id = (uint32_t)strtoul(row[0], NULL, 0);
            players = (uint32_t)strtoul(row[2], NULL, 0);

            /* Fill in what we have */
            pkt->entries[num_ships].menu_id = LE32(0x00000001);
            pkt->entries[num_ships].item_id = LE32(ship_id);
            pkt->entries[num_ships].flags = LE16(0x0000);

            /* Create the name string */
            sprintf(pkt->entries[num_ships].name, "%s (%d)", row[1], players);

            /* We're done with this ship, increment the counter */
            ++num_ships;
            len += 0x1C;
        }
    }

    sylverant_db_result_free(result);

    /* Figure out any lists we need to allow to be seen */
    sprintf(query, "SELECT DISTINCT menu_code FROM online_ships ORDER BY "
            "menu_code");

    /* Query the database and see what we've got */
    if(sylverant_db_query(&conn, query)) {
        i = -3;
        goto out;
    }

    if((result = sylverant_db_result_store(&conn)) == NULL) {
        i = -4;
        goto out;
    }

    /* As long as we have some rows, go */
    while((row = sylverant_db_result_fetch(result))) {
        /* Grab info from the row */
        ship_id = (uint16_t)strtoul(row[0], NULL, 0);

        /* Skip the entry we're filling in now */
        if(ship_id == menu_code) {
            continue;
        }

        tmp[0] = (char)(ship_id);
        tmp[1] = (char)(ship_id >> 8);
        tmp[2] = '\0';

        /* Make sure the values are in-bounds */
        if((tmp[0] || tmp[1]) && (!isalpha(tmp[0]) || !isalpha(tmp[1]))) {
            continue;
        }

        /* Clear out the ship information */
        memset(&pkt->entries[num_ships], 0, 0x1C);

        /* Fill in what we have */
        pkt->entries[num_ships].menu_id = LE32((0x00000001 | (ship_id << 8)));
        pkt->entries[num_ships].item_id = LE32(0x00000000);
        pkt->entries[num_ships].flags = LE16(0x0000);

        /* Create the name string */
        if(tmp[0] && tmp[1]) {
            sprintf(pkt->entries[num_ships].name, "\tC6%s Ship List", tmp);
        }
        else {
            strcpy(pkt->entries[num_ships].name, "\tC6Main Ships");
        }

        /* We're done with this ship, increment the counter */
        ++num_ships;
        len += 0x1C;
    }

    sylverant_db_result_free(result);

    if(qlist[c->type][c->language_code].cats && !menu_code) {
        /* Add the entry for Offline Quests. */
        memset(&pkt->entries[num_ships], 0, 0x1C);
    
        /* Fill in what we have */
        pkt->entries[num_ships].menu_id = LE32(0x000000FF);
        pkt->entries[num_ships].item_id = LE32(0xDEADBEEF);
        pkt->entries[num_ships].flags = LE16(0x0000);
    
        /* Create the name string */
        strcpy(pkt->entries[num_ships].name, "Offline Quests");
    
        /* We're done with this "ship", increment the counter */
        ++num_ships;
        len += 0x1C;
    }

    /* Make sure we have at least one ship... */
    if(num_ships == 1) {
        /* Clear out the ship information */
        memset(&pkt->entries[num_ships], 0, 0x1C);
        pkt->entries[num_ships].menu_id = LE32(0xDEADBEEF);
        pkt->entries[num_ships].item_id = LE32(0x00000000);
        pkt->entries[num_ships].flags = LE16(0x0000);
        strcpy(pkt->entries[num_ships].name, no_ship_msg);
        
        ++num_ships;
        len += 0x1C;
    }

    /* Fill in the rest of the header */
    pkt->hdr.pkt_len = LE16(len);
    pkt->hdr.flags = (uint8_t)(num_ships - 1);

    /* Send the packet away */
    return crypt_send(c, len);

out:
    return i;
}

/* Send the list of ships to the client. */
static int send_ship_list_pc(login_client_t *c, uint16_t menu_code) {
    pc_ship_list_pkt *pkt = (pc_ship_list_pkt *)sendbuf;
    char no_ship_msg[] = "No Ships";
    char query[256], tmp[18], tmp2[3];
    uint32_t num_ships = 0;
    void *result;
    char **row;
    uint32_t ship_id, players;
    int i, len = 0x30, gm_only;
    iconv_t ic = iconv_open("UTF-16LE", "UTF-8");
    size_t in, out;
    ICONV_CONST char *inptr;
    char *outptr;

    if(ic == (iconv_t)-1) {
        perror("iconv_open");
        return -1;
    }

    /* Clear the base packet */
    memset(pkt, 0, sizeof(pc_ship_list_pkt));

    /* Fill in some basic stuff */
    pkt->hdr.pkt_type = BLOCK_LIST_TYPE;

    /* Fill in the "DATABASE/JP" entry */
    memset(&pkt->entries[0], 0, 0x2C);
    pkt->entries[0].menu_id = LE32(0x00040000);
    pkt->entries[0].item_id = 0;
    pkt->entries[0].flags = LE16(0x0004);
    memcpy(pkt->entries[0].name, "D\0A\0T\0A\0B\0A\0S\0E\0/\0J\0P\0", 22);
    num_ships = 1;

    /* Get ready to query the database */
    sprintf(query, "SELECT ship_id, name, players, gm_only FROM online_ships "
            "WHERE menu_code='%hu' AND (flags & 0x40) = 0 ORDER BY ship_id",
            menu_code);

    /* Query the database and see what we've got */
    if(sylverant_db_query(&conn, query)) {
        i = -1;
        goto out;
    }

    if((result = sylverant_db_result_store(&conn)) == NULL) {
        i = -2;
        goto out;
    }

    /* As long as we have some rows, go */
    while((row = sylverant_db_result_fetch(result))) {
        gm_only = atoi(row[3]);

        if(!gm_only || c->is_gm) {
            /* Clear out the ship information */
            memset(&pkt->entries[num_ships], 0, 0x2C);

            /* Grab info from the row */
            ship_id = (uint32_t)strtoul(row[0], NULL, 0);
            players = (uint32_t)strtoul(row[2], NULL, 0);

            /* Fill in what we have */
            pkt->entries[num_ships].menu_id = LE32(0x00000001);
            pkt->entries[num_ships].item_id = LE32(ship_id);
            pkt->entries[num_ships].flags = LE16(0x0000);

            /* Create the name string (UTF-8) */
            sprintf(tmp, "%s (%d)", row[1], players);

            /* And convert to UTF-16 */
            in = strlen(tmp);
            out = 0x22;
            inptr = tmp;
            outptr = (char *)pkt->entries[num_ships].name;
            iconv(ic, &inptr, &in, &outptr, &out);

            /* We're done with this ship, increment the counter */
            ++num_ships;
            len += 0x2C;
        }
    }

    sylverant_db_result_free(result);

    /* Figure out any lists we need to allow to be seen */
    sprintf(query, "SELECT DISTINCT menu_code FROM online_ships ORDER BY "
            "menu_code");

    /* Query the database and see what we've got */
    if(sylverant_db_query(&conn, query)) {
        i = -3;
        goto out;
    }

    if((result = sylverant_db_result_store(&conn)) == NULL) {
        i = -4;
        goto out;
    }

    /* As long as we have some rows, go */
    while((row = sylverant_db_result_fetch(result))) {
        /* Grab info from the row */
        ship_id = (uint16_t)strtoul(row[0], NULL, 0);

        /* Skip the entry we're filling in now */
        if(ship_id == menu_code) {
            continue;
        }

        tmp2[0] = (char)(ship_id);
        tmp2[1] = (char)(ship_id >> 8);
        tmp2[2] = '\0';

        /* Make sure the values are in-bounds */
        if((tmp2[0] || tmp2[1]) && (!isalpha(tmp2[0]) || !isalpha(tmp2[1]))) {
            continue;
        }

        /* Clear out the ship information */
        memset(&pkt->entries[num_ships], 0, 0x2C);

        /* Fill in what we have */
        pkt->entries[num_ships].menu_id = LE32((0x00000001 | (ship_id << 8)));
        pkt->entries[num_ships].item_id = LE32(0x00000000);
        pkt->entries[num_ships].flags = LE16(0x0000);

        /* Create the name string (UTF-8) */
        if(tmp2[0] && tmp2[1]) {
            sprintf(tmp, "\tC6%s Ship List", tmp2);
        }
        else {
            strcpy(tmp, "\tC6Main Ships");
        }

        /* And convert to UTF-16 */
        in = strlen(tmp);
        out = 0x22;
        inptr = tmp;
        outptr = (char *)pkt->entries[num_ships].name;
        iconv(ic, &inptr, &in, &outptr, &out);

        /* We're done with this ship, increment the counter */
        ++num_ships;
        len += 0x2C;
    }

    sylverant_db_result_free(result);

    if(qlist[c->type][c->language_code].cats && !menu_code) {
        /* Add the entry for Offline Quests. */
        memset(&pkt->entries[num_ships], 0, 0x2C);

        /* Fill in what we have */
        pkt->entries[num_ships].menu_id = LE32(0x000000FF);
        pkt->entries[num_ships].item_id = LE32(0xDEADBEEF);
        pkt->entries[num_ships].flags = LE16(0x0000);

        /* Create the name string */
        memcpy(pkt->entries[num_ships].name,
               "O\0f\0f\0l\0i\0n\0e\0 \0Q\0u\0e\0s\0t\0s\0", 28);

        /* We're done with this "ship", increment the counter */
        ++num_ships;
        len += 0x2C;
    }

    /* Make sure we have at least one ship... */
    if(num_ships == 1) {
        /* Clear out the ship information */
        memset(&pkt->entries[num_ships], 0, 0x2C);
        pkt->entries[num_ships].menu_id = LE32(0xDEADBEEF);
        pkt->entries[num_ships].item_id = LE32(0x00000000);
        pkt->entries[num_ships].flags = LE16(0x0000);

        /* And convert to UTF16 */
        in = strlen(no_ship_msg);
        out = 0x22;
        inptr = no_ship_msg;
        outptr = (char *)pkt->entries[num_ships].name;
        iconv(ic, &inptr, &in, &outptr, &out);

        ++num_ships;
        len += 0x2C;
    }

    /* Fill in the rest of the header */
    pkt->hdr.pkt_len = LE16(len);
    pkt->hdr.flags = (uint8_t)(num_ships - 1);

    iconv_close(ic);

    /* Send the packet away */
    return crypt_send(c, len);

out:
    iconv_close(ic);
    return i;
}

int send_ship_list(login_client_t *c, uint16_t menu_code) {
    /* Call the appropriate function */
    switch(c->type) {
        case CLIENT_TYPE_DC:
        case CLIENT_TYPE_GC:
            return send_ship_list_dc(c, menu_code);

        case CLIENT_TYPE_PC:
            return send_ship_list_pc(c, menu_code);
    }

    return -1;
}

static int send_info_reply_dc(login_client_t *c, const char msg[]) {
    dc_info_reply_pkt *pkt = (dc_info_reply_pkt *)sendbuf;
    iconv_t ic;
    size_t in, out;
    ICONV_CONST char *inptr;
    char *outptr;

    if(c->type == CLIENT_TYPE_DC || c->type == CLIENT_TYPE_GC) {
        if(msg[1] == 'J') {
            ic = iconv_open("SHIFT_JIS", "UTF-8");
        }
        else {
            ic = iconv_open("ISO-8859-1", "UTF-8");
        }
    }
    else {
        ic = iconv_open("UTF-16LE", "UTF-8");
    }

    if(ic == (iconv_t)-1) {
        perror("iconv_open");
        return -1;
    }

    /* Convert the message to the appropriate encoding. */
    in = strlen(msg);
    out = 65524;
    inptr = (ICONV_CONST char *)msg;
    outptr = pkt->msg;
    iconv(ic, &inptr, &in, &outptr, &out);
    iconv_close(ic);

    /* Figure out how long the new string is. */
    out = 65524 - out + 12;

    /* Fill in the oddities of the packet. */
    pkt->odd[0] = LE32(0x00200000);
    pkt->odd[1] = LE32(0x00200020);

    /* Pad to a length that's at divisible by 4. */
    while(out & 0x03) {
        sendbuf[out++] = 0;
    }

    /* Fill in the header */
    if(c->type == CLIENT_TYPE_DC || c->type == CLIENT_TYPE_GC) {
        pkt->hdr.dc.pkt_type = INFO_REPLY_TYPE;
        pkt->hdr.dc.flags = 0;
        pkt->hdr.dc.pkt_len = LE16(out);
    }
    else {
        pkt->hdr.pc.pkt_type = INFO_REPLY_TYPE;
        pkt->hdr.pc.flags = 0;
        pkt->hdr.pc.pkt_len = LE16(out);
    }

    /* Send the packet away */
    return crypt_send(c, out);
}

int send_info_reply(login_client_t *c, const char msg[]) {
    /* Call the appropriate function. */
    switch(c->type) {
        case CLIENT_TYPE_DC:
        case CLIENT_TYPE_PC:
        case CLIENT_TYPE_GC:
            return send_info_reply_dc(c, msg);
    }

    return -1;
}

/* Send a simple (header-only) packet to the client */
static int send_simple_dc(login_client_t *c, int type, int flags) {
    dc_pkt_hdr_t *pkt = (dc_pkt_hdr_t *)sendbuf;

    /* Fill in the header */
    pkt->pkt_type = (uint8_t)type;
    pkt->flags = (uint8_t)flags;
    pkt->pkt_len = LE16(4);

    /* Send the packet away */
    return crypt_send(c, 4);
}

static int send_simple_pc(login_client_t *c, int type, int flags) {
    pc_pkt_hdr_t *pkt = (pc_pkt_hdr_t *)sendbuf;

    /* Fill in the header */
    pkt->pkt_type = (uint8_t)type;
    pkt->flags = (uint8_t)flags;
    pkt->pkt_len = LE16(4);

    /* Send the packet away */
    return crypt_send(c, 4);
}

int send_simple(login_client_t *c, int type, int flags) {
    /* Call the appropriate function. */
    switch(c->type) {
        case CLIENT_TYPE_DC:
        case CLIENT_TYPE_GC:
            return send_simple_dc(c, type, flags);

        case CLIENT_TYPE_PC:
            return send_simple_pc(c, type, flags);
    }

    return -1;
}

/* Send the list of quests in a category to the client. */
static int send_dc_quest_list(login_client_t *c,
                              sylverant_quest_category_t *l, uint32_t ver) {
    dc_quest_list_pkt *pkt = (dc_quest_list_pkt *)sendbuf;
    int i, len = 0x04, entries = 0;
    iconv_t ic;
    size_t in, out;
    ICONV_CONST char *inptr;
    char *outptr;

    /* Quest names are stored internally as UTF-8, convert to the appropriate
       encoding. */
    if(c->language_code == CLIENT_LANG_JAPANESE) {
        ic = iconv_open("SHIFT_JIS", "UTF-8");
    }
    else {
        ic = iconv_open("ISO-8859-1", "UTF-8");
    }

    if(ic == (iconv_t)-1) {
        perror("iconv_open");
        return -1;
    }

    /* Clear out the header */
    memset(pkt, 0, 0x04);

    /* Fill in the header */
    pkt->hdr.pkt_type = DL_QUEST_LIST_TYPE;

    for(i = 0; i < l->quest_count; ++i) {
        if(!(l->quests[i].versions & ver)) {
            continue;
        }

        /* Clear the entry */
        memset(pkt->entries + entries, 0, 0x98);

        /* Copy the category's information over to the packet */
        pkt->entries[entries].menu_id = LE32(0x00000004);
        pkt->entries[entries].item_id = LE32(i);

        /* Convert the name and the description to the right encoding. */
        in = 32;
        out = 32;
        inptr = l->quests[i].name;
        outptr = (char *)pkt->entries[entries].name;
        iconv(ic, &inptr, &in, &outptr, &out);

        in = 112;
        out = 112;
        inptr = l->quests[i].desc;
        outptr = (char *)pkt->entries[entries].desc;
        iconv(ic, &inptr, &in, &outptr, &out);

        ++entries;
        len += 0x98;
    }

    iconv_close(ic);

    /* Fill in the rest of the header */
    pkt->hdr.flags = entries;
    pkt->hdr.pkt_len = LE16(len);

    /* Send it away */
    return crypt_send(c, len);
}

static int send_pc_quest_list(login_client_t *c,
                              sylverant_quest_category_t *l) {
    pc_quest_list_pkt *pkt = (pc_quest_list_pkt *)sendbuf;
    int i, len = 0x04, entries = 0;
    iconv_t ic;
    size_t in, out;
    ICONV_CONST char *inptr;
    char *outptr;

    /* Quest names are stored internally as UTF-8, convert to UTF-16. */
    ic = iconv_open("UTF-16LE", "UTF-8");

    if(ic == (iconv_t)-1) {
        perror("iconv_open");
        return -1;
    }

    /* Clear out the header */
    memset(pkt, 0, 0x04);

    /* Fill in the header */
    pkt->hdr.pkt_type = DL_QUEST_LIST_TYPE;

    for(i = 0; i < l->quest_count; ++i) {
        /* Clear the entry */
        memset(pkt->entries + entries, 0, 0x98);

        /* Copy the category's information over to the packet */
        pkt->entries[entries].menu_id = LE32(0x00000004);
        pkt->entries[entries].item_id = LE32(i);

        /* Convert the name and the description to UTF-16. */
        in = 32;
        out = 64;
        inptr = l->quests[i].name;
        outptr = (char *)pkt->entries[entries].name;
        iconv(ic, &inptr, &in, &outptr, &out);

        in = 112;
        out = 224;
        inptr = l->quests[i].desc;
        outptr = (char *)pkt->entries[entries].desc;
        iconv(ic, &inptr, &in, &outptr, &out);

        ++entries;
        len += 0x128;
    }

    iconv_close(ic);

    /* Fill in the rest of the header */
    pkt->hdr.flags = entries;
    pkt->hdr.pkt_len = LE16(len);

    /* Send it away */
    return crypt_send(c, len);
}

static int send_gc_quest_list(login_client_t *c,
                              sylverant_quest_category_t *l) {
    dc_quest_list_pkt *pkt = (dc_quest_list_pkt *)sendbuf;
    int i, len = 0x04, entries = 0;
    iconv_t ic;
    size_t in, out;
    ICONV_CONST char *inptr;
    char *outptr;

    /* Quest names are stored internally as UTF-8, convert to the appropriate
       encoding. */
    if(c->language_code == CLIENT_LANG_JAPANESE) {
        ic = iconv_open("SHIFT_JIS", "UTF-8");
    }
    else {
        ic = iconv_open("ISO-8859-1", "UTF-8");
    }

    if(ic == (iconv_t)-1) {
        perror("iconv_open");
        return -1;
    }

    /* Clear out the header */
    memset(pkt, 0, 0x04);

    /* Fill in the header */
    pkt->hdr.pkt_type = DL_QUEST_LIST_TYPE;

    for(i = 0; i < l->quest_count; ++i) {
        /* Clear the entry */
        memset(pkt->entries + entries, 0, 0x98);

        /* Copy the category's information over to the packet */
        pkt->entries[entries].menu_id = LE32(0x00000004);
        pkt->entries[entries].item_id = LE32(i);

        /* Convert the name and the description to the right encoding. */
        in = 32;
        out = 32;
        inptr = l->quests[i].name;
        outptr = (char *)pkt->entries[entries].name;
        iconv(ic, &inptr, &in, &outptr, &out);

        in = 112;
        out = 112;
        inptr = l->quests[i].desc;
        outptr = (char *)pkt->entries[entries].desc;
        iconv(ic, &inptr, &in, &outptr, &out);

        ++entries;
        len += 0x98;
    }

    iconv_close(ic);

    /* Fill in the rest of the header */
    pkt->hdr.flags = entries;
    pkt->hdr.pkt_len = LE16(len);

    /* Send it away */
    return crypt_send(c, len);
}

int send_quest_list(login_client_t *c, sylverant_quest_category_t *l) {
    /* Call the appropriate function. */
    switch(c->type) {
        case CLIENT_TYPE_DC:
            return send_dc_quest_list(c, l, c->version);

        case CLIENT_TYPE_PC:
            return send_pc_quest_list(c, l);

        case CLIENT_TYPE_GC:
            return send_gc_quest_list(c, l);
    }

    return -1;
}

/* Send a quest to a client. This only supports the .qst format that Qedit spits
   out by default (Download quest format). */
int send_quest(login_client_t *c, sylverant_quest_t *q) {
    char filename[256];
    FILE *fp;
    long len;
    size_t read;

    /* Figure out what file we're going to send. */
    sprintf(filename, "%s/%s-%s/%s.qst", cfg.quests_dir, type_codes[c->type],
            language_codes[c->language_code], q->prefix);
    fp = fopen(filename, "rb");

    if(!fp) {
        return -1;
    }

    /* Figure out how long the file is. */
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    /* Copy the file (in chunks if necessary) to the sendbuf to actually send
       away. */
    while(len) {
        read = fread(sendbuf, 1, 65536, fp);

        /* If we can't read from the file, bail. */
        if(!read) {
            fclose(fp);
            return -2;
        }

        /* Make sure we read up to a header-size boundary. */
        if((read & (c->hdr_size - 1)) && !feof(fp)) {
            long amt = (read & (c->hdr_size - 1));

            fseek(fp, -amt, SEEK_CUR);
            read -= amt;
        }

        /* Send this chunk away. */
        if(crypt_send(c, read)) {
            fclose(fp);
            return -3;
        }

        len -= read;
    }

    /* We're finished. */
    fclose(fp);
    return 0;
}
