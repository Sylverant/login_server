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
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <iconv.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <sylverant/encryption.h>
#include <sylverant/database.h>

#include "login_packets.h"

extern sylverant_dbconn_t conn;

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

/* Send a Blue Burst Welcome packet to the given client. */
int send_bb_welcome(login_client_t *c, uint8_t svect[48], uint8_t cvect[48]) {
    bb_login_welcome_pkt *pkt = (bb_login_welcome_pkt *)sendbuf;

    /* Scrub the buffer */
    memset(pkt, 0, sizeof(bb_login_welcome_pkt));

    /* Fill in the header */
    pkt->hdr.pkt_len = LE16(LOGIN_BB_WELCOME_LENGTH);
    pkt->hdr.pkt_type = LE16(LOGIN_BB_WELCOME_TYPE);

    /* Fill in the required message */
    memcpy(pkt->copyright, login_bb_welcome_copyright, 75);

    /* Fill in the encryption vectors */
    memcpy(pkt->svect, svect, 48);
    memcpy(pkt->cvect, cvect, 48);

    /* Send the packet away */
    return send_raw(c, LOGIN_BB_WELCOME_LENGTH);
}

/* Send a Dreamcast/PC Welcome packet to the given client. */
int send_dc_welcome(login_client_t *c, uint32_t svect, uint32_t cvect) {
    dc_login_welcome_pkt *pkt = (dc_login_welcome_pkt *)sendbuf;

    /* Scrub the buffer */
    memset(pkt, 0, sizeof(dc_login_welcome_pkt));

    /* Fill in the header */
    if(c->type == CLIENT_TYPE_DC || c->type == CLIENT_TYPE_GC) {
        pkt->hdr.dc.pkt_len = LE16(LOGIN_DC_WELCOME_LENGTH);
        pkt->hdr.dc.pkt_type = LOGIN_DC_WELCOME_TYPE;
    }
    else {
        pkt->hdr.pc.pkt_len = LE16(LOGIN_DC_WELCOME_LENGTH);
        pkt->hdr.pc.pkt_type = LOGIN_DC_WELCOME_TYPE;
    }

    /* Fill in the required message */
    memcpy(pkt->copyright, login_dc_welcome_copyright, 52);

    /* Fill in the encryption vectors */
    pkt->svect = LE32(svect);
    pkt->cvect = LE32(cvect);

    /* Send the packet away */
    return send_raw(c, LOGIN_DC_WELCOME_LENGTH);
}

/* Send a large message packet to the given client. */
int send_large_msg(login_client_t *c, char msg[]) {
    login_large_msg_pkt *pkt = (login_large_msg_pkt *)sendbuf;
    int slen = strlen(msg), i;
    uint16_t len = 0x0C + (slen << 1);

    /* Clear the packet first. */
    memset(pkt, 0, sizeof(login_large_msg_pkt));

    /* Fill in the language marker for English. */
    pkt->lang[0] = '\t';
    pkt->lang[2] = 'E';

    /* Fill in the message */
    for(i = 0; i < slen; ++i) {
        pkt->message[(i << 1)]     = msg[i];
        pkt->message[(i << 1) + 1] = 0;
    }

    /* Append a NUL terminator, and any padding needed */
    sendbuf[len++] = 0;
    sendbuf[len++] = 0;

    while(len & 0x07) {
        sendbuf[len++] = 0;
    }

    /* Fill in the header */
    pkt->hdr.pkt_len = LE16(len);
    pkt->hdr.pkt_type = LE16(LOGIN_LARGE_MESSAGE_TYPE);

    /* Send the packet away */
    return crypt_send(c, len);
}

/* Send the Dreamcast security packet to the given client. */
int send_dc_security(login_client_t *c, uint32_t gc, uint8_t *data,
                     int data_len) {
    dc_login_security_pkt *pkt = (dc_login_security_pkt *)sendbuf;

    /* Wipe the packet */
    memset(pkt, 0, sizeof(dc_login_security_pkt));

    /* Fill in the header */
    if(c->type == CLIENT_TYPE_DC || c->type == CLIENT_TYPE_GC) {
        pkt->hdr.dc.pkt_type = LOGIN_DC_SECURITY_TYPE;
        pkt->hdr.dc.pkt_len = LE16((0x0C + data_len));
    }
    else {
        pkt->hdr.pc.pkt_type = LOGIN_DC_SECURITY_TYPE;
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
static int send_redirect_bb(login_client_t *c, in_addr_t ip, uint16_t port) {
    bb_login_redirect_pkt *pkt = (bb_login_redirect_pkt *)sendbuf;

    /* Wipe the packet */
    memset(pkt, 0, LOGIN_BB_REDIRECT_LENGTH);

    /* Fill in the header */
    pkt->hdr.pkt_len = LE16(LOGIN_BB_REDIRECT_LENGTH);
    pkt->hdr.pkt_type = LE16(LOGIN_REDIRECT_TYPE);

    /* Fill in the IP and port */
    pkt->ip_addr = ip;
    pkt->port = LE16(port);

    /* Send the packet away */
    return crypt_send(c, LOGIN_BB_REDIRECT_LENGTH);
}

/* Send a redirect packet to the given client. */
static int send_redirect_dc(login_client_t *c, in_addr_t ip, uint16_t port) {
    dc_login_redirect_pkt *pkt = (dc_login_redirect_pkt *)sendbuf;

    /* Wipe the packet */
    memset(pkt, 0, LOGIN_DC_REDIRECT_LENGTH);

    /* Fill in the header */
    if(c->type == CLIENT_TYPE_DC || c->type == CLIENT_TYPE_GC) {
        pkt->hdr.dc.pkt_type = LOGIN_REDIRECT_TYPE;
        pkt->hdr.dc.pkt_len = LE16(LOGIN_DC_REDIRECT_LENGTH);
    }
    else {
        pkt->hdr.pc.pkt_type = LOGIN_REDIRECT_TYPE;
        pkt->hdr.pc.pkt_len = LE16(LOGIN_DC_REDIRECT_LENGTH);
    }

    /* Fill in the IP and port */
    pkt->ip_addr = ip;
    pkt->port = LE16(port);

    /* Send the packet away */
    return crypt_send(c, LOGIN_DC_REDIRECT_LENGTH);
}

int send_redirect(login_client_t *c, in_addr_t ip, uint16_t port) {
    /* Call the appropriate function. */
    switch(c->type) {
        case CLIENT_TYPE_BB_LOGIN:
        case CLIENT_TYPE_BB_CHARACTER:
            return send_redirect_bb(c, ip, port);

        case CLIENT_TYPE_DC:
        case CLIENT_TYPE_PC:
            return send_redirect_dc(c, ip, port);
    }

    return -1;
}

/* Send the packet to clients that will help sort out PSOGC versus PSOPC
   users. */
int send_selective_redirect(login_client_t *c, in_addr_t ip, uint16_t port) {
    dc_login_redirect_pkt *pkt = (dc_login_redirect_pkt *)sendbuf;

    /* Verify we got the sendbuf. */
    if(!sendbuf) {
        return -1;
    }

    /* Wipe the packet */
    memset(pkt, 0, 0xB0);

    /* Fill in the header */
    pkt->hdr.dc.pkt_type = LOGIN_REDIRECT_TYPE;
    pkt->hdr.dc.pkt_len = LE16(0xB0);

    /* Fill in the IP and port */
    pkt->ip_addr = ip;
    pkt->port = LE16(port);

    /* Send the packet away */
    return send_raw(c, 0xB0);
}

/* Send a timestamp packet to the given client. */
static int send_timestamp_bb(login_client_t *c) {
    bb_login_timestamp_pkt *pkt = (bb_login_timestamp_pkt *)sendbuf;
    struct timeval rawtime;
    struct tm cooked;

    /* Wipe the packet */
    memset(pkt, 0, LOGIN_BB_TIMESTAMP_LENGTH);

    /* Fill in the header */
    pkt->hdr.pkt_len = LE16(LOGIN_BB_TIMESTAMP_LENGTH);
    pkt->hdr.pkt_type = LE16(LOGIN_TIMESTAMP_TYPE);

    /* Get thet timestamp */
    gettimeofday(&rawtime, NULL);

    /* Get UTC */
    gmtime_r(&rawtime.tv_sec, &cooked);

    /* Fill in the timestamp */
    sprintf(pkt->timestamp, "%u:%02u:%02u: %02u:%02u:%02u.%03u",
            cooked.tm_year + 1900, cooked.tm_mon + 1, cooked.tm_mday,
            cooked.tm_hour, cooked.tm_min, cooked.tm_sec,
            (unsigned)(rawtime.tv_usec / 1000));

    /* Send the packet away */
    return crypt_send(c, LOGIN_BB_TIMESTAMP_LENGTH);
}

static int send_timestamp_dc(login_client_t *c) {
    dc_login_timestamp_pkt *pkt = (dc_login_timestamp_pkt *)sendbuf;
    struct timeval rawtime;
    struct tm cooked;

    /* Wipe the packet */
    memset(pkt, 0, LOGIN_DC_TIMESTAMP_LENGTH);

    /* Fill in the header */
    if(c->type == CLIENT_TYPE_DC || c->type == CLIENT_TYPE_GC) {
        pkt->hdr.dc.pkt_type = LOGIN_TIMESTAMP_TYPE;
        pkt->hdr.dc.pkt_len = LE16(LOGIN_DC_TIMESTAMP_LENGTH);
    }
    else {
        pkt->hdr.pc.pkt_type = LOGIN_TIMESTAMP_TYPE;
        pkt->hdr.pc.pkt_len = LE16(LOGIN_DC_TIMESTAMP_LENGTH);
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
    return crypt_send(c, LOGIN_DC_TIMESTAMP_LENGTH);
}

int send_timestamp(login_client_t *c) {
    /* Call the appropriate function */
    switch(c->type) {
        case CLIENT_TYPE_BB_LOGIN:
        case CLIENT_TYPE_BB_CHARACTER:
            return send_timestamp_bb(c);

        case CLIENT_TYPE_DC:
        case CLIENT_TYPE_PC:
        case CLIENT_TYPE_GC:
            return send_timestamp_dc(c);
    }

    return -1;
}

/* Send a scrolling message packet to the given client. */
int send_scroll_msg(login_client_t *c, char msg[]) {
    login_scroll_msg_pkt *pkt = (login_scroll_msg_pkt *)sendbuf;
    int slen = strlen(msg), i;
    uint16_t len = 0x10 + (slen << 1);

    /* Clear the packet out */
    memset(pkt, 0, len);

    /* Fill in the message */
    for(i = 0; i < slen; ++i) {
        pkt->msg[(i << 1)]     = msg[i];
        pkt->msg[(i << 1) + 1] = 0;
    }

    /* Append a NUL terminator, and any padding needed */
    sendbuf[len++] = 0;
    sendbuf[len++] = 0;

    while(len & 0x07) {
        sendbuf[len++] = 0;
    }

    /* Fill in the header */
    pkt->hdr.pkt_len = LE16(len);
    pkt->hdr.pkt_type = LE16(LOGIN_SCROLL_MESSAGE_TYPE);

    /* Send the packet away */
    return crypt_send(c, len);
}

/* Send a option reply packet to the given client. */
int send_optreply(login_client_t *c, uint8_t keys[420]) {
    login_option_reply_pkt *pkt = (login_option_reply_pkt *)sendbuf;

    /* Clear it out first */
    memset(pkt, 0, LOGIN_SECURITY_LENGTH);

    /* Fill in the header */
    pkt->hdr.pkt_len = LE16(LOGIN_OPTION_REPLY_LENGTH);
    pkt->hdr.pkt_type = LE16(LOGIN_OPTION_REPLY_TYPE);

    /* Copy the options in */
    memcpy(pkt->keys, keys, 420);

    /* Set the flags */
    memset(pkt->flags, 0xFF, 4);

    /* Send the packet away */
    return crypt_send(c, LOGIN_OPTION_REPLY_LENGTH);
}

/* Send a character ack to the given client. */
int send_char_ack(login_client_t *c, uint8_t slot, uint8_t reason) {
    login_char_ack_pkt *pkt = (login_char_ack_pkt *)sendbuf;

    /* Clear it out */
    memset(pkt, 0, LOGIN_CHAR_ACK_LENGTH);

    /* Fill in the header */
    pkt->hdr.pkt_len = LE16(LOGIN_CHAR_ACK_LENGTH);
    pkt->hdr.pkt_type = LE16(LOGIN_CHAR_ACK_TYPE);

    /* Set the slot and reason */
    pkt->slot = slot;
    pkt->reason = reason;

    /* Send the packet away */
    return crypt_send(c, LOGIN_CHAR_ACK_LENGTH);
}

/* Send character data to the given client. */
int send_char_data(login_client_t *c, sylverant_mini_char_t *ch) {
    /* Copy it to the send buffer */
    memcpy(sendbuf, ch, LOGIN_CHAR_DATA_LENGTH);

    /* Send the packet away */
    return crypt_send(c, LOGIN_CHAR_DATA_LENGTH);
}

/* Send a guild card checksum ack to the given client. */
int send_guild_ack(login_client_t *c, uint32_t ack) {
    login_guild_ack_pkt *pkt = (login_guild_ack_pkt *)sendbuf;

    /* Clear it out */
    memset(pkt, 0, LOGIN_GUILD_ACK_LENGTH);

    /* Fill in the header */
    pkt->hdr.pkt_len = LE16(LOGIN_GUILD_ACK_LENGTH);
    pkt->hdr.pkt_type = LE16((LOGIN_GUILD_REQUEST_TYPE | 0x0200));

    /* Fill in the acknowledgement value */
    pkt->ack = LE32(ack);

    /* Send the packet away */
    return crypt_send(c, LOGIN_GUILD_ACK_LENGTH);
}

/* Send a guild card checksum packet to the given client. */
int send_gc_checksum(login_client_t *c, uint32_t checksum) {
    login_gc_csum_pkt *pkt = (login_gc_csum_pkt *)sendbuf;

    /* Clear it out */
    memset(pkt, 0, LOGIN_GUILD_CHECKSUM_LENGTH);

    /* Fill in the header */
    pkt->hdr.pkt_len = LE16(LOGIN_GUILD_CHECKSUM_LENGTH);
    pkt->hdr.pkt_type = LE16((LOGIN_GUILD_CARDS_TYPE | 0x0100));

    /* Fill in the required values */
    pkt->one = 1;
    pkt->gc_len = LE16(0xD590);
    pkt->checksum = LE32(checksum);

    /* Send the packet away */
    return crypt_send(c, LOGIN_GUILD_CHECKSUM_LENGTH);
}

/* Send guild card data to the given client. */
int send_gc_data(login_client_t *c, uint8_t *data, uint8_t idx) {
    bb_pkt_header_t *pkt = (bb_pkt_header_t *)sendbuf;
    uint16_t amt = idx == 2 ? 1440 : 26640;

    /* Clear the header first */
    memset(pkt, 0, 0x10);

    /* Fill in the header data */
    pkt->pkt_len = LE16(amt);
    pkt->pkt_type = LE16((LOGIN_GUILD_CARDS_TYPE | 0x0200));
    sendbuf[0x0C] = idx;

    /* Copy the data over */
    data += idx * 26624;
    memcpy(sendbuf + 0x10, data, amt - 0x10);

    /* Send the packet away */
    return crypt_send(c, amt);
}

/* Send the list of ships to the client. */
static int send_ship_list_bb(login_client_t *c) {
    bb_login_ship_list_pkt *pkt = (bb_login_ship_list_pkt *)sendbuf;
    const char server_name[] = "S\0Y\0L\0V\0E\0R\0A\0N\0T\0";
    const char no_ship_msg[] = "N\0o\0 \0s\0h\0i\0p\0s\0!\0";
    char query[256], tmp[18];
    uint32_t num_ships = 0;
    void *result;
    char **row;
    uint32_t ship_id, players;
    int i, len = 0x36;

    /* Clear the base packet */
    memset(pkt, 0, sizeof(bb_login_ship_list_pkt));

    /* Fill in some basic stuff */
    pkt->hdr.pkt_type = LE16(LOGIN_BB_SHIP_LIST_TYPE);
    pkt->thirty_two = 0x20;
    pkt->unk1 = LE32(0xFFFFFFF4);
    pkt->four = 0x04;
    memcpy(pkt->sname, server_name, 18);

    /* Get ready to query the database */
    sprintf(query, "SELECT ship_id, name, players FROM online_ships");

    /* Query the database and see what we've got */
    if(sylverant_db_query(&conn, query)) {
        return -1;
    }

    if((result = sylverant_db_result_store(&conn)) == NULL) {
        return -2;
    }

    /* As long as we have some rows, go */
    while((row = sylverant_db_result_fetch(result))) {
        /* Clear out the ship information */
        memset(&pkt->inf[num_ships], 0, sizeof(login_ship_info_t));

        /* Grab info from the row */
        ship_id = (uint32_t)strtoul(row[0], NULL, 0);
        players = (uint32_t)strtoul(row[2], NULL, 0);

        /* Fill in what we have */
        pkt->inf[num_ships].eighteen = 0x12;
        pkt->inf[num_ships].ship_id = LE32(ship_id);

        /* Create the name string (ASCII) */
        sprintf(tmp, "%s (%d)", row[1], players);

        /* And convert to UTF-16 */
        i = 0;
        while(i < 17) {
            pkt->inf[num_ships].name[i << 1] = tmp[i];
            pkt->inf[num_ships].name[(i << 1) + 1] = 0x00;
            ++i;
        }

        /* We're done with this ship, increment the counter */
        ++num_ships;
        len += 0x2C;
    }

    sylverant_db_result_free(result);

    /* Make sure we have at least one ship... */
    if(!num_ships) {
        memset(&pkt->inf[0], 0, sizeof(login_ship_info_t));
        pkt->inf[0].eighteen = 0x12;
        pkt->inf[0].ship_id = 0;
        memcpy(pkt->inf[0].name, no_ship_msg, 18);

        ++num_ships;
        len += 0x2C;
    }

    /* Fill in the remainder of the packet */
    while(len & 0x07) {
        sendbuf[len++] = 0;
    }

    pkt->hdr.pkt_len = LE16(len);
    pkt->hdr.padding = LE32(num_ships);

    /* Send the packet away */
    return crypt_send(c, len);
}

/* Send the list of ships to the client. */
static int send_ship_list_dc(login_client_t *c) {
    dc_login_ship_list_pkt *pkt = (dc_login_ship_list_pkt *)sendbuf;
    char no_ship_msg[] = "No Ships";
    char query[256], tmp[18];
    uint32_t num_ships = 0;
    void *result;
    char **row;
    uint32_t ship_id, players;
    int i, len = 0x20;
    iconv_t ic = iconv_open("SHIFT_JIS", "ASCII");
    size_t in, out;
    char *inptr, *outptr;

    if(ic == (iconv_t)-1) {
        perror("iconv_open");
        return -1;
    }

    /* Clear the base packet */
    memset(pkt, 0, sizeof(dc_login_ship_list_pkt));

    /* Fill in some basic stuff */
    pkt->hdr.pkt_type = LOGIN_DC_SHIP_LIST_TYPE;

    /* Fill in the "DATABASE/JP" entry */
    memset(&pkt->entries[0], 0, 0x1C);
    pkt->entries[0].menu_id = LE32(0x00040000);
    pkt->entries[0].item_id = 0;
    pkt->entries[0].flags = LE16(0x0004);
    strcpy(pkt->entries[0].name, "DATABASE/JP");
    pkt->entries[0].name[0x11] = 0x08;
    num_ships = 1;

    /* Get ready to query the database */
    sprintf(query, "SELECT ship_id, name, players FROM online_ships");

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
        /* Clear out the ship information */
        memset(&pkt->entries[num_ships], 0, 0x1C);

        /* Grab info from the row */
        ship_id = (uint32_t)strtoul(row[0], NULL, 0);
        players = (uint32_t)strtoul(row[2], NULL, 0);

        /* Fill in what we have */
        pkt->entries[num_ships].menu_id = LE32(0x00120000);
        pkt->entries[num_ships].item_id = LE32(ship_id);
        pkt->entries[num_ships].flags = LE16(0x0000);

        /* Create the name string (ASCII) */
        sprintf(tmp, "%s (%d)", row[1], players);

        /* And convert to Shift-JIS */
        in = strlen(tmp);
        out = 0x12;
        inptr = tmp;
        outptr = pkt->entries[num_ships].name;
        iconv(ic, &inptr, &in, &outptr, &out);

        /* We're done with this ship, increment the counter */
        ++num_ships;
        len += 0x1C;
    }

    sylverant_db_result_free(result);

    /* Make sure we have at least one ship... */
    if(num_ships == 1) {
        /* Clear out the ship information */
        memset(&pkt->entries[num_ships], 0, 0x1C);
        pkt->entries[num_ships].menu_id = LE32(0xFFFFFFFF);
        pkt->entries[num_ships].item_id = LE32(0x00000000);
        pkt->entries[num_ships].flags = LE16(0x0000);
        
        /* And convert to Shift-JIS */
        in = strlen(no_ship_msg);
        out = 0x12;
        inptr = no_ship_msg;
        outptr = pkt->entries[num_ships].name;
        iconv(ic, &inptr, &in, &outptr, &out);
        
        ++num_ships;
        len += 0x1C;
    }

    /* Fill in the rest of the header */
    pkt->hdr.pkt_len = LE16(len);
    pkt->hdr.flags = (uint8_t)(num_ships - 1);

    /* Send the packet away */
    iconv_close(ic);

    return crypt_send(c, len);

out:
    iconv_close(ic);
    return i;
}

/* Send the list of ships to the client. */
static int send_ship_list_pc(login_client_t *c) {
    pc_login_ship_list_pkt *pkt = (pc_login_ship_list_pkt *)sendbuf;
    char no_ship_msg[] = "No Ships";
    char query[256], tmp[18];
    uint32_t num_ships = 0;
    void *result;
    char **row;
    uint32_t ship_id, players;
    int i, len = 0x30;
    iconv_t ic = iconv_open("UTF-16LE", "SHIFT_JIS");
    size_t in, out;
    char *inptr, *outptr;

    if(ic == (iconv_t)-1) {
        perror("iconv_open");
        return -1;
    }

    /* Clear the base packet */
    memset(pkt, 0, sizeof(dc_login_ship_list_pkt));

    /* Fill in some basic stuff */
    pkt->hdr.pkt_type = LOGIN_DC_SHIP_LIST_TYPE;

    /* Fill in the "DATABASE/JP" entry */
    memset(&pkt->entries[0], 0, 0x2C);
    pkt->entries[0].menu_id = LE32(0x00040000);
    pkt->entries[0].item_id = 0;
    pkt->entries[0].flags = LE16(0x0004);
    memcpy(pkt->entries[0].name, "D\0A\0T\0A\0B\0A\0S\0E\0/\0J\0P\0", 22);
    num_ships = 1;

    /* Get ready to query the database */
    sprintf(query, "SELECT ship_id, name, players FROM online_ships");

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
        /* Clear out the ship information */
        memset(&pkt->entries[num_ships], 0, 0x2C);

        /* Grab info from the row */
        ship_id = (uint32_t)strtoul(row[0], NULL, 0);
        players = (uint32_t)strtoul(row[2], NULL, 0);

        /* Fill in what we have */
        pkt->entries[num_ships].menu_id = LE32(0x00120000);
        pkt->entries[num_ships].item_id = LE32(ship_id);
        pkt->entries[num_ships].flags = LE16(0x0000);

        /* Create the name string (ASCII) */
        sprintf(tmp, "%s (%d)", row[1], players);

        /* And convert to UTF16 */
        in = strlen(tmp);
        out = 0x22;
        inptr = tmp;
        outptr = pkt->entries[num_ships].name;
        iconv(ic, &inptr, &in, &outptr, &out);

        /* We're done with this ship, increment the counter */
        ++num_ships;
        len += 0x2C;
    }

    sylverant_db_result_free(result);

    /* Make sure we have at least one ship... */
    if(num_ships == 1) {
        /* Clear out the ship information */
        memset(&pkt->entries[num_ships], 0, 0x2C);
        pkt->entries[num_ships].menu_id = LE32(0xFFFFFFFF);
        pkt->entries[num_ships].item_id = LE32(0x00000000);
        pkt->entries[num_ships].flags = LE16(0x0000);

        /* And convert to UTF16 */
        in = strlen(no_ship_msg);
        out = 0x22;
        inptr = no_ship_msg;
        outptr = pkt->entries[num_ships].name;
        iconv(ic, &inptr, &in, &outptr, &out);

        ++num_ships;
        len += 0x2C;
    }

    /* Fill in the rest of the header */
    pkt->hdr.pkt_len = LE16(len);
    pkt->hdr.flags = (uint8_t)(num_ships - 1);

    /* Send the packet away */
    iconv_close(ic);

    return crypt_send(c, len);

out:
    iconv_close(ic);
    return i;
}

int send_ship_list(login_client_t *c) {
    /* Call the appropriate function */
    switch(c->type) {
        case CLIENT_TYPE_BB_CHARACTER:
            return send_ship_list_bb(c);

        case CLIENT_TYPE_DC:
        case CLIENT_TYPE_GC:
            return send_ship_list_dc(c);

        case CLIENT_TYPE_PC:
            return send_ship_list_pc(c);
    }

    return -1;
}

/* Send an information reply to the given client. */
static int send_info_reply_bb(login_client_t *c, char msg[]) {
    login_scroll_msg_pkt *pkt = (login_scroll_msg_pkt *)sendbuf;
    int slen = strlen(msg), i;
    uint16_t len = 0x10 + (slen << 1);

    /* Clear the packet out */
    memset(pkt, 0, len);

    /* Fill in the message */
    for(i = 0; i < slen; ++i) {
        pkt->msg[(i << 1)]     = msg[i];
        pkt->msg[(i << 1) + 1] = 0;
    }

    /* Append a NUL terminator, and any padding needed */
    sendbuf[len++] = 0;
    sendbuf[len++] = 0;

    while(len & 0x07) {
        sendbuf[len++] = 0;
    }

    /* Fill in the header */
    pkt->hdr.pkt_len = LE16(len);
    pkt->hdr.pkt_type = LE16(LOGIN_INFO_REPLY_TYPE);

    /* Send the packet away */
    return crypt_send(c, len);
}

static int send_info_reply_dc(login_client_t *c, char msg[]) {
    dc_login_info_reply_pkt *pkt = (dc_login_info_reply_pkt *)sendbuf;
    iconv_t ic;
    size_t in, out;
    char *inptr, *outptr;

    if(c->type == CLIENT_TYPE_DC || c->type == CLIENT_TYPE_GC) {
        ic = iconv_open("SHIFT_JIS", "SHIFT_JIS");
    }
    else {
        ic = iconv_open("UTF-16LE", "SHIFT_JIS");
    }

    if(ic == (iconv_t)-1) {
        perror("iconv_open");
        return -1;
    }

    /* Convert the message to the appropriate encoding. */
    in = strlen(msg);
    out = 65524;
    inptr = msg;
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
    if(c->type == CLIENT_TYPE_DC) {
        pkt->hdr.dc.pkt_type = LOGIN_INFO_REPLY_TYPE;
        pkt->hdr.dc.flags = 0;
        pkt->hdr.dc.pkt_len = LE16(out);
    }
    else {
        pkt->hdr.pc.pkt_type = LOGIN_INFO_REPLY_TYPE;
        pkt->hdr.pc.flags = 0;
        pkt->hdr.pc.pkt_len = LE16(out);
    }

    /* Send the packet away */
    return crypt_send(c, out);
}

int send_info_reply(login_client_t *c, char msg[]) {
    /* Call the appropriate function. */
    switch(c->type) {
        case CLIENT_TYPE_BB_CHARACTER:
            return send_info_reply_bb(c, msg);

        case CLIENT_TYPE_DC:
        case CLIENT_TYPE_PC:
        case CLIENT_TYPE_GC:
            return send_info_reply_dc(c, msg);
    }

    return -1;
}

/* Send a simple (header-only) packet to the client */
static int send_simple_dc(login_client_t *c, int type, int flags) {
    dc_pkt_header_t *pkt = (dc_pkt_header_t *)sendbuf;

    /* Fill in the header */
    pkt->pkt_type = (uint8_t)type;
    pkt->flags = (uint8_t)flags;
    pkt->pkt_len = LE16(4);

    /* Send the packet away */
    return crypt_send(c, 4);
}

static int send_simple_pc(login_client_t *c, int type, int flags) {
    pc_pkt_header_t *pkt = (pc_pkt_header_t *)sendbuf;

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
