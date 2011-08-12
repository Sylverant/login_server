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
#include <stdarg.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <sylverant/config.h>
#include <sylverant/encryption.h>
#include <sylverant/database.h>
#include <sylverant/quest.h>

#include "login_packets.h"

extern sylverant_dbconn_t conn;
extern sylverant_config_t *cfg;
extern sylverant_quest_list_t qlist[CLIENT_TYPE_COUNT][CLIENT_LANG_COUNT];

uint8_t sendbuf[65536];

static void ascii_to_utf16(const char *in, uint16_t *out, int maxlen) {
    while(*in && maxlen) {
        *out++ = LE16(*in++);
        --maxlen;
    }

    while(maxlen--) {
        *out++ = 0;
    }
}

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
    if(c->type == CLIENT_TYPE_DC || c->type == CLIENT_TYPE_GC ||
       c->type == CLIENT_TYPE_EP3) {
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

/* Send a Blue Burst Welcome packet to the given client. */
int send_bb_welcome(login_client_t *c, const uint8_t svect[48],
                    const uint8_t cvect[48]) {
    bb_welcome_pkt *pkt = (bb_welcome_pkt *)sendbuf;

    /* Scrub the buffer */
    memset(pkt, 0, sizeof(bb_welcome_pkt));

    /* Fill in the header */
    pkt->hdr.pkt_len = LE16(BB_WELCOME_LENGTH);
    pkt->hdr.pkt_type = LE16(BB_WELCOME_TYPE);

    /* Fill in the required message */
    memcpy(pkt->copyright, login_bb_welcome_copyright, 75);

    /* Fill in the encryption vectors */
    memcpy(pkt->svect, svect, 48);
    memcpy(pkt->cvect, cvect, 48);

    /* Send the packet away */
    return send_raw(c, BB_WELCOME_LENGTH);
}

static int send_large_msg_dc(login_client_t *c, const char msg[]) {
    dc_msg_box_pkt *pkt = (dc_msg_box_pkt *)sendbuf;
    int size = 4;
    iconv_t ic;
    size_t in, out;
    ICONV_CONST char *inptr;
    char *outptr;

    if(c->type == CLIENT_TYPE_DC || c->type == CLIENT_TYPE_GC ||
       c->type == CLIENT_TYPE_EP3) {
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

static int send_msg_bb(login_client_t *c, const char msg[]) {
    bb_msg_box_pkt *pkt = (bb_msg_box_pkt *)sendbuf;
    int size = 8;
    iconv_t ic;
    size_t in, out;
    ICONV_CONST char *inptr;
    char *outptr;

    ic = iconv_open("UTF-16LE", "UTF-8");

    if(ic == (iconv_t)-1) {
        perror("iconv_open");
        return -1;
    }

    /* Convert to the proper encoding */
    in = strlen(msg) + 1;
    out = 65520;
    inptr = (ICONV_CONST char *)msg;
    outptr = (char *)pkt->msg;
    iconv(ic, &inptr, &in, &outptr, &out);
    iconv_close(ic);

    /* Figure out how long the packet is */
    size += 65520 - out;

    /* Pad to a length divisible by 4 */
    while(size & 0x04) {
        sendbuf[size++] = 0;
    }

    /* Fill in the header */
    pkt->hdr.pkt_type = LE16(MSG_BOX_TYPE);
    pkt->hdr.flags = 0;
    pkt->hdr.pkt_len = LE16(size);

    /* Send the packet away */
    return crypt_send(c, size);
}

int send_large_msg(login_client_t *c, const char msg[]) {
    /* Call the appropriate function. */
    switch(c->type) {
        case CLIENT_TYPE_DC:
        case CLIENT_TYPE_GC:
        case CLIENT_TYPE_PC:
        case CLIENT_TYPE_EP3:
            return send_large_msg_dc(c, msg);

        case CLIENT_TYPE_BB_LOGIN:
        case CLIENT_TYPE_BB_CHARACTER:
            return send_msg_bb(c, msg);
    }

    return -1;
}

/* Send the Dreamcast security packet to the given client. */
int send_dc_security(login_client_t *c, uint32_t gc, const void *data,
                     int data_len) {
    dc_security_pkt *pkt = (dc_security_pkt *)sendbuf;

    /* Wipe the packet */
    memset(pkt, 0, sizeof(dc_security_pkt));

    /* Fill in the header */
    if(c->type == CLIENT_TYPE_DC || c->type == CLIENT_TYPE_GC ||
       c->type == CLIENT_TYPE_EP3) {
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

/* Send a Blue Burst security packet to the given client. */
int send_bb_security(login_client_t *c, uint32_t gc, uint32_t err,
                     uint32_t team, const void *data, int data_len) {
    bb_security_pkt *pkt = (bb_security_pkt *)sendbuf;

    /* Make sure the data is sane */
    if(data_len > 40 || data_len < 0) {
        return -1;
    }

    /* Wipe the packet */
    memset(pkt, 0, sizeof(bb_security_pkt));

    /* Fill in the header */
    pkt->hdr.pkt_len = LE16(BB_SECURITY_LENGTH);
    pkt->hdr.pkt_type = LE16(BB_SECURITY_TYPE);

    /* Fill in the information */
    pkt->err_code = LE32(err);
    pkt->tag = LE32(0x00010000);
    pkt->guildcard = LE32(gc);
    pkt->team_id = LE32(team);
    pkt->caps = LE32(0x00000102);   /* ??? - newserv sets it this way */

    /* Copy over any security data */
    if(data_len)
        memcpy(pkt->security_data, data, data_len);

    /* Send the packet away */
    return crypt_send(c, BB_SECURITY_LENGTH);    
}

/* Send a redirect packet to the given client. */
static int send_redirect_bb(login_client_t *c, in_addr_t ip, uint16_t port) {
    bb_redirect_pkt *pkt = (bb_redirect_pkt *)sendbuf;

    /* Wipe the packet */
    memset(pkt, 0, BB_REDIRECT_LENGTH);

    /* Fill in the header */
    pkt->hdr.pkt_type = LE16(REDIRECT_TYPE);
    pkt->hdr.pkt_len = LE16(BB_REDIRECT_LENGTH);

    /* Fill in the IP and port */
    pkt->ip_addr = ip;
    pkt->port = LE16(port);

    /* Send the packet away */
    return crypt_send(c, BB_REDIRECT_LENGTH);
}

static int send_redirect_dc(login_client_t *c, in_addr_t ip, uint16_t port) {
    dc_redirect_pkt *pkt = (dc_redirect_pkt *)sendbuf;

    /* Wipe the packet */
    memset(pkt, 0, DC_REDIRECT_LENGTH);

    /* Fill in the header */
    if(c->type == CLIENT_TYPE_DC || c->type == CLIENT_TYPE_GC ||
       c->type == CLIENT_TYPE_EP3) {
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
        case CLIENT_TYPE_EP3:
            return send_redirect_dc(c, ip, port);

        case CLIENT_TYPE_BB_LOGIN:
        case CLIENT_TYPE_BB_CHARACTER:
            return send_redirect_bb(c, ip, port);
    }

    return -1;
}

#ifdef ENABLE_IPV6
/* Send a redirect packet (IPv6) to the given client. */
static int send_redirect6_dc(login_client_t *c, const uint8_t ip[16],
                             uint16_t port) {
    dc_redirect6_pkt *pkt = (dc_redirect6_pkt *)sendbuf;

    /* Wipe the packet */
    memset(pkt, 0, DC_REDIRECT6_LENGTH);

    /* Fill in the header */
    if(c->type == CLIENT_TYPE_DC || c->type == CLIENT_TYPE_GC ||
       c->type == CLIENT_TYPE_EP3) {
        pkt->hdr.dc.pkt_type = REDIRECT_TYPE;
        pkt->hdr.dc.pkt_len = LE16(DC_REDIRECT6_LENGTH);
        pkt->hdr.dc.flags = 6;
    }
    else {
        pkt->hdr.pc.pkt_type = REDIRECT_TYPE;
        pkt->hdr.pc.pkt_len = LE16(DC_REDIRECT6_LENGTH);
        pkt->hdr.pc.flags = 6;
    }

    /* Fill in the IP and port */
    memcpy(pkt->ip_addr, ip, 16);
    pkt->port = LE16(port);

    /* Send the packet away */
    return crypt_send(c, DC_REDIRECT6_LENGTH);
}

int send_redirect6(login_client_t *c, const uint8_t ip[16], uint16_t port) {
    /* Call the appropriate function. */
    switch(c->type) {
        case CLIENT_TYPE_DC:
        case CLIENT_TYPE_PC:
        case CLIENT_TYPE_GC:
        case CLIENT_TYPE_EP3:
            return send_redirect6_dc(c, ip, port);
    }

    return -1;
}
#endif

/* Send a packet to clients connecting on the Gamecube port to sort out any PC
   clients that might end up there. This must be sent before encryption is set
   up! */
static int send_selective_redirect_ipv4(login_client_t *c) {
    dc_redirect_pkt *pkt = (dc_redirect_pkt *)sendbuf;
    dc_pkt_hdr_t *hdr2 = (dc_pkt_hdr_t *)(sendbuf + 0x19);
    in_addr_t addr = cfg->server_ip;

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

int send_selective_redirect(login_client_t *c) {
#ifdef ENABLE_IPV6
    if(c->is_ipv6) {
        /* This is handled in the proxy for IPv6. */
        return 0;
    }
#endif

    return send_selective_redirect_ipv4(c);
}

/* Send a timestamp packet to the given client. */
static int send_timestamp_dc(login_client_t *c) {
    dc_timestamp_pkt *pkt = (dc_timestamp_pkt *)sendbuf;
    struct timeval rawtime;
    struct tm cooked;

    /* Wipe the packet */
    memset(pkt, 0, DC_TIMESTAMP_LENGTH);

    /* Fill in the header */
    if(c->type == CLIENT_TYPE_DC || c->type == CLIENT_TYPE_GC ||
       c->type == CLIENT_TYPE_EP3) {
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

static int send_timestamp_bb(login_client_t *c) {
    bb_timestamp_pkt *pkt = (bb_timestamp_pkt *)sendbuf;
    struct timeval rawtime;
    struct tm cooked;

    /* Wipe the packet */
    memset(pkt, 0, BB_TIMESTAMP_LENGTH);

    /* Fill in the header */
    pkt->hdr.pkt_type = LE16(TIMESTAMP_TYPE);
    pkt->hdr.pkt_len = LE16(BB_TIMESTAMP_LENGTH);

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
    return crypt_send(c, BB_TIMESTAMP_LENGTH);
}

int send_timestamp(login_client_t *c) {
    /* Call the appropriate function */
    switch(c->type) {
        case CLIENT_TYPE_DC:
        case CLIENT_TYPE_PC:
        case CLIENT_TYPE_GC:
        case CLIENT_TYPE_EP3:
            return send_timestamp_dc(c);

        case CLIENT_TYPE_BB_CHARACTER:
            return send_timestamp_bb(c);
    }

    return -1;
}

/* Send the initial menu to clients, with the options of "Ship Select" and
   "Download". */
static int send_initial_menu_dc(login_client_t *c) {
    dc_ship_list_pkt *pkt = (dc_ship_list_pkt *)sendbuf;
    int len = 0x58, count = 2;

    /* Clear the base packet */
    memset(pkt, 0, 0x0074);

    /* Fill in the "DATABASE/US" entry */
    pkt->entries[0].menu_id = LE32(MENU_ID_DATABASE);
    pkt->entries[0].item_id = 0;
    pkt->entries[0].flags = LE16(0x0004);
    strcpy(pkt->entries[0].name, "DATABASE/US");
    pkt->entries[0].name[0x11] = 0x08;

    /* Fill in the "Ship Select" entry */
    pkt->entries[1].menu_id = LE32(MENU_ID_INITIAL);
    pkt->entries[1].item_id = LE32(ITEM_ID_INIT_SHIP);
    pkt->entries[1].flags = LE16(0x0004);
    strcpy(pkt->entries[1].name, "Ship Select");

    /* Fill in the "Download" entry */
    pkt->entries[2].menu_id = LE32(MENU_ID_INITIAL);
    pkt->entries[2].item_id = LE32(ITEM_ID_INIT_DOWNLOAD);
    pkt->entries[2].flags = LE16(0x0F04);
    strcpy(pkt->entries[2].name, "Download");

    /* If the user is a GM, give them a bit more... */
    if(IS_GLOBAL_GM(c)) {
        pkt->entries[3].menu_id = LE32(MENU_ID_INITIAL);
        pkt->entries[3].item_id = LE32(ITEM_ID_INIT_GM);
        pkt->entries[3].flags = LE16(0x0004);
        strcpy(pkt->entries[3].name, "GM Operations");
        ++count;
        len += 0x1C;
    }

    /* Fill in some basic stuff */
    pkt->hdr.pkt_type = BLOCK_LIST_TYPE;
    pkt->hdr.flags = count;
    pkt->hdr.pkt_len = LE16(len);

    /* Send the packet away */
    return crypt_send(c, len);
}

static int send_initial_menu_pc(login_client_t *c) {
    pc_ship_list_pkt *pkt = (pc_ship_list_pkt *)sendbuf;
    int len = 0x88, count = 2;

    /* Clear the base packet */
    memset(pkt, 0, 0x00B4);

    /* Fill in the "DATABASE/US" entry */
    pkt->entries[0].menu_id = LE32(MENU_ID_DATABASE);
    pkt->entries[0].item_id = 0;
    pkt->entries[0].flags = LE16(0x0004);
    memcpy(pkt->entries[0].name, "D\0A\0T\0A\0B\0A\0S\0E\0/\0U\0S\0", 22);
    pkt->entries[0].name[0x11] = 0x08;

    /* Fill in the "Ship Select" entry */
    pkt->entries[1].menu_id = LE32(MENU_ID_INITIAL);
    pkt->entries[1].item_id = LE32(ITEM_ID_INIT_SHIP);
    pkt->entries[1].flags = LE16(0x0004);
    memcpy(pkt->entries[1].name, "S\0h\0i\0p\0 \0S\0e\0l\0e\0c\0t\0", 22);

    /* Fill in the "Download" entry */
    pkt->entries[2].menu_id = LE32(MENU_ID_INITIAL);
    pkt->entries[2].item_id = LE32(ITEM_ID_INIT_DOWNLOAD);
    pkt->entries[2].flags = LE16(0x0F04);
    memcpy(pkt->entries[2].name, "D\0o\0w\0n\0l\0o\0a\0d\0", 16);

    /* If the user is a GM, give them a bit more... */
    if(IS_GLOBAL_GM(c)) {
        pkt->entries[3].menu_id = LE32(MENU_ID_INITIAL);
        pkt->entries[3].item_id = LE32(ITEM_ID_INIT_GM);
        pkt->entries[3].flags = LE16(0x0004);
        memcpy(pkt->entries[3].name, "G\0M\0 \0O\0p\0e\0r\0a\0t\0i\0o\0n\0s\0",
               26);
        ++count;
        len += 0x2C;
    }

    /* Fill in some basic stuff */
    pkt->hdr.pkt_type = BLOCK_LIST_TYPE;
    pkt->hdr.flags = count;
    pkt->hdr.pkt_len = LE16(len);

    /* Send the packet away */
    return crypt_send(c, len);
}

static int send_initial_menu_gc(login_client_t *c) {
    dc_ship_list_pkt *pkt = (dc_ship_list_pkt *)sendbuf;
    int count = 3, len = 0x74;
    
    /* Clear the base packet */
    memset(pkt, 0, 0x0090);
    
    /* Fill in the "DATABASE/US" entry */
    pkt->entries[0].menu_id = LE32(MENU_ID_DATABASE);
    pkt->entries[0].item_id = 0;
    pkt->entries[0].flags = LE16(0x0004);
    strcpy(pkt->entries[0].name, "DATABASE/US");
    pkt->entries[0].name[0x11] = 0x08;
    
    /* Fill in the "Ship Select" entry */
    pkt->entries[1].menu_id = LE32(MENU_ID_INITIAL);
    pkt->entries[1].item_id = LE32(ITEM_ID_INIT_SHIP);
    pkt->entries[1].flags = LE16(0x0004);
    strcpy(pkt->entries[1].name, "Ship Select");
    
    /* Fill in the "Download" entry */
    pkt->entries[2].menu_id = LE32(MENU_ID_INITIAL);
    pkt->entries[2].item_id = LE32(ITEM_ID_INIT_DOWNLOAD);
    pkt->entries[2].flags = LE16(0x0F04);
    strcpy(pkt->entries[2].name, "Download");

    /* Fill in the "Information" entry */
    pkt->entries[3].menu_id = LE32(MENU_ID_INITIAL);
    pkt->entries[3].item_id = LE32(ITEM_ID_INIT_INFO);
    pkt->entries[3].flags = LE16(0x0004);
    strcpy(pkt->entries[3].name, "Information");

    /* If the user is a GM, give them a bit more... */
    if(IS_GLOBAL_GM(c)) {
        pkt->entries[4].menu_id = LE32(MENU_ID_INITIAL);
        pkt->entries[4].item_id = LE32(ITEM_ID_INIT_GM);
        pkt->entries[4].flags = LE16(0x0004);
        strcpy(pkt->entries[4].name, "GM Operations");
        ++count;
        len += 0x1C;
    }

    /* Fill in some basic stuff */
    pkt->hdr.pkt_type = BLOCK_LIST_TYPE;
    pkt->hdr.flags = count;
    pkt->hdr.pkt_len = LE16(len);
    
    /* Send the packet away */
    return crypt_send(c, len);
}

int send_initial_menu(login_client_t *c) {
    /* Call the appropriate function */
    switch(c->type) {
        case CLIENT_TYPE_DC:
            return send_initial_menu_dc(c);

        case CLIENT_TYPE_PC:
            return send_initial_menu_pc(c);

        case CLIENT_TYPE_GC:
        case CLIENT_TYPE_EP3:
            return send_initial_menu_gc(c);
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
    int i, len = 0x20, gm_only, flags, ship_num;
    char tmp[3] = { menu_code, menu_code >> 8, 0 };

    /* Clear the base packet */
    memset(pkt, 0, sizeof(dc_ship_list_pkt));

    /* Fill in some basic stuff */
    pkt->hdr.pkt_type = BLOCK_LIST_TYPE;

    /* Fill in the "SHIP/cc" entry */
    memset(&pkt->entries[0], 0, 0x1C);
    pkt->entries[0].menu_id = LE32(0x00040000);
    pkt->entries[0].item_id = 0;
    pkt->entries[0].flags = LE16(0x0004);

    if(menu_code) {
        sprintf(pkt->entries[0].name, "SHIP/%c%c", (char)menu_code,
                (char)(menu_code >> 8));
    }
    else {
        strcpy(pkt->entries[0].name, "SHIP/US");
    }

    pkt->entries[0].name[0x11] = 0x08;
    num_ships = 1;

    /* Figure out what ships we might exclude by flags */
    if(c->type == CLIENT_TYPE_GC) {
        flags = 0x80;
    }
    else if(c->type == CLIENT_TYPE_EP3) {
        flags = 0x100;
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
    sprintf(query, "SELECT ship_id, name, players, gm_only, ship_number FROM "
            "online_ships WHERE menu_code='%hu' AND (flags & 0x%02x) = 0 ORDER "
            "BY ship_number", menu_code, flags);

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

        if(!gm_only || IS_GLOBAL_GM(c)) {
            /* Clear out the ship information */
            memset(&pkt->entries[num_ships], 0, 0x1C);

            /* Grab info from the row */
            ship_id = (uint32_t)strtoul(row[0], NULL, 0);
            players = (uint32_t)strtoul(row[2], NULL, 0);
            ship_num = atoi(row[4]);

            /* Fill in what we have */
            pkt->entries[num_ships].menu_id = LE32(0x00000001);
            pkt->entries[num_ships].item_id = LE32(ship_id);
            pkt->entries[num_ships].flags = LE16(0x0F04);

            /* Create the name string */
            if(menu_code) {
                sprintf(pkt->entries[num_ships].name, "%02X:%c%c/%s", ship_num,
                        (char)menu_code, (char)(menu_code >> 8), row[1]);
            }
            else {
                sprintf(pkt->entries[num_ships].name, "%02X:%s", ship_num,
                        row[1]);
            }

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
        pkt->entries[num_ships].flags = LE16(0x0F04);

        /* Create the name string */
        if(tmp[0] && tmp[1]) {
            sprintf(pkt->entries[num_ships].name, "SHIP/%s", tmp);
        }
        else {
            strcpy(pkt->entries[num_ships].name, "SHIP/Main");
        }

        /* We're done with this ship, increment the counter */
        ++num_ships;
        len += 0x1C;
    }

    sylverant_db_result_free(result);

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
    int i, len = 0x30, gm_only, ship_num;
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

    /* Fill in the "SHIP/cc" entry */
    memset(&pkt->entries[0], 0, 0x2C);
    pkt->entries[0].menu_id = LE32(0x00040000);
    pkt->entries[0].item_id = 0;
    pkt->entries[0].flags = LE16(0x0004);
    memcpy(pkt->entries[0].name, "S\0H\0I\0P\0/\0U\0S\0", 14);

    if(menu_code) {
        pkt->entries[0].name[5] = LE16((menu_code & 0x00FF));
        pkt->entries[0].name[6] = LE16((menu_code >> 8));
    }

    num_ships = 1;

    /* Get ready to query the database */
    sprintf(query, "SELECT ship_id, name, players, gm_only, ship_number FROM "
            "online_ships WHERE menu_code='%hu' AND (flags & 0x40) = 0 ORDER "
            "BY ship_number", menu_code);

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

        if(!gm_only || IS_GLOBAL_GM(c)) {
            /* Clear out the ship information */
            memset(&pkt->entries[num_ships], 0, 0x2C);

            /* Grab info from the row */
            ship_id = (uint32_t)strtoul(row[0], NULL, 0);
            players = (uint32_t)strtoul(row[2], NULL, 0);
            ship_num = atoi(row[4]);

            /* Fill in what we have */
            pkt->entries[num_ships].menu_id = LE32(0x00000001);
            pkt->entries[num_ships].item_id = LE32(ship_id);
            pkt->entries[num_ships].flags = LE16(0x0F04);

            /* Create the name string (UTF-8) */
            if(menu_code) {
                sprintf(tmp, "%02X:%c%c/%s", ship_num, (char)menu_code,
                        (char)(menu_code >> 8), row[1]);
            }
            else {
                sprintf(tmp, "%02X:%s", ship_num, row[1]);
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
        pkt->entries[num_ships].flags = LE16(0x0F04);

        /* Create the name string (UTF-8) */
        if(tmp2[0] && tmp2[1]) {
            sprintf(tmp, "SHIP/%s", tmp2);
        }
        else {
            strcpy(tmp, "SHIP/Main");
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

static int send_ship_list_bb(login_client_t *c, uint16_t menu_code) {
    bb_ship_list_pkt *pkt = (bb_ship_list_pkt *)sendbuf;
    char no_ship_msg[] = "No Ships";
    char query[256], tmp[18], tmp2[3];
    uint32_t num_ships = 0;
    void *result;
    char **row;
    uint32_t ship_id, players;
    int i, len = 0x34, gm_only, ship_num;
    iconv_t ic = iconv_open("UTF-16LE", "UTF-8");
    size_t in, out;
    ICONV_CONST char *inptr;
    char *outptr;

    if(ic == (iconv_t)-1) {
        perror("iconv_open");
        return -1;
    }

    /* Clear the base packet */
    memset(pkt, 0, sizeof(bb_ship_list_pkt));

    /* Fill in some basic stuff */
    pkt->hdr.pkt_type = BLOCK_LIST_TYPE;

    /* Fill in the "SHIP/cc" entry */
    memset(&pkt->entries[0], 0, 0x2C);
    pkt->entries[0].menu_id = LE32(0x00040000);
    pkt->entries[0].item_id = 0;
    pkt->entries[0].flags = LE16(0x0004);
    memcpy(pkt->entries[0].name, "S\0H\0I\0P\0/\0U\0S\0", 14);

    if(menu_code) {
        pkt->entries[0].name[5] = LE16((menu_code & 0x00FF));
        pkt->entries[0].name[6] = LE16((menu_code >> 8));
    }

    num_ships = 1;

    /* Get ready to query the database */
    sprintf(query, "SELECT ship_id, name, players, gm_only, ship_number FROM "
            "online_ships WHERE menu_code='%hu' AND (flags & 0x200) = 0 ORDER "
            "BY ship_number", menu_code);

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

        if(!gm_only || IS_GLOBAL_GM(c)) {
            /* Clear out the ship information */
            memset(&pkt->entries[num_ships], 0, 0x2C);

            /* Grab info from the row */
            ship_id = (uint32_t)strtoul(row[0], NULL, 0);
            players = (uint32_t)strtoul(row[2], NULL, 0);
            ship_num = atoi(row[4]);

            /* Fill in what we have */
            pkt->entries[num_ships].menu_id = LE32(0x00000001);
            pkt->entries[num_ships].item_id = LE32(ship_id);
            pkt->entries[num_ships].flags = LE16(0x0F04);

            /* Create the name string (UTF-8) */
            if(menu_code) {
                sprintf(tmp, "%02X:%c%c/%s", ship_num, (char)menu_code,
                        (char)(menu_code >> 8), row[1]);
            }
            else {
                sprintf(tmp, "%02X:%s", ship_num, row[1]);
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
        pkt->entries[num_ships].flags = LE16(0x0F04);

        /* Create the name string (UTF-8) */
        if(tmp2[0] && tmp2[1]) {
            sprintf(tmp, "SHIP/%s", tmp2);
        }
        else {
            strcpy(tmp, "SHIP/Main");
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
    pkt->hdr.flags = LE32((num_ships - 1));

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
        case CLIENT_TYPE_EP3:
            return send_ship_list_dc(c, menu_code);

        case CLIENT_TYPE_PC:
            return send_ship_list_pc(c, menu_code);

        case CLIENT_TYPE_BB_CHARACTER:
            return send_ship_list_bb(c, menu_code);
    }

    return -1;
}

static int send_info_reply_dc(login_client_t *c, const char msg[]) {
    dc_info_reply_pkt *pkt = (dc_info_reply_pkt *)sendbuf;
    iconv_t ic;
    size_t in, out;
    ICONV_CONST char *inptr;
    char *outptr;

    if(c->type == CLIENT_TYPE_DC || c->type == CLIENT_TYPE_GC ||
       c->type == CLIENT_TYPE_EP3) {
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
    in = strlen(msg) + 1;
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
    if(c->type == CLIENT_TYPE_DC || c->type == CLIENT_TYPE_GC ||
       c->type == CLIENT_TYPE_EP3) {
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

static int send_info_reply_bb(login_client_t *c, const char msg[],
                              uint16_t type) {
    bb_info_reply_pkt *pkt = (bb_info_reply_pkt *)sendbuf;
    iconv_t ic;
    size_t in, out;
    ICONV_CONST char *inptr;
    char *outptr;

    ic = iconv_open("UTF-16LE", "UTF-8");

    if(ic == (iconv_t)-1) {
        perror("iconv_open");
        return -1;
    }

    /* Convert the message to the appropriate encoding. */
    in = strlen(msg) + 1;
    out = 65520;
    inptr = (ICONV_CONST char *)msg;
    outptr = (char *)pkt->msg;
    iconv(ic, &inptr, &in, &outptr, &out);
    iconv_close(ic);

    /* Figure out how long the packet is. */
    out = 65520 - out + 16;

    pkt->unused[0] = 0;
    pkt->unused[1] = 0;

    /* Pad to a length that's at divisible by 4. */
    while(out & 0x03) {
        sendbuf[out++] = 0;
    }

    /* Fill in the header */
    pkt->hdr.pkt_type = LE16(type);
    pkt->hdr.flags = 0;
    pkt->hdr.pkt_len = LE16(out);

    /* Send the packet away */
    return crypt_send(c, out);
}

int send_info_reply(login_client_t *c, const char msg[]) {
    /* Call the appropriate function. */
    switch(c->type) {
        case CLIENT_TYPE_DC:
        case CLIENT_TYPE_PC:
        case CLIENT_TYPE_GC:
        case CLIENT_TYPE_EP3:
            return send_info_reply_dc(c, msg);

        case CLIENT_TYPE_BB_CHARACTER:
            return send_info_reply_bb(c, msg, INFO_REPLY_TYPE);
    }

    return -1;
}

/* Send a Blue Burst style scrolling message to the client */
int send_scroll_msg(login_client_t *c, const char msg[]) {
    /* Call the appropriate function. */
    switch(c->type) {
        case CLIENT_TYPE_BB_LOGIN:
        case CLIENT_TYPE_BB_CHARACTER:
            return send_info_reply_bb(c, msg, BB_SCROLL_MSG_TYPE);
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
        case CLIENT_TYPE_EP3:
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
        case CLIENT_TYPE_EP3:
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
    sprintf(filename, "%s/%s-%s/%s.qst", cfg->quests_dir, type_codes[c->type],
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

/* Send an Episode 3 rank update to a client. */
int send_ep3_rank_update(login_client_t *c) {
    ep3_rank_update_pkt *pkt = (ep3_rank_update_pkt *)sendbuf;

    /* XXXX: Need to actually do something with this in the future */
    memset(pkt, 0, sizeof(ep3_rank_update_pkt));
    pkt->hdr.pkt_type = EP3_RANK_UPDATE_TYPE;
    pkt->hdr.pkt_len = LE16(0x0020);
    pkt->meseta = LE32(0x00FFFFFF);
    pkt->max_meseta = LE32(0x00FFFFFF);
    pkt->jukebox = LE32(0xFFFFFFFF);

    return crypt_send(c, 0x0020);
}

/* Send the Episode 3 card list to a client. */
int send_ep3_card_update(login_client_t *c) {
    ep3_card_update_pkt *pkt = (ep3_card_update_pkt *)sendbuf;
    FILE *fp;
    long size;
    uint16_t pkt_len;

    /* Make sure we're actually dealing with Episode 3 */
    if(c->type != CLIENT_TYPE_EP3) {
        return -1;
    }

    /* Grab the card list */
    fp = fopen("ep3/cardupdate.mnr", "rb");
    if(!fp) {
        return -1;
    }

    /* Figure out how big the file is */
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    /* Make sure the size is sane... */
    if(size > 0x8000) {
        return -1;
    }

    /* Not sure why this size is used, but for now we'll go with it (borrowed
       from Fuzziqer's newserv) */
    pkt_len = (13 + size) & 0xFFFC;

    /* Fill in the packet */
    pkt->hdr.pkt_len = LE16(pkt_len);
    pkt->hdr.pkt_type = EP3_CARD_UPDATE_TYPE;
    pkt->hdr.flags = 0;
    pkt->size = LE32(size);
    fread(pkt->data, 1, size, fp);

    /* Send it away */
    return crypt_send(c, pkt_len);
}

/* Send a Blue Burst option reply to the client. */
int send_bb_option_reply(login_client_t *c, const uint8_t keys[420]) {
    bb_opt_config_pkt *pkt = (bb_opt_config_pkt *)sendbuf;

    /* Clear it out first */
    memset(pkt, 0, sizeof(bb_opt_config_pkt));

    /* Fill in the header */
    pkt->hdr.pkt_len = LE16(sizeof(bb_opt_config_pkt));
    pkt->hdr.pkt_type = LE16(BB_OPTION_CONFIG_TYPE);

    /* Copy in the key/joystick data */
    memcpy(pkt->data.key_config, keys, 420);

    /* Set all the rewards... */
    pkt->data.team_rewards[0] = 0xFFFFFFFF;
    pkt->data.team_rewards[1] = 0xFFFFFFFF;

    /* XXXX: Handle the rest sometime... */
    /* Send the packet away */
    return crypt_send(c, sizeof(bb_opt_config_pkt));
}

/* Send a Blue Burst character acknowledgement to the client. */
int send_bb_char_ack(login_client_t *c, uint8_t slot, uint8_t code) {
    bb_char_ack_pkt *pkt = (bb_char_ack_pkt *)sendbuf;

    /* Clear it out first */
    memset(pkt, 0, sizeof(bb_char_ack_pkt));

    /* Fill in the packet */
    pkt->hdr.pkt_len = LE16(sizeof(bb_char_ack_pkt));
    pkt->hdr.pkt_type = LE16(BB_CHARACTER_ACK_TYPE);
    pkt->slot = slot;
    pkt->code = code;

    /* Send it away */
    return crypt_send(c, sizeof(bb_char_ack_pkt));
}

/* Send a Blue Burst checksum acknowledgement to the client. */
int send_bb_checksum_ack(login_client_t *c, uint32_t ack) {
    bb_checksum_ack_pkt *pkt = (bb_checksum_ack_pkt *)sendbuf;

    /* Clear it out first */
    memset(pkt, 0, sizeof(bb_checksum_ack_pkt));

    /* Fill it in */
    pkt->hdr.pkt_len = LE16(sizeof(bb_checksum_ack_pkt));
    pkt->hdr.pkt_type = LE16(BB_CHECKSUM_ACK_TYPE);
    pkt->ack = LE32(ack);

    /* Send it away */
    return crypt_send(c, sizeof(bb_checksum_ack_pkt));
}

/* Send a Blue Burst guildcard header packet. */
int send_bb_guild_header(login_client_t *c, uint32_t checksum) {
    bb_guildcard_hdr_pkt *pkt = (bb_guildcard_hdr_pkt *)sendbuf;

    /* Clear it out first */
    memset(pkt, 0, sizeof(bb_guildcard_hdr_pkt));

    /* Fill it in */
    pkt->hdr.pkt_len = LE16(sizeof(bb_guildcard_hdr_pkt));
    pkt->hdr.pkt_type = LE16(BB_GUILDCARD_HEADER_TYPE);
    pkt->one = 1;
    pkt->len = LE16(sizeof(bb_gc_data_t));
    pkt->checksum = LE32(checksum);

    /* Send it away */
    return crypt_send(c, sizeof(bb_guildcard_hdr_pkt));
}

/* Send a Blue Burst guildcard chunk packet. */
int send_bb_guild_chunk(login_client_t *c, uint32_t chunk) {
    bb_guildcard_chunk_pkt *pkt = (bb_guildcard_chunk_pkt *)sendbuf;
    uint32_t offset = (chunk * 0x6800);
    uint16_t size = sizeof(bb_gc_data_t) - offset;
    uint8_t *ptr = ((uint8_t *)c->gc_data) + offset;

    /* Sanity check... */
    if(offset > sizeof(bb_gc_data_t)) {
        return -1;
    }

    /* Don't send a chunk bigger than PSO wants */
    if(size > 0x6800) {
        size = 0x6800;
    }

    /* Clear it out first */
    memset(pkt, 0, size + 0x10);

    /* Fill it in */
    pkt->hdr.pkt_len = LE16((size + 0x10));
    pkt->hdr.pkt_type = LE16(BB_GUILDCARD_CHUNK_TYPE);
    pkt->chunk = LE32(chunk);
    memcpy(pkt->data, ptr, size);

    /* Send it away */
    return crypt_send(c, size + 0x10);
}

/* Send a prepared Blue Burst packet. */
int send_bb_pkt(login_client_t *c, bb_pkt_hdr_t *hdr) {
    uint16_t len = LE16(hdr->pkt_len);

    /* Copy it into our buffer */
    memcpy(sendbuf, hdr, len);

    /* Send it away */
    return crypt_send(c, len);
}

/* Send a Blue Burst character preview packet. */
int send_bb_char_preview(login_client_t *c, const sylverant_bb_mini_char_t *mc,
                         uint8_t slot) {
    bb_char_preview_pkt *pkt = (bb_char_preview_pkt *)sendbuf;

    /* Fill in the header */
    pkt->hdr.pkt_type = LE16(BB_CHARACTER_UPDATE_TYPE);
    pkt->hdr.pkt_len = LE16(sizeof(bb_char_preview_pkt));
    pkt->hdr.flags = 0;

    pkt->slot = slot;
    pkt->unused[0] = pkt->unused[1] = pkt->unused[2] = 0;

    /* Copy in the character data */
    memcpy(&pkt->data, mc, sizeof(sylverant_bb_mini_char_t));
    
    return crypt_send(c, sizeof(bb_char_preview_pkt));
}

/* Send the content of the "Information" menu. */
static int send_gc_info_list(login_client_t *c, uint32_t ver) {
    dc_block_list_pkt *pkt = (dc_block_list_pkt *)sendbuf;
    int i, len = 0x20, entries = 1;
    uint32_t lang = (1 << c->language_code);

    /* Clear the base packet */
    memset(pkt, 0, sizeof(dc_block_list_pkt));

    /* Fill in some basic stuff */
    pkt->hdr.pkt_type = BLOCK_LIST_TYPE;

    /* Fill in the DATABASE entry */
    memset(&pkt->entries[0], 0, 0x1C);
    pkt->entries[0].menu_id = LE32(MENU_ID_DATABASE);
    pkt->entries[0].item_id = 0;
    pkt->entries[0].flags = LE16(0x0004);
    strcpy(pkt->entries[0].name, "DATABASE/US");
    pkt->entries[0].name[0x11] = 0x08;

    /* Add each info item to the list. */
    for(i = 0; i < cfg->info_file_count; ++i) {
        /* See if we should look at this entry. */
        if(!(cfg->info_files[i].versions & ver)) {
            continue;
        }

        if(!(cfg->info_files[i].languages & lang)) {
            continue;
        }

        /* Skip MOTD entries. */
        if(!(cfg->info_files[i].desc)) {
            continue;
        }

        /* Clear out the info file information */
        memset(&pkt->entries[entries], 0, 0x1C);

        /* Fill in what we have */
        pkt->entries[entries].menu_id = LE32(MENU_ID_INFODESK);
        pkt->entries[entries].item_id = LE32(i);
        pkt->entries[entries].flags = LE16(0x0000);

        /* These are always ASCII, so this is fine */
        strncpy(pkt->entries[entries].name, cfg->info_files[i].desc, 0x11);
        pkt->entries[entries].name[0x11] = 0;

        len += 0x1C;
        ++entries;
    }

    /* Add the entry to return to the initial menu. */
    memset(&pkt->entries[entries], 0, 0x1C);

    pkt->entries[entries].menu_id = LE32(MENU_ID_INFODESK);
    pkt->entries[entries].item_id = LE32(0xFFFFFFFF);
    pkt->entries[entries].flags = LE16(0x0000);

    strcpy(pkt->entries[entries].name, "Main Menu");
    len += 0x1C;

    /* Fill in the rest of the header */
    pkt->hdr.pkt_len = LE16(len);
    pkt->hdr.flags = (uint8_t)(entries);

    /* Send the packet away */
    return crypt_send(c, len);
}

int send_info_list(login_client_t *c) {
    /* Call the appropriate function */
    switch(c->type) {
        case CLIENT_TYPE_GC:
            return send_gc_info_list(c, SYLVERANT_INFO_GC);

        case CLIENT_TYPE_EP3:
            return send_gc_info_list(c, SYLVERANT_INFO_EP3);
    }

    return -1;
}

/* Send a message to the client. */
static int send_gc_message_box(login_client_t *c, const char *fmt,
                               va_list args) {
    dc_msg_box_pkt *pkt = (dc_msg_box_pkt *)sendbuf;
    int len;

    /* Do the formatting */
    vsnprintf(pkt->msg, 1024, fmt, args);
    pkt->msg[1024] = '\0';
    len = strlen(pkt->msg) + 1;

    /* Make sure we have a language code tag */
    if(pkt->msg[0] != '\t' || (pkt->msg[1] != 'E' && pkt->msg[1] != 'J')) {
        /* Assume Non-Japanese if we don't have a marker. */
        memmove(&pkt->msg[2], &pkt->msg[0], len);
        pkt->msg[0] = '\t';
        pkt->msg[1] = 'E';
        len += 2;
    }

    /* Add any padding needed */
    while(len & 0x03) {
        pkt->msg[len++] = 0;
    }

    /* Fill in the header */
    len += 0x04;

    pkt->hdr.dc.pkt_type = GC_MSG_BOX_TYPE;
    pkt->hdr.dc.flags = 0;
    pkt->hdr.dc.pkt_len = LE16(len);

    /* Send it away */
    return crypt_send(c, len);
}

int send_message_box(login_client_t *c, const char *fmt, ...) {
    va_list args;
    int rv = -1;

    va_start(args, fmt);

    /* Call the appropriate function. */
    switch(c->type) {
        case CLIENT_TYPE_GC:
        case CLIENT_TYPE_EP3:
            rv = send_gc_message_box(c, fmt, args);
    }

    va_end(args);

    return rv;
}

/* Send a message box containing an information file entry. */
int send_info_file(login_client_t *c, uint32_t entry) {
    FILE *fp;
    char buf[1024];
    long len;

    /* The item_id should be the information the client wants. */
    if(entry >= cfg->info_file_count) {
        send_message_box(c, "%s\n%s",
                         __(c, "\tE\tC4Something went wrong!"),
                         __(c, "\tC7The information requested is missing."));
        return 0;
    }

    /* Attempt to open the file */
    fp = fopen(cfg->info_files[entry].filename, "r");

    if(!fp) {
        send_message_box(c, "%s\n%s",
                         __(c, "\tE\tC4Something went wrong!"),
                         __(c, "\tC7The information requested is missing."));
        return 0;
    }

    /* Figure out the length of the file. */
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    /* Truncate to about 1KB */
    if(len > 1023) {
        len = 1023;
    }

    /* Read the file in. */
    fread(buf, 1, len, fp);
    fclose(fp);
    buf[len] = 0;

    /* Send the message to the client. */
    return send_message_box(c, "%s", buf);
}

/* Send the GM operations menu to the user. */
static int send_gm_menu_dc(login_client_t *c) {
    dc_ship_list_pkt *pkt = (dc_ship_list_pkt *)sendbuf;
    int len = 0x04, count = 0;

    /* Fill in the "DATABASE/US" entry */
    pkt->entries[count].menu_id = LE32(MENU_ID_DATABASE);
    pkt->entries[count].item_id = 0;
    pkt->entries[count].flags = LE16(0x0004);
    strncpy(pkt->entries[count].name, "DATABASE/US", 0x12);
    pkt->entries[count].name[0x11] = 0x08;
    ++count;
    len += 0x1C;

    /* Add our entries... */
    pkt->entries[count].menu_id = LE32(MENU_ID_GM);
    pkt->entries[count].item_id = LE32(ITEM_ID_GM_REFRESH_Q);
    pkt->entries[count].flags = LE16(0x0004);
    strncpy(pkt->entries[count].name, "Refresh Quests", 0x12);
    ++count;
    len += 0x1C;

    if(IS_GLOBAL_ROOT(c)) {
        pkt->entries[count].menu_id = LE32(MENU_ID_GM);
        pkt->entries[count].item_id = LE32(ITEM_ID_GM_RESTART);
        pkt->entries[count].flags = LE16(0x0004);
        strncpy(pkt->entries[count].name, "Restart", 0x12);
        ++count;
        len += 0x1C;

        pkt->entries[count].menu_id = LE32(MENU_ID_GM);
        pkt->entries[count].item_id = LE32(ITEM_ID_GM_SHUTDOWN);
        pkt->entries[count].flags = LE16(0x0004);
        strncpy(pkt->entries[count].name, "Shutdown", 0x12);
        ++count;
        len += 0x1C;
    }

    pkt->entries[count].menu_id = LE32(MENU_ID_GM);
    pkt->entries[count].item_id = LE32(0xFFFFFFFF);
    pkt->entries[count].flags = LE16(0x0004);
    strncpy(pkt->entries[count].name, "Main Menu", 0x12);
    ++count;
    len += 0x1C;

    /* Fill in some basic stuff */
    pkt->hdr.pkt_type = BLOCK_LIST_TYPE;
    pkt->hdr.flags = (uint8_t)(count - 1);
    pkt->hdr.pkt_len = LE16(len);

    /* Send the packet away */
    return crypt_send(c, len);
}

static int send_gm_menu_pc(login_client_t *c) {
    pc_ship_list_pkt *pkt = (pc_ship_list_pkt *)sendbuf;
    int len = 0x04, count = 0;

    /* Fill in the "DATABASE/US" entry */
    pkt->entries[count].menu_id = LE32(MENU_ID_DATABASE);
    pkt->entries[count].item_id = 0;
    pkt->entries[count].flags = LE16(0x0004);
    ascii_to_utf16("DATABASE/US", pkt->entries[count].name, 0x11);
    pkt->entries[count].name[0x11] = 0x08;
    ++count;
    len += 0x2C;

    /* Add our entries... */
    pkt->entries[count].menu_id = LE32(MENU_ID_GM);
    pkt->entries[count].item_id = LE32(ITEM_ID_GM_REFRESH_Q);
    pkt->entries[count].flags = LE16(0x0004);
    ascii_to_utf16("Refresh Quests", pkt->entries[count].name, 0x11);
    ++count;
    len += 0x2C;

    if(IS_GLOBAL_ROOT(c)) {
        pkt->entries[count].menu_id = LE32(MENU_ID_GM);
        pkt->entries[count].item_id = LE32(ITEM_ID_GM_RESTART);
        pkt->entries[count].flags = LE16(0x0004);
        ascii_to_utf16("Restart", pkt->entries[count].name, 0x11);
        ++count;
        len += 0x2C;
        
        pkt->entries[count].menu_id = LE32(MENU_ID_GM);
        pkt->entries[count].item_id = LE32(ITEM_ID_GM_SHUTDOWN);
        pkt->entries[count].flags = LE16(0x0004);
        ascii_to_utf16("Shutdown", pkt->entries[count].name, 0x11);
        ++count;
        len += 0x2C;
    }

    pkt->entries[count].menu_id = LE32(MENU_ID_GM);
    pkt->entries[count].item_id = LE32(0xFFFFFFFF);
    pkt->entries[count].flags = LE16(0x0F04);
    ascii_to_utf16("Main Menu", pkt->entries[count].name, 0x11);
    ++count;
    len += 0x2C;

    /* Fill in some basic stuff */
    pkt->hdr.pkt_type = BLOCK_LIST_TYPE;
    pkt->hdr.flags = (uint8_t)(count  - 1);
    pkt->hdr.pkt_len = LE16(len);

    /* Send the packet away */
    return crypt_send(c, len);
}

int send_gm_menu(login_client_t *c) {
    /* Make sure the user is actually a GM... */
    if(!IS_GLOBAL_GM(c)) {
        return -1;
    }

    /* Call the appropriate function */
    switch(c->type) {
        case CLIENT_TYPE_DC:
        case CLIENT_TYPE_GC:
        case CLIENT_TYPE_EP3:
            return send_gm_menu_dc(c);

        case CLIENT_TYPE_PC:
            return send_gm_menu_pc(c);
    }

    return -1;
}

/* Send the message of the day to the given client. */
int send_motd(login_client_t *c) {
    FILE *fp;
    char buf[1024];
    long len;
    uint32_t lang = (1 << c->language_code), ver;
    int i, found = 0;
    sylverant_info_file_t *f;

    switch(c->type) {
        case CLIENT_TYPE_GC:
            ver = SYLVERANT_INFO_GC;
            break;

        case CLIENT_TYPE_EP3:
            ver = SYLVERANT_INFO_EP3;
            break;

        case CLIENT_TYPE_BB_LOGIN:
        case CLIENT_TYPE_BB_CHARACTER:
            ver = SYLVERANT_INFO_BB;
            break;

        default:
            return 1;
    }

    for(i = 0; i < cfg->info_file_count && !found; ++i) {
        f = &cfg->info_files[i];

        if(!f->desc && (f->versions & ver) && (f->languages & lang)) {
            found = 1;
        }
    }

    /* No MOTD found for the given version/language combination. */
    if(!found) {
        return 1;
    }

    /* Attempt to open the file */
    fp = fopen(f->filename, "r");

    /* Can't find the file? Punt. */
    if(!fp) {
        return 1;
    }

    /* Figure out the length of the file. */
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    /* Truncate to about 1KB */
    if(len > 1023) {
        len = 1023;
    }

    /* Read the file in. */
    fread(buf, 1, len, fp);
    fclose(fp);
    buf[len] = 0;

    /* Send the message to the client. */
    return send_message_box(c, "%s", buf);
}
