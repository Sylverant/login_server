/*
    Sylverant Login Server
    Copyright (C) 2009, 2010 Lawrence Sebald

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

#ifndef LOGIN_H
#define LOGIN_H

#include <sys/queue.h>
#include <netinet/in.h>

#include <sylverant/config.h>
#include <sylverant/encryption.h>
#include <sylverant/database.h>

/* Determine if a client is in our LAN */
#define IN_NET(c, s, n) ((c & n) == (s & n))

#define PACKETS_H_HEADERS_ONLY
#include "packets.h"
#undef PACKETS_H_HEADERS_ONLY

/* Login server client structure. */
typedef struct login_client {
    TAILQ_ENTRY(login_client) qentry;
    
    int type;
    int sock;
    int disconnected;
    int hdr_size;

    in_addr_t ip_addr;
    uint32_t guildcard;
    int language_code;
    int is_gm;

    uint32_t client_key;
    uint32_t server_key;
    int got_first;
    int version;

    CRYPT_SETUP client_cipher;
    CRYPT_SETUP server_cipher;
    
    unsigned char *recvbuf;
    int recvbuf_cur;
    int recvbuf_size;
    pkt_header_t pkt;

    unsigned char *sendbuf;
    int sendbuf_cur;
    int sendbuf_size;
    int sendbuf_start;

    uint8_t *gc_data;
    int dressflag;
    int hdr_read;
} login_client_t;

/* Values for the type of the login_client_t */
#define CLIENT_TYPE_DC              0
#define CLIENT_TYPE_PC              1
#define CLIENT_TYPE_GC              2

#define CLIENT_TYPE_COUNT           3

/* The list of type codes for the quest directories. */
static const char type_codes[][3] __attribute__((unused)) = {
    "dc", "pc", "gc"
};

/* These are not supported at the moment, but here to make it so that the code
   that was written for them still works. */
#define CLIENT_TYPE_BB_LOGIN        0xFE
#define CLIENT_TYPE_BB_CHARACTER    0xFF

/* Language codes. */
#define CLIENT_LANG_JAPANESE        0
#define CLIENT_LANG_ENGLISH         1
#define CLIENT_LANG_GERMAN          2
#define CLIENT_LANG_FRENCH          3
#define CLIENT_LANG_SPANISH         4
#define CLIENT_LANG_CHINESE_SIMP    5
#define CLIENT_LANG_CHINESE_TRAD    6
#define CLIENT_LANG_KOREAN          7

#define CLIENT_LANG_COUNT           8

/* The list of language codes for the quest directories. */
static const char language_codes[][3] __attribute__((unused)) = {
    "jp", "en", "de", "fr", "sp", "cs", "ct", "kr"
};

TAILQ_HEAD(client_queue, login_client);
extern struct client_queue clients;

extern sylverant_dbconn_t conn;
extern sylverant_config_t cfg;

login_client_t *create_connection(int sock, in_addr_t ip, int type);
void destroy_connection(login_client_t *c);

int process_dclogin_packet(login_client_t *c, void *pkt);

int read_from_client(login_client_t *c);

void disconnect_from_ships(uint32_t gcn);

/* In dclogin.c */
void init_i18n(void);
void cleanup_i18n(void);

#endif /* !LOGIN_H */
