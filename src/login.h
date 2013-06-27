/*
    Sylverant Login Server
    Copyright (C) 2009, 2010, 2011, 2012, 2013 Lawrence Sebald

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

#ifndef LOGIN_H
#define LOGIN_H

#include <sys/queue.h>
#include <netinet/in.h>

#include <sylverant/config.h>
#include <sylverant/encryption.h>
#include <sylverant/database.h>

#include "player.h"

/* Determine if a client is in our LAN */
#define IN_NET(c, s, n) ((c & n) == (s & n))

#define PACKETS_H_HEADERS_ONLY
#include "packets.h"
#undef PACKETS_H_HEADERS_ONLY

#ifdef PACKED
#undef PACKED
#endif

#define PACKED __attribute__((packed))

/* Data that is set on the client via the 0xE6 packet */
typedef struct bb_security_data {
    uint32_t magic;                     /* Must be 0xDEADBEEF */
    uint8_t slot;                       /* Selected character */
    uint8_t sel_char;                   /* Have they selected a character? */
    uint8_t reserved[34];               /* Set to 0 */
} PACKED bb_security_data_t;

/* Level-up information table from PlyLevelTbl.prs */
typedef struct bb_level_table {
    struct {
        uint16_t atp;
        uint16_t mst;
        uint16_t evp;
        uint16_t hp;
        uint16_t dfp;
        uint16_t ata;
        uint16_t lck;
    } start_stats[12];
    uint32_t unk[12];
    struct {
        uint8_t atp;
        uint8_t mst;
        uint8_t evp;
        uint8_t hp;
        uint8_t dfp;
        uint8_t ata;
        uint8_t unk[2];
        uint32_t exp;
    } levels[12][200];
} PACKED bb_level_table_t;

#undef PACKED

/* Login server client structure. */
typedef struct login_client {
    TAILQ_ENTRY(login_client) qentry;
    
    int type;
    int sock;
    int disconnected;
    int is_ipv6;
    int motd_wait;

    struct sockaddr_storage ip_addr;

    uint32_t guildcard;
    uint32_t account_id;
    uint32_t team_id;
    uint32_t flags;

    int language_code;
    int is_gm;

    uint32_t client_key;
    uint32_t server_key;
    int got_first;
    int version;

    CRYPT_SETUP client_cipher;
    CRYPT_SETUP server_cipher;

    unsigned char *recvbuf;
    int pkt_cur;
    int pkt_sz;

    unsigned char *sendbuf;
    int sendbuf_cur;
    int sendbuf_size;
    int sendbuf_start;

    bb_gc_data_t *gc_data;
    bb_security_data_t sec_data;
    int hdr_read;

    /* Only used for the Dreamcast Network Trial Edition */
    char serial[16];
    char access_key[16];
} login_client_t;

/* Privilege levels */
#define CLIENT_PRIV_LOCAL_GM    0x01
#define CLIENT_PRIV_GLOBAL_GM   0x02
#define CLIENT_PRIV_LOCAL_ROOT  0x04
#define CLIENT_PRIV_GLOBAL_ROOT 0x08

#define IS_GLOBAL_GM(c)     (!!((c)->is_gm & CLIENT_PRIV_GLOBAL_GM))
#define IS_GLOBAL_ROOT(c)   (!!((c)->is_gm & CLIENT_PRIV_GLOBAL_ROOT))

/* Values for the type of the login_client_t */
#define CLIENT_TYPE_DC              0
#define CLIENT_TYPE_PC              1
#define CLIENT_TYPE_GC              2
#define CLIENT_TYPE_EP3             3
#define CLIENT_TYPE_BB_LOGIN        4
#define CLIENT_TYPE_BB_CHARACTER    5
#define CLIENT_TYPE_DCNTE           6

#define CLIENT_TYPE_COUNT           4   /* This doesn't include the BB types */

/* The list of type codes for the quest directories. */
static const char type_codes[][3] __attribute__((unused)) = {
    "dc", "pc", "gc", "e3"
};

static const int hdr_sizes[] __attribute__((unused)) = {
    4, 4, 4, 4, 8, 8, 4
};

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

/* Character classes, as strings */
static const char *classes[12] __attribute__((unused)) = {
    "HUmar", "HUnewearl", "HUcast",
    "RAmar", "RAcast", "RAcaseal",
    "FOmarl", "FOnewm", "FOnewearl",
    "HUcaseal", "FOmar", "RAmarl"
};

TAILQ_HEAD(client_queue, login_client);
extern struct client_queue clients;

extern sylverant_dbconn_t conn;
extern sylverant_config_t *cfg;

login_client_t *create_connection(int sock, int type, struct sockaddr *ip,
                                  socklen_t size);
void destroy_connection(login_client_t *c);

int read_from_client(login_client_t *c);

void disconnect_from_ships(uint32_t gcn);

/* In login_server.c */
int ship_transfer(login_client_t *c, uint32_t shipid);
void read_quests();

/* In dclogin.c */
int process_dclogin_packet(login_client_t *c, void *pkt);

void init_i18n(void);
void cleanup_i18n(void);
void print_packet(unsigned char *pkt, int len);

/* In bblogin.c */
int process_bblogin_packet(login_client_t *c, void *pkt);

/* In bbcharacter.c */
int process_bbcharacter_packet(login_client_t *c, void *pkt);
int load_param_data(void);
void cleanup_param_data(void);
int load_bb_char_data(void);

#ifdef HAVE_LIBMINI18N
#include <mini18n-multi.h>
#define __(c, s) mini18n_get(langs[c->language_code], s)
extern mini18n_t langs[CLIENT_LANG_COUNT];
#else
#define __(c, s) s
#endif

#endif /* !LOGIN_H */
