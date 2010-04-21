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

#ifdef PACKED
#undef PACKED
#endif

#define PACKED __attribute__((packed))

/* The common packet header on top of all packets. */
typedef struct bb_pkt_header {
    uint16_t pkt_len;
    uint16_t pkt_type;
    uint32_t padding;
} PACKED bb_pkt_header_t;

typedef struct dc_pkt_header {
    uint8_t pkt_type;
    uint8_t flags;
    uint16_t pkt_len;
} PACKED dc_pkt_header_t;

typedef struct pc_pkt_header {
    uint16_t pkt_len;
    uint8_t pkt_type;
    uint8_t flags;
} PACKED pc_pkt_header_t;

typedef union pkt_header {
    bb_pkt_header_t bb;
    dc_pkt_header_t dc;
    pc_pkt_header_t pc;
} pkt_header_t;

#undef PACKED

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
} login_client_t;

/* Values for the type of the login_client_t */
#define CLIENT_TYPE_DC              0
#define CLIENT_TYPE_PC              1
#define CLIENT_TYPE_GC              2

/* These are not supported at the moment, but here to make it so that the code
   that was written for them still works. */
#define CLIENT_TYPE_BB_LOGIN        0xFE
#define CLIENT_TYPE_BB_CHARACTER    0xFF

TAILQ_HEAD(client_queue, login_client);
extern struct client_queue clients;

extern sylverant_dbconn_t conn;
extern sylverant_config_t cfg;

login_client_t *create_connection(int sock, in_addr_t ip, int type);
void destroy_connection(login_client_t *c);

int process_login_packet(login_client_t *c, bb_pkt_header_t *hdr);
int process_character_packet(login_client_t *c, bb_pkt_header_t *hdr);
int process_dclogin_packet(login_client_t *c, void *pkt);

int read_from_client(login_client_t *c);

void disconnect_from_ships(uint32_t gcn);

#endif /* !LOGIN_H */
