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

#ifndef LOGINPACKETS_H
#define LOGINPACKETS_H

#include <inttypes.h>
#include <netinet/in.h>

#include <sylverant/characters.h>
#include <sylverant/encryption.h>
#include <sylverant/quest.h>

#include "login.h"

#if defined(WORDS_BIGENDIAN) || defined(__BIG_ENDIAN__)
#define LE16(x) (((x >> 8) & 0xFF) | ((x & 0xFF) << 8))
#define LE32(x) (((x >> 24) & 0x00FF) | \
                 ((x >>  8) & 0xFF00) | \
                 ((x & 0xFF00) <<  8) | \
                 ((x & 0x00FF) << 24))
#define LE64(x) (((x >> 56) & 0x000000FF) | \
                 ((x >> 40) & 0x0000FF00) | \
                 ((x >> 24) & 0x00FF0000) | \
                 ((x >>  8) & 0xFF000000) | \
                 ((x & 0xFF000000) <<  8) | \
                 ((x & 0x00FF0000) << 24) | \
                 ((x & 0x0000FF00) << 40) | \
                 ((x & 0x000000FF) << 56))
#else
#define LE16(x) x
#define LE32(x) x
#define LE64(x) x
#endif

#ifdef PACKED
#undef PACKED
#endif

#define PACKED __attribute__((packed))

/* The Welcome packet for setting up encryption keys. */
typedef struct bb_login_welcome {
    bb_pkt_header_t hdr;
    char copyright[75];
    uint8_t padding[21];
    uint8_t svect[48];
    uint8_t cvect[48];
} PACKED bb_login_welcome_pkt;

typedef struct dc_login_welcome {
    union {
        dc_pkt_header_t dc;
        pc_pkt_header_t pc;
    } hdr;
    char copyright[0x40];
    uint32_t svect;
    uint32_t cvect;
} PACKED dc_login_welcome_pkt;

/* The ship select packet that the client sends to us (Blue Burst). */
typedef struct bb_login_ship_select {
    bb_pkt_header_t hdr;
    uint8_t padding1[2];
    uint8_t unk;            /* 0x12 */
    uint8_t padding2;
    uint32_t shipid;
} PACKED bb_login_ship_select_pkt;

/* The ship select packet that the client sends to us (Dreamcast/PC). */
typedef struct dc_login_ship_select {
    union {
        dc_pkt_header_t dc;
        pc_pkt_header_t pc;
    } hdr;
    uint32_t menu_id;
    uint32_t item_id;
} PACKED dc_login_ship_select_pkt;

/* The login packet that the client sends to us (Blue Burst). */
typedef struct login_login {
    bb_pkt_header_t hdr;
    uint8_t unk1[8];
    uint16_t client_version;
    uint8_t unk2[6];
    uint32_t sec32;
    char username[48];
    char password[56];
    uint8_t hwinfo[8];
    union {
        char version_string[40];
        uint64_t sec64[5];
    };
} PACKED login_login_pkt;

/* The login packet that the client sends to us (Dreamcast V1). */
typedef struct login_dclogin {
    dc_pkt_header_t hdr;
    uint32_t unk1[2];
    uint32_t unk2[4];
    char serial[8];
    uint8_t padding1[9];
    char access_key[8];
    uint8_t padding2[9];
    char dc_id[8];
    uint8_t padding3[88];
    char name[16];
    uint8_t padding4[2];
    uint8_t sec_data[0];
} PACKED login_dclogin_pkt;

/* The login packet that the client sends to us (Dreamcast V2/PC). */
typedef struct login_dcv2login {
    union {
        dc_pkt_header_t dc;
        pc_pkt_header_t pc;
    } hdr;
    uint8_t unused[32];
    char serial[8];
    uint8_t padding1[8];
    char access_key[8];
    uint8_t padding2[10];
    uint8_t unk[7];
    uint8_t padding3[3];
    char dc_id[8];
    uint8_t padding4[88];
    char email[32];
    uint8_t padding5[16];
} PACKED login_dcv2login_pkt;

/* The packet sent to redirect clients (Blue Burst). */
typedef struct bb_login_redirect {
    bb_pkt_header_t hdr;
    uint32_t ip_addr;       /* Big-endian */
    uint16_t port;          /* Little-endian */
    uint8_t padding2[2];
} PACKED bb_login_redirect_pkt;

/* The packet sent to redirect clients (Dreamcast/PC). */
typedef struct dc_login_redirect {
    union {
        dc_pkt_header_t dc;
        pc_pkt_header_t pc;
    } hdr;
    uint32_t ip_addr;       /* Big-endian */
    uint16_t port;          /* Little-endian */
    uint8_t padding2[2];
} PACKED dc_login_redirect_pkt;

/* The packet sent to display a large message to clients. */
typedef struct login_largemsg {
    bb_pkt_header_t hdr;
    uint8_t lang[4];
    uint8_t message[];
} PACKED login_large_msg_pkt;

/* The packet sent as a timestamp (Blue Burst). */
typedef struct bb_login_timestamp {
    bb_pkt_header_t hdr;
    char timestamp[28];
} PACKED bb_login_timestamp_pkt;

/* The packet sent as a timestamp (Dreamcast/PC). */
typedef struct dc_login_timestamp {
    union {
        dc_pkt_header_t dc;
        pc_pkt_header_t pc;
    } hdr;
    char timestamp[28];
} PACKED dc_login_timestamp_pkt;

/* The packet sent to communicate the guild card checksum. */
typedef struct login_gc_csum {
    bb_pkt_header_t hdr;
    uint8_t one;            /* 1 */
    uint8_t padding1[3];
    uint16_t gc_len;        /* 0xD590 */
    uint8_t padding2[2];
    uint32_t checksum;
} PACKED login_gc_csum_pkt;

/* The packet sent to send out the player's key configuration. */
typedef struct login_option_reply {
    bb_pkt_header_t hdr;
    uint8_t unk1[276];      /* All zeroes? */
    uint8_t keys[420];
    uint8_t unk2[2100];     /* All zeroes? */
    uint8_t flags[4];       /* All bits set. */
} PACKED login_option_reply_pkt;

/* The packet that the client sends to select a character. */
typedef struct login_char_select {
    bb_pkt_header_t hdr;
    uint8_t slot;
    uint8_t padding1[3];
    uint8_t reason;
    uint8_t padding2[3];
} PACKED login_char_select_pkt;

/* The packet that acts as an acknowledgement to a character select. */
typedef struct login_char_ack {
    bb_pkt_header_t hdr;
    uint8_t slot;
    uint8_t padding1[3];
    uint8_t reason;
    uint8_t padding2[3];
} PACKED login_char_ack_pkt;

/* The packet sent to inform clients of their security data (Blue Burst). */
typedef struct bb_login_security {
    bb_pkt_header_t hdr;
    uint8_t unk[8];
    uint32_t guildcard;
    uint32_t sec32;
    uint8_t unk2[32];
    uint64_t sec64;
    uint8_t unk3[4];        /* 0x01 0x01 0x00 0x00 */
} PACKED bb_login_security_pkt;

/* The packet sent to inform clients of their security data (Dreamcast/PC). */
typedef struct dc_login_security {
    union {
        dc_pkt_header_t dc;
        pc_pkt_header_t pc;
    } hdr;
    uint32_t tag;
    uint32_t guildcard;
    uint8_t security_data[0];
} PACKED dc_login_security_pkt;

/* The packet sent to ack a guild card checksum. */
typedef struct login_guild_ack {
    bb_pkt_header_t hdr;
    uint32_t ack;
} PACKED login_guild_ack_pkt;

/* The packet sent by the client to set various flags (regarding character
   creation). */
typedef struct login_setflags {
    bb_pkt_header_t hdr;
    uint8_t flags[8];
} PACKED login_setflags_pkt;

/* The packet sent to display a scrolling message on the top of the screen. */
typedef struct login_scrollmsg {
    bb_pkt_header_t hdr;
    uint8_t padding[8];
    uint8_t msg[];
} PACKED login_scroll_msg_pkt;

/* The packet used for the information reply on the Dreamcast/PC version. */
typedef struct dc_login_info_reply {
    union {
        dc_pkt_header_t dc;
        pc_pkt_header_t pc;
    } hdr;
    uint32_t odd[2];
    char msg[];
} PACKED dc_login_info_reply_pkt;

/* The data sent about each ship in the ship list packet. */
typedef struct login_ship_info {
    uint8_t eighteen;       /* 0x12 */
    uint8_t padding1;       /* Zero */
    uint32_t ship_id;
    uint8_t padding2[2];    /* Both zeroes */
    uint8_t name[36];       /* Ship Name (num players) */
} PACKED login_ship_info_t;

/* The ship list packet sent to tell clients what ships are up (Blue Burst). */
typedef struct bb_login_ship_list {
    bb_pkt_header_t hdr;    /* The padding field in hdr is for the ship count */
    uint8_t padding1[2];
    uint8_t thirty_two;     /* 0x20 */
    uint8_t padding2;
    uint32_t unk1;          /* 0xFFFFFFF4 */
    uint8_t four;           /* 0x04 */
    uint8_t padding3;
    uint8_t sname[18];      /* Probably also includes below padding */
    uint8_t padding[18];
    login_ship_info_t inf[0];
} PACKED bb_login_ship_list_pkt;

/* The ship list packet send to tell clients what ships are up (Dreamcast). */
typedef struct dc_login_ship_list {
    dc_pkt_header_t hdr;    /* The flags field says how entries are below */
    struct {
        uint32_t menu_id;
        uint32_t item_id;
        uint16_t flags;
        char name[0x12];
    } entries[0];
} PACKED dc_login_ship_list_pkt;

/* The ship list packet send to tell clients what ships are up (PC). */
typedef struct pc_login_ship_list {
    pc_pkt_header_t hdr;    /* The flags field says how entries are below */
    struct {
        uint32_t menu_id;
        uint32_t item_id;
        uint16_t flags;
        uint16_t name[0x11];
    } entries[0];
} PACKED pc_login_ship_list_pkt;

/* The ship information request packet the client sends. */
typedef struct login_info_req {
    bb_pkt_header_t hdr;
    uint8_t padding1[2];
    uint8_t eighteen;       /* 0x12 */
    uint8_t padding2;
    uint32_t ship_id;
} PACKED login_info_req_pkt;

/* The packet to verify that a hunter's license has been procured. */
typedef struct login_gc_hlcheck {
    dc_pkt_header_t hdr;
    uint8_t padding1[32];
    char serial[8];
    uint8_t padding2[8];
    char access_key[12];
    uint8_t padding3[12];
    uint8_t version;
    uint8_t padding4[3];
    char serial2[8];
    uint8_t padding5[40];
    char access_key2[12];
    uint8_t padding6[36];
    char password[16];
    uint8_t padding7[32];
} PACKED login_gc_hlcheck_pkt;

/* One of the login packets sent by PSOGC. */
typedef struct login_gc_loginc {
    dc_pkt_header_t hdr;
    uint8_t padding1[8];
    uint8_t version;
    uint8_t padding2[4];
    uint8_t one;            /* 0x01 */
    uint8_t padding3[2];
    char serial[8];
    uint8_t padding4[40];
    char access_key[12];
    uint8_t padding5[36];
    char password[16];
    uint8_t padding6[32];
} PACKED login_gc_loginc_pkt;

/* The other login packet sent by PSOGC. */
typedef struct login_gc_logine {
    dc_pkt_header_t hdr;
    uint8_t padding1[2];
    uint8_t ffffffffffff[6];
    uint8_t padding2[8];
    uint8_t version;
    uint8_t padding3[4];
    uint8_t one;            /* 0x01 */
    uint8_t padding4[34];
    char serial[8];
    uint8_t padding5[8];
    char access_key[12];
    uint8_t padding6[4];
    char serial2[8];
    uint8_t padding7[40];
    char access_key2[12];
    uint8_t padding8[36];
    char name[16];
    uint8_t padding9[132];
} PACKED login_gc_logine_pkt;

/* The packet used to send the quest list (Dreamcast). */
typedef struct dc_quest_list {
    dc_pkt_header_t hdr;
    struct {
        uint32_t menu_id;
        uint32_t item_id;
        char name[32];
        char desc[112];
    } entries[0];
} PACKED dc_quest_list_pkt;

/* The packet used to send the quest list (PC). */
typedef struct pc_quest_list {
    pc_pkt_header_t hdr;
    struct {
        uint32_t menu_id;
        uint32_t item_id;
        uint16_t name[32];
        uint16_t desc[112];
    } entries[0];
} PACKED pc_quest_list_pkt;

/* The packet sent to inform a client of a quest file that will be coming down
   the pipe (Dreamcast). */
typedef struct dc_quest_file {
    dc_pkt_header_t hdr;
    char name[32];
    uint8_t unused1[3];
    char filename[16];
    uint8_t unused2;
    uint32_t length;
} PACKED dc_quest_file_pkt;

/* The packet sent to inform a client of a quest file that will be coming down
   the pipe (PC). */
typedef struct pc_quest_file {
    pc_pkt_header_t hdr;
    char name[32];
    uint16_t unused;
    uint16_t flags;
    char filename[16];
    uint32_t length;
} PACKED pc_quest_file_pkt;

/* The packet sent to inform a client of a quest file that will be coming down
   the pipe (Gamecube). */
typedef struct gc_quest_file {
    dc_pkt_header_t hdr;
    char name[32];
    uint16_t unused;
    uint16_t flags;
    char filename[16];
    uint32_t length;
} PACKED gc_quest_file_pkt;

/* The packet sent to actually send quest data (Dreamcast/PC). */
typedef struct dc_quest_chunk {
    union {
        dc_pkt_header_t dc;
        pc_pkt_header_t pc;
    } hdr;
    char filename[16];
    char data[1024];
    uint32_t length;
} PACKED dc_quest_chunk_pkt;

#undef PACKED

/* Parameters for the various packets. */
#define LOGIN_BB_WELCOME_TYPE               0x0003
#define LOGIN_DC_SECURITY_TYPE              0x0004
#define LOGIN_CLIENT_DISCONNECT_TYPE        0x0005
#define LOGIN_DC_SHIP_LIST_TYPE             0x0007
#define LOGIN_INFO_REQUEST_TYPE             0x0009
#define LOGIN_SHIP_SELECT_TYPE              0x0010
#define LOGIN_INFO_REPLY_TYPE               0x0011
#define LOGIN_DC_WELCOME_TYPE               0x0017
#define LOGIN_REDIRECT_TYPE                 0x0019
#define LOGIN_LARGE_MESSAGE_TYPE            0x001A
#define LOGIN_DC_LOGIN0_TYPE                0x0090
#define LOGIN_DC_LOGIN2_TYPE                0x0092
#define LOGIN_CLIENT_LOGIN_TYPE             0x0093
#define LOGIN_DC_CHECKSUM_TYPE              0x0096
#define LOGIN_DC_CHECKSUM_REPLY_TYPE        0x0097
#define LOGIN_DC_SHIP_LIST_REQ_TYPE         0x0099
#define LOGIN_DCV2_LOGINA_TYPE              0x009A
#define LOGIN_GC_LOGINC_TYPE                0x009C
#define LOGIN_GC_LOGINE_TYPE                0x009E
#define LOGIN_SHIP_LIST_TYPE                0x00A0
#define LOGIN_QUEST_LIST_TYPE               0x00A4
#define LOGIN_QUEST_FILE_TYPE               0x00A6
#define LOGIN_QUEST_CHUNK_TYPE              0x00A7
#define LOGIN_TIMESTAMP_TYPE                0x00B1
#define LOGIN_GC_VERIFY_LICENSE_TYPE        0x00DB
#define LOGIN_GUILD_CARDS_TYPE              0x00DC
#define LOGIN_OPTION_REQUEST_TYPE           0x00E0
#define LOGIN_OPTION_REPLY_TYPE             0x00E2
#define LOGIN_CHAR_SELECT_TYPE              0x00E3
#define LOGIN_CHAR_ACK_TYPE                 0x00E4
#define LOGIN_CHAR_DATA_TYPE                0x00E5
#define LOGIN_BB_SECURITY_TYPE              0x00E6
#define LOGIN_GUILD_REQUEST_TYPE            0x00E8
#define LOGIN_PARAMETER_TYPE                0x00EB
#define LOGIN_SETFLAG_TYPE                  0x00EC
#define LOGIN_SCROLL_MESSAGE_TYPE           0x00EE

#define LOGIN_BB_WELCOME_LENGTH             0x00C8
#define LOGIN_DC_WELCOME_LENGTH             0x004C
#define LOGIN_BB_REDIRECT_LENGTH            0x0010
#define LOGIN_DC_REDIRECT_LENGTH            0x000C
#define LOGIN_CLIENT_LOGIN_LENGTH           0x00B4
#define LOGIN_BB_TIMESTAMP_LENGTH           0x0024
#define LOGIN_DC_TIMESTAMP_LENGTH           0x0020
#define LOGIN_GUILD_CHECKSUM_LENGTH         0x0014
#define LOGIN_OPTION_REPLY_LENGTH           0x0AF8
#define LOGIN_CHAR_ACK_LENGTH               0x0010
#define LOGIN_CHAR_DATA_LENGTH              0x0088
#define LOGIN_SECURITY_LENGTH               0x0044
#define LOGIN_GUILD_ACK_LENGTH              0x000C
#define LOGIN_DC_QUEST_INFO_LENGTH          0x0128
#define LOGIN_PC_QUEST_INFO_LENGTH          0x024C
#define LOGIN_DC_QUEST_FILE_LENGTH          0x003C
#define LOGIN_DC_QUEST_CHUNK_LENGTH         0x0418

/* This must be placed into the copyright field in the BB welcome packet. */
const static char login_bb_welcome_copyright[] =
    "Phantasy Star Online Blue Burst Game Server. "
    "Copyright 1999-2004 SONICTEAM.";

/* This must be placed into the copyright field in the DC welcome packet. */
const static char login_dc_welcome_copyright[] =
    "DreamCast Port Map. Copyright SEGA Enterprises. 1999";

/* Values for the reason of an acknowledgement of a character. */
#define ACK_CREATE                          0
#define ACK_SELECT                          1
#define ACK_NONEXISTANT                     2

/* Send a Blue Burst Welcome packet to the given client. */
int send_bb_welcome(login_client_t *c, uint8_t svect[48], uint8_t cvect[48]);

/* Send a Dreamcast Welcome packet to the given client. */
int send_dc_welcome(login_client_t *c, uint32_t svect, uint32_t cvect);

/* Send a large message packet to the given client. */
int send_large_msg(login_client_t *c, char msg[]);

/* Send the Dreamcast security packet to the given client. */
int send_dc_security(login_client_t *c, uint32_t gc, uint8_t *data,
                     int data_len);

/* Send a redirect packet to the given client. */
int send_redirect(login_client_t *c, in_addr_t ip, uint16_t port);

/* Send a timestamp packet to the given client. */
int send_timestamp(login_client_t *c);

/* Send a scrolling message packet to the given client. */
int send_scroll_msg(login_client_t *c, char msg[]);

/* Send a option reply packet to the given client. */
int send_optreply(login_client_t *c, uint8_t keys[420]);

/* Send a character ack to the given client. */
int send_char_ack(login_client_t *c, uint8_t slot, uint8_t reason);

/* Send character data to the given client. */
int send_char_data(login_client_t *c, sylverant_mini_char_t *ch);

/* Send a guild card checksum ack to the given client. */
int send_guild_ack(login_client_t *c, uint32_t ack);

/* Send a guild card checksum packet to the given client. */
int send_gc_checksum(login_client_t *c, uint32_t checksum);

/* Send guild card data to the given client. */
int send_gc_data(login_client_t *c, uint8_t *data, uint8_t idx);

/* Send the list of ships to the client. */
int send_ship_list(login_client_t *c);

/* Send a information reply packet to the client. */
int send_info_reply(login_client_t *c, char msg[]);

/* Send a simple (header-only) packet to the client. */
int send_simple(login_client_t *c, int type, int flags);

/* Send the packet to clients that will help sort out PSOGC versus PSOPC
   users. */
int send_selective_redirect(login_client_t *c, in_addr_t ip, uint16_t port);

/* Send the quest list to a client. */
int send_quest_list(login_client_t *c, sylverant_quest_category_t *l);

/* Send a quest to a client. */
int send_quest(login_client_t *c, sylverant_quest_t *q);

#endif /* !LOGINPACKETS_H */
