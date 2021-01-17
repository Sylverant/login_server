/*
    Sylverant Login Server
    Copyright (C) 2009, 2010, 2011, 2013, 2015, 2016, 2018, 2020,
                  2021 Lawrence Sebald

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
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <netdb.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <ifaddrs.h>

#include <sylverant/config.h>
#include <sylverant/checksum.h>
#include <sylverant/database.h>
#include <sylverant/encryption.h>
#include <sylverant/mtwist.h>
#include <sylverant/debug.h>
#include <sylverant/quest.h>
#include <sylverant/items.h>

#if HAVE_LIBUTIL_H == 1
#include <libutil.h>
#elif HAVE_BSD_LIBUTIL_H == 1
#include <bsd/libutil.h>
#else
/* From pidfile.c */
struct pidfh;
struct pidfh *pidfile_open(const char *path, mode_t mode, pid_t *pidptr);
int pidfile_write(struct pidfh *pfh);
int pidfile_remove(struct pidfh *pfh);
int pidfile_fileno(struct pidfh *pfh);
#endif

#include "login.h"
#include "login_packets.h"
#include "patch.h"

#ifndef PID_DIR
#define PID_DIR "/var/run"
#endif

#ifndef RUNAS_DEFAULT
#define RUNAS_DEFAULT "sylverant"
#endif

#ifndef ENABLE_IPV6
#define NUM_DCSOCKS  3
#define NUM_PCSOCKS  1
#define NUM_GCSOCKS  2
#define NUM_EP3SOCKS 4
#define NUM_WEBSOCKS 1
#define NUM_BBSOCKS  2
#define NUM_XBSOCKS  1
#else
#define NUM_DCSOCKS  6
#define NUM_PCSOCKS  2
#define NUM_GCSOCKS  4
#define NUM_EP3SOCKS 8
#define NUM_WEBSOCKS 2
#define NUM_BBSOCKS  4
#define NUM_XBSOCKS  2
#endif

static const int dcports[NUM_DCSOCKS][2] = {
    { AF_INET , 9200 },
    { AF_INET , 9201 },
    { AF_INET , 9000 },                 /* Dreamcast Network Trial Edition */
#ifdef ENABLE_IPV6
    { AF_INET6, 9200 },
    { AF_INET6, 9201 },
    { AF_INET6, 9000 }
#endif
};

static const int pcports[NUM_PCSOCKS][2] = {
    { AF_INET , 9300 },
#ifdef ENABLE_IPV6
    { AF_INET6, 9300 }
#endif
};

static const int gcports[NUM_GCSOCKS][2] = {
    { AF_INET , 9100 },
    { AF_INET , 9001 },
#ifdef ENABLE_IPV6
    { AF_INET6, 9100 },
    { AF_INET6, 9001 }
#endif
};

static const int ep3ports[NUM_EP3SOCKS][2] = {
    { AF_INET , 9103 },
    { AF_INET , 9003 },
    { AF_INET , 9203 },
    { AF_INET , 9002 },
#ifdef ENABLE_IPV6
    { AF_INET6, 9103 },
    { AF_INET6, 9003 },
    { AF_INET6, 9203 },
    { AF_INET6, 9002 }
#endif
};

static const int webports[NUM_WEBSOCKS][2] = {
    { AF_INET , 10003 },
#ifdef ENABLE_IPV6
    { AF_INET6, 10003 }
#endif
};

static const int bbports[NUM_BBSOCKS][2] = {
    { AF_INET , 12000 },
    { AF_INET , 12001 },
#ifdef ENABLE_IPV6
    { AF_INET6, 12000 },
    { AF_INET6, 12001 }
#endif
};

static const int xbports[NUM_XBSOCKS][2] = {
    { AF_INET , 9500 },
#ifdef ENABLE_IPV6
    { AF_INET6, 9500 }
#endif
};

/* Stuff read from the config files */
sylverant_dbconn_t conn;
sylverant_config_t *cfg;
sylverant_limits_t *limits = NULL;
patch_list_t *patches_v2 = NULL;
patch_list_t *patches_gc = NULL;

sylverant_quest_list_t qlist[CLIENT_TYPE_COUNT][CLIENT_LANG_COUNT];
volatile sig_atomic_t shutting_down = 0;

static const char *config_file = NULL;
static const char *custom_dir = NULL;
static int dont_daemonize = 0;
static const char *pidfile_name = NULL;
static struct pidfh *pf = NULL;
static const char *runas_user = RUNAS_DEFAULT;

/* Print information about this program to stdout. */
static void print_program_info() {
    printf("Sylverant Login Server version %s\n", VERSION);
    printf("Copyright (C) 2009-2021 Lawrence Sebald\n\n");
    printf("This program is free software: you can redistribute it and/or\n"
           "modify it under the terms of the GNU Affero General Public\n"
           "License version 3 as published by the Free Software Foundation.\n\n"
           "This program is distributed in the hope that it will be useful,\n"
           "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
           "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
           "GNU General Public License for more details.\n\n"
           "You should have received a copy of the GNU Affero General Public\n"
           "License along with this program.  If not, see"
           "<http://www.gnu.org/licenses/>.\n");
}

/* Print help to the user to stdout. */
static void print_help(const char *bin) {
    printf("Usage: %s [arguments]\n"
           "-----------------------------------------------------------------\n"
           "--version       Print version info and exit\n"
           "--verbose       Log many messages that might help debug a problem\n"
           "--quiet         Only log warning and error messages\n"
           "--reallyquiet   Only log error messages\n"
           "-C configfile   Use the specified configuration instead of the\n"
           "                default one.\n"
           "-D directory    Use the specified directory as the root\n"
           "--nodaemon      Don't daemonize\n"
           "-P filename     Use the specified name for the pid file to write\n"
           "                instead of the default.\n"
           "-U username     Run as the specified user instead of '%s'\n"
           "--help          Print this help and exit\n\n"
           "Note that if more than one verbosity level is specified, the last\n"
           "one specified will be used. The default is --verbose.\n", bin,
           RUNAS_DEFAULT);
}

/* Parse any command-line arguments passed in. */
static void parse_command_line(int argc, char *argv[]) {
    int i;

    for(i = 1; i < argc; ++i) {
        if(!strcmp(argv[i], "--version")) {
            print_program_info();
            exit(EXIT_SUCCESS);
        }
        else if(!strcmp(argv[i], "--verbose")) {
            debug_set_threshold(DBG_LOG);
        }
        else if(!strcmp(argv[i], "--quiet")) {
            debug_set_threshold(DBG_WARN);
        }
        else if(!strcmp(argv[i], "--reallyquiet")) {
            debug_set_threshold(DBG_ERROR);
        }
        else if(!strcmp(argv[i], "-C")) {
            /* Save the config file's name. */
            if(i == argc - 1) {
                printf("-C requires an argument!\n\n");
                print_help(argv[0]);
                exit(EXIT_FAILURE);
            }

            config_file = argv[++i];
        }
        else if(!strcmp(argv[i], "-D")) {
            /* Save the custom dir */
            if(i == argc - 1) {
                printf("-D requires an argument!\n\n");
                print_help(argv[0]);
                exit(EXIT_FAILURE);
            }

            custom_dir = argv[++i];
        }
        else if(!strcmp(argv[i], "--nodaemon")) {
            dont_daemonize = 1;
        }
        else if(!strcmp(argv[i], "-P")) {
            if(i == argc - 1) {
                printf("-P requires an argument!\n\n");
                print_help(argv[0]);
                exit(EXIT_FAILURE);
            }

            pidfile_name = argv[++i];
        }
        else if(!strcmp(argv[i], "-U")) {
            if(i == argc - 1) {
                printf("-U requires an argument!\n\n");
                print_help(argv[0]);
                exit(EXIT_FAILURE);
            }

            runas_user = argv[++i];
        }
        else if(!strcmp(argv[i], "--help")) {
            print_help(argv[0]);
            exit(EXIT_SUCCESS);
        }
        else {
            printf("Illegal command line argument: %s\n", argv[i]);
            print_help(argv[0]);
            exit(EXIT_FAILURE);
        }
    }
}

void read_quests() {
    int i, j;
    char fn[512];
    sylverant_quest_list_t tmp;
    static int read_quests = 0;

    debug(DBG_LOG, "Reading quests...\n");

    if(cfg->quests_dir && cfg->quests_dir[0]) {
        for(i = 0; i < CLIENT_TYPE_COUNT; ++i) {
            if(type_codes[i][0] == 0)
                continue;

            for(j = 0; j < CLIENT_LANG_COUNT; ++j) {
                sprintf(fn, "%s/%s-%s/quests.xml", cfg->quests_dir,
                        type_codes[i], language_codes[j]);
                if(!sylverant_quests_read(fn, &tmp)) {
                    debug(DBG_LOG, "Read quests for %s-%s\n", type_codes[i],
                          language_codes[j]);
                }

                /* Cleanup and move the new stuff in place. */
                if(read_quests) {
                    sylverant_quests_destroy(&qlist[i][j]);
                }

                qlist[i][j] = tmp;
            }
        }
    }

    read_quests = 1;
}

/* Load the configuration file. */
static void load_config() {
    if(sylverant_read_config(config_file, &cfg)) {
        debug(DBG_ERROR, "Cannot load configuration!\n");
        exit(EXIT_FAILURE);
    }
}

static void load_config2() {
    char *fn;
    char *pfn;
    int i;

    /* Attempt to read each quests file... */
    read_quests();

    /* Attempt to read the legit items list */
    if(cfg->limits_enforced != -1) {
        fn = cfg->limits[cfg->limits_enforced].filename;

        debug(DBG_LOG, "Reading enforced limits file %s (name: %s)...\n", fn,
              cfg->limits[cfg->limits_enforced].name);
        if(fn && sylverant_read_limits(fn, &limits)) {
            debug(DBG_WARN, "Cannot read specified limits file\n");
        }
    }

    /* Print out the rest... */
    for(i = 0; i < cfg->limits_count; ++i) {
        if(!cfg->limits[i].enforce) {
            debug(DBG_LOG, "Ignoring non-enforced limits file %s (name: %s)\n",
                  cfg->limits[i].filename, cfg->limits[i].name);
        }
    }

    /* Read the Blue Burst param data */
    if(load_param_data())
        exit(EXIT_FAILURE);

    if(load_bb_char_data())
        exit(EXIT_FAILURE);

    /* Read patch lists. */
    if(cfg->patch_dir) {
        debug(DBG_LOG, "Runtime Patches Directory: %s\n", cfg->patch_dir);

        pfn = (char *)malloc(strlen(cfg->patch_dir) + 32);
        if(!pfn) {
            perror("malloc");
            exit(EXIT_FAILURE);
        }

        /* Start with v2... */
        sprintf(pfn, "%s/v2/patches.xml", cfg->patch_dir);

        debug(DBG_LOG, "Reading DCv2 Patch List '%s'...\n", pfn);
        if(patch_list_read(pfn, &patches_v2)) {
            debug(DBG_LOG, "Couldn't read DCv2 patch list\n");
            patches_v2 = NULL;
        }
        else {
            debug(DBG_LOG, "Found %" PRIu32 " patches\n",
                  patches_v2->patch_count);
        }

        sprintf(pfn, "%s/gc/patches.xml", cfg->patch_dir);

        debug(DBG_LOG, "Reading GC Patch list '%s'...\n", pfn);
        if(patch_list_read(pfn, &patches_gc)) {
            debug(DBG_LOG, "Couldn't read GC patch list\n");
            patches_gc = NULL;
        }
        else {
            debug(DBG_LOG, "Found %" PRIu32 " patches\n",
                  patches_gc->patch_count);
        }
    }

    debug(DBG_LOG, "Connecting to the database...\n");

    if(sylverant_db_open(&cfg->dbcfg, &conn)) {
        debug(DBG_ERROR, "Can't connect to the database\n");
        exit(EXIT_FAILURE);
    }
}

int ship_transfer(login_client_t *c, uint32_t shipid) {
    char query[256];
    void *result;
    char **row;
    in_addr_t ip;
    uint16_t port;
#ifdef ENABLE_IPV6
    uint64_t ip6_hi, ip6_lo;
    uint8_t ip6[16];
#endif

    /* Query the database for the ship in question */
    sprintf(query, "SELECT ip, port, ship_ip6_high, ship_ip6_low FROM "
            "online_ships WHERE ship_id='%lu'", (unsigned long)shipid);

    if(sylverant_db_query(&conn, query))
        return -1;

    if(!(result = sylverant_db_result_store(&conn)))
        return -2;

    if(!(row = sylverant_db_result_fetch(result)))
        return -3;

    /* Grab the data from the row */
    if(c->type < CLIENT_TYPE_BB_CHARACTER)
        port = (uint16_t)strtoul(row[1], NULL, 0) + c->type;
    else if(c->type == CLIENT_TYPE_DCNTE)
        port = (uint16_t)strtoul(row[1], NULL, 0);
    else if(c->type == CLIENT_TYPE_XBOX)
        port = (uint16_t)strtoul(row[1], NULL, 0) + 5;
    else
        port = (uint16_t)strtoul(row[1], NULL, 0) + 4;

#ifdef ENABLE_IPV6
    if(row[2] && row[3]) {
        ip6_hi = (uint64_t)strtoull(row[2], NULL, 0);
        ip6_lo = (uint64_t)strtoull(row[3], NULL, 0);
    }

    if(!c->is_ipv6 || !row[2] || !row[3] || !ip6_hi) {
#endif
        ip = htonl((in_addr_t)strtoul(row[0], NULL, 0));

        return send_redirect(c, ip, port);
#ifdef ENABLE_IPV6
    }
    else {
        ip6[0] = (uint8_t)(ip6_hi >> 56);
        ip6[1] = (uint8_t)(ip6_hi >> 48);
        ip6[2] = (uint8_t)(ip6_hi >> 40);
        ip6[3] = (uint8_t)(ip6_hi >> 32);
        ip6[4] = (uint8_t)(ip6_hi >> 24);
        ip6[5] = (uint8_t)(ip6_hi >> 16);
        ip6[6] = (uint8_t)(ip6_hi >> 8);
        ip6[7] = (uint8_t)(ip6_hi);
        ip6[8] = (uint8_t)(ip6_lo >> 56);
        ip6[9] = (uint8_t)(ip6_lo >> 48);
        ip6[10] = (uint8_t)(ip6_lo >> 40);
        ip6[11] = (uint8_t)(ip6_lo >> 32);
        ip6[12] = (uint8_t)(ip6_lo >> 24);
        ip6[13] = (uint8_t)(ip6_lo >> 16);
        ip6[14] = (uint8_t)(ip6_lo >> 8);
        ip6[15] = (uint8_t)(ip6_lo);

        return send_redirect6(c, ip6, port);
    }
#endif
}

const void *my_ntop(struct sockaddr_storage *addr, char str[INET6_ADDRSTRLEN]) {
    int family = addr->ss_family;

    switch(family) {
        case AF_INET:
        {
            struct sockaddr_in *a = (struct sockaddr_in *)addr;
            return inet_ntop(family, &a->sin_addr, str, INET6_ADDRSTRLEN);
        }

        case AF_INET6:
        {
            struct sockaddr_in6 *a = (struct sockaddr_in6 *)addr;
            return inet_ntop(family, &a->sin6_addr, str, INET6_ADDRSTRLEN);
        }
    }

    return NULL;
}

static void run_server(int dcsocks[NUM_DCSOCKS], int pcsocks[NUM_PCSOCKS],
                       int gcsocks[NUM_GCSOCKS], int websocks[NUM_WEBSOCKS],
                       int ep3socks[NUM_EP3SOCKS], int bbsocks[NUM_BBSOCKS],
                       int xbsocks[NUM_XBSOCKS]) {
    fd_set readfds, writefds;
    struct timeval timeout;
    socklen_t len;
    struct sockaddr_storage addr;
    struct sockaddr *addr_p = (struct sockaddr *)&addr;
    char ipstr[INET6_ADDRSTRLEN];
    int nfds, asock, j, type;
    login_client_t *i, *tmp;
    ssize_t sent;
    uint32_t client_count;

    for(;;) {
        /* Clear the fd_sets so we can use them. */
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        timeout.tv_sec = 9001;
        timeout.tv_usec = 0;
        nfds = 0;
        client_count = 0;

        /* Fill the sockets into the fd_set so we can use select below. */
        TAILQ_FOREACH(i, &clients, qentry) {
            FD_SET(i->sock, &readfds);

            /* Only add to the writing fd_set if we have something to write. */
            if(i->sendbuf_cur) {
                FD_SET(i->sock, &writefds);
            }

            nfds = nfds > i->sock ? nfds : i->sock;
            ++client_count;
        }

        /* If we have a shutdown scheduled and nobody's connected, go ahead and
           do it. */
        if(!client_count && shutting_down) {
            debug(DBG_LOG, "Got shutdown signal.\n");
            return;
        }

        /* Add the listening sockets for incoming connections to the fd_set. */
        for(j = 0; j < NUM_DCSOCKS; ++j) {
            FD_SET(dcsocks[j], &readfds);
            nfds = nfds > dcsocks[j] ? nfds : dcsocks[j];
        }

        for(j = 0; j < NUM_GCSOCKS; ++j) {
            FD_SET(gcsocks[j], &readfds);
            nfds = nfds > gcsocks[j] ? nfds : gcsocks[j];
        }

        for(j = 0; j < NUM_EP3SOCKS; ++j) {
            FD_SET(ep3socks[j], &readfds);
            nfds = nfds > ep3socks[j] ? nfds : ep3socks[j];
        }

        for(j = 0; j < NUM_PCSOCKS; ++j) {
            FD_SET(pcsocks[j], &readfds);
            nfds = nfds > pcsocks[j] ? nfds : pcsocks[j];
        }

        for(j = 0; j < NUM_BBSOCKS; ++j) {
            FD_SET(bbsocks[j], &readfds);
            nfds = nfds > bbsocks[j] ? nfds : bbsocks[j];
        }

        for(j = 0; j < NUM_XBSOCKS; ++j) {
            FD_SET(xbsocks[j], &readfds);
            nfds = nfds > xbsocks[j] ? nfds : xbsocks[j];
        }

        for(j = 0; j < NUM_WEBSOCKS; ++j) {
            FD_SET(websocks[j], &readfds);
            nfds = nfds > websocks[j] ? nfds : websocks[j];
        }

        if(select(nfds + 1, &readfds, &writefds, NULL, &timeout) > 0) {
            /* See if we have an incoming client. */
            for(j = 0; j < NUM_DCSOCKS; ++j) {
                if(FD_ISSET(dcsocks[j], &readfds)) {
                    len = sizeof(struct sockaddr_storage);

                    if((asock = accept(dcsocks[j], addr_p, &len)) < 0) {
                        perror("accept");
                    }

                    my_ntop(&addr, ipstr);
                    debug(DBG_LOG, "Accepted Dreamcast connection from %s "
                          "on port %d\n", ipstr, dcports[j][1]);

                    if(!create_connection(asock, CLIENT_TYPE_DC, addr_p, len,
                                          dcports[j][1])) {
                        close(asock);
                    }
                    else {
                        ++client_count;
                    }
                }
            }

            for(j = 0; j < NUM_PCSOCKS; ++j) {
                if(FD_ISSET(pcsocks[j], &readfds)) {
                    len = sizeof(struct sockaddr_storage);

                    if((asock = accept(pcsocks[j], addr_p, &len)) < 0) {
                        perror("accept");
                    }

                    my_ntop(&addr, ipstr);
                    debug(DBG_LOG, "Accepted PC connection from %s "
                          "on port %d\n", ipstr, pcports[j][1]);

                    if(!create_connection(asock, CLIENT_TYPE_PC, addr_p, len,
                                          pcports[j][1])) {
                        close(asock);
                    }
                    else {
                        ++client_count;
                    }
                }
            }

            for(j = 0; j < NUM_GCSOCKS; ++j) {
                if(FD_ISSET(gcsocks[j], &readfds)) {
                    len = sizeof(struct sockaddr_storage);

                    if((asock = accept(gcsocks[j], addr_p, &len)) < 0) {
                        perror("accept");
                    }

                    my_ntop(&addr, ipstr);
                    debug(DBG_LOG, "Accepted Gamecube connection from %s "
                          "on port %d\n", ipstr, gcports[j][1]);

                    if(!create_connection(asock, CLIENT_TYPE_GC, addr_p, len,
                                          gcports[j][1])) {
                        close(asock);
                    }
                    else {
                        ++client_count;
                    }
                }
            }

            for(j = 0; j < NUM_EP3SOCKS; ++j) {
                if(FD_ISSET(ep3socks[j], &readfds)) {
                    len = sizeof(struct sockaddr_storage);

                    if((asock = accept(ep3socks[j], addr_p, &len)) < 0) {
                        perror("accept");
                    }

                    my_ntop(&addr, ipstr);
                    debug(DBG_LOG, "Accepted Episode 3 connection from %s "
                          "on port %d\n", ipstr, ep3ports[j][1]);

                    if(!create_connection(asock, CLIENT_TYPE_EP3, addr_p,
                                          len, ep3ports[j][1])) {
                        close(asock);
                    }
                    else {
                        ++client_count;
                    }
                }
            }

            for(j = 0; j < NUM_BBSOCKS; ++j) {
                if(FD_ISSET(bbsocks[j], &readfds)) {
                    len = sizeof(struct sockaddr_storage);

                    if((asock = accept(bbsocks[j], addr_p, &len)) < 0) {
                        perror("accept");
                    }

                    my_ntop(&addr, ipstr);
                    debug(DBG_LOG, "Accepted Blue Burst connection from %s "
                          "on port %d\n", ipstr, bbports[j][1]);

                    if(j & 1) {
                        type = CLIENT_TYPE_BB_CHARACTER;
                    }
                    else {
                        type = CLIENT_TYPE_BB_LOGIN;
                    }

                    if(!create_connection(asock, type, addr_p, len,
                                          bbports[j][1])) {
                        close(asock);
                    }
                    else {
                        ++client_count;
                    }
                }
            }

            for(j = 0; j < NUM_XBSOCKS; ++j) {
                if(FD_ISSET(xbsocks[j], &readfds)) {
                    len = sizeof(struct sockaddr_storage);

                    if((asock = accept(xbsocks[j], addr_p, &len)) < 0) {
                        perror("accept");
                    }

                    my_ntop(&addr, ipstr);
                    debug(DBG_LOG, "Accepted Xbox connection from secure "
                          "gateway %s on port %d\n", ipstr, xbports[j][1]);

                    if(!create_connection(asock, CLIENT_TYPE_XBOX, addr_p,
                                          len, xbports[j][1])) {
                        close(asock);
                    }
                    else {
                        ++client_count;
                    }
                }
            }

            for(j = 0; j < NUM_WEBSOCKS; ++j) {
                if(FD_ISSET(websocks[j], &readfds)) {
                    len = sizeof(struct sockaddr_storage);

                    if((asock = accept(websocks[j], addr_p, &len)) < 0) {
                        perror("accept");
                    }
                    else {
                        /* Send the number of connected clients, and close the
                           socket. */
                        client_count = LE32(client_count);
                        send(asock, &client_count, 4, 0);
                        close(asock);
                    }
                }
            }

            /* Handle the client connections, if any. */
            TAILQ_FOREACH(i, &clients, qentry) {
                /* Check if this connection was trying to send us something. */
                if(FD_ISSET(i->sock, &readfds)) {
                    if(read_from_client(i)) {
                        i->disconnected = 1;
                    }
                }

                /* If we have anything to write, check if we can right now. */
                if(FD_ISSET(i->sock, &writefds)) {
                    if(i->sendbuf_cur) {
                        sent = send(i->sock, i->sendbuf + i->sendbuf_start,
                                    i->sendbuf_cur - i->sendbuf_start, 0);

                        /* If we fail to send, and the error isn't EAGAIN,
                           bail. */
                        if(sent == -1) {
                            if(errno != EAGAIN) {
                                i->disconnected = 1;
                            }
                        }
                        else {
                            i->sendbuf_start += sent;

                            /* If we've sent everything, free the buffer. */
                            if(i->sendbuf_start == i->sendbuf_cur) {
                                free(i->sendbuf);
                                i->sendbuf = NULL;
                                i->sendbuf_cur = 0;
                                i->sendbuf_size = 0;
                                i->sendbuf_start = 0;
                            }
                        }
                    }
                }
            }
        }

        /* Clean up any dead connections (its not safe to do a TAILQ_REMOVE in
           the middle of a TAILQ_FOREACH, and destroy_connection does indeed
           use TAILQ_REMOVE). */
        i = TAILQ_FIRST(&clients);
        while(i) {
            tmp = TAILQ_NEXT(i, qentry);

            if(i->disconnected) {
                my_ntop(&i->ip_addr, ipstr);

                if(!i->guildcard) {
                    debug(DBG_LOG, "Disconnecting unidentified client (%s)\n",
                          ipstr);
                }
                else {
                    debug(DBG_LOG, "Disconnecting guild card %" PRIu32
                          " (%s)\n", i->guildcard, ipstr);
                }

                destroy_connection(i);
            }

            i = tmp;
        }
    }
}

static int open_sock(int family, uint16_t port) {
    int sock = -1, val;
    struct sockaddr_in addr;
    struct sockaddr_in6 addr6;

    /* Create the socket and listen for connections. */
    sock = socket(family, SOCK_STREAM, IPPROTO_TCP);

    if(sock < 0) {
        perror("socket");
        return -1;
    }

    /* Set SO_REUSEADDR so we don't run into issues when we kill the login
       server bring it back up quickly... */
    val = 1;
    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(int))) {
        perror("setsockopt");
        /* We can ignore this error, pretty much... its just a convenience thing
           anyway... */
    }

    if(family == PF_INET) {
        memset(&addr, 0, sizeof(struct sockaddr_in));
        addr.sin_family = family;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if(bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in))) {
            perror("bind");
            close(sock);
            return -1;
        }

        if(listen(sock, 10)) {
            perror("listen");
            close(sock);
            return -1;
        }
    }
    else if(family == PF_INET6) {
        /* Since we create separate sockets for IPv4 and IPv6, make this one
           support ONLY IPv6. */
        val = 1;
        if(setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(int))) {
            perror("setsockopt IPV6_V6ONLY");
            close(sock);
            return -1;
        }

        memset(&addr6, 0, sizeof(struct sockaddr_in6));
        addr6.sin6_family = family;
        addr6.sin6_addr = in6addr_any;
        addr6.sin6_port = htons(port);

        if(bind(sock, (struct sockaddr *)&addr6, sizeof(struct sockaddr_in6))) {
            perror("bind");
            close(sock);
            return -1;
        }

        if(listen(sock, 10)) {
            perror("listen");
            close(sock);
            return -1;
        }
    }
    else {
        debug(DBG_ERROR, "Unknown socket family\n");
        close(sock);
        return -1;
    }

    return sock;
}

static void open_log(void) {
    FILE *dbgfp;

    dbgfp = fopen("logs/login_debug.log", "a");

    if(!dbgfp) {
        debug(DBG_ERROR, "Cannot open log file\n");
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    debug_set_file(dbgfp);
}

static void reopen_log(void) {
    FILE *dbgfp, *ofp;

    dbgfp = fopen("logs/login_debug.log", "a");

    if(!dbgfp) {
        /* Uhh... Welp, guess we'll try to continue writing to the old one,
           then... */
        debug(DBG_ERROR, "Cannot reopen log file\n");
        perror("fopen");
    }
    else {
        ofp = debug_set_file(dbgfp);
        fclose(ofp);
    }
}

static void sighup_hnd(int signum, siginfo_t *inf, void *ptr) {
    (void)signum;
    (void)inf;
    (void)ptr;
    reopen_log();
}

static void sigterm_hnd(int signum, siginfo_t *inf, void *ptr) {
    (void)signum;
    (void)inf;
    (void)ptr;
    shutting_down = 1;
}

static void sigusr1_hnd(int signum, siginfo_t *inf, void *ptr) {
    (void)signum;
    (void)inf;
    (void)ptr;
    shutting_down = 2;
}

/* Install any handlers for signals we care about */
static void install_signal_handlers() {
    struct sigaction sa;

    memset(&sa, 0, sizeof(struct sigaction));
    sigemptyset(&sa.sa_mask);

    /* Ignore SIGPIPEs */
    sa.sa_handler = SIG_IGN;

    if(sigaction(SIGPIPE, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

    /* Set up a SIGHUP handler to reopen the log file, if we do log rotation. */
    if(!dont_daemonize) {
        sigemptyset(&sa.sa_mask);
        sa.sa_handler = NULL;
        sa.sa_sigaction = &sighup_hnd;
        sa.sa_flags = SA_SIGINFO | SA_RESTART;

        if(sigaction(SIGHUP, &sa, NULL) < 0) {
            perror("sigaction");
            fprintf(stderr, "Can't set SIGHUP handler, log rotation may not"
                    "work.\n");
        }
    }

    /* Set up a SIGTERM handler to somewhat gracefully shutdown. */
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = NULL;
    sa.sa_sigaction = &sigterm_hnd;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;

    if(sigaction(SIGTERM, &sa, NULL) < 0) {
        perror("sigaction");
        fprintf(stderr, "Can't set SIGTERM handler.\n");
    }

    /* Set up a SIGUSR1 handler to restart... */
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = NULL;
    sa.sa_sigaction = &sigusr1_hnd;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;

    if(sigaction(SIGUSR1, &sa, NULL) < 0) {
        perror("sigaction");
        fprintf(stderr, "Can't set SIGUSR1 handler.\n");
    }
}

void cleanup_pidfile(void) {
    pidfile_remove(pf);
}

static int drop_privs(void) {
    struct passwd *pw;
    uid_t uid;
    gid_t gid;
    int gid_count = 0;
    gid_t *groups;

    /* Make sure we're actually root, otherwise some of this will fail. */
    if(getuid() && geteuid())
        return 0;

    /* Look for users. We're looking for the user "sylverant", generally. */
    if((pw = getpwnam(runas_user))) {
        uid = pw->pw_uid;
        gid = pw->pw_gid;
    }
    else {
        debug(DBG_ERROR, "Cannot find user \"%s\". Bailing out!\n", runas_user);
        return -1;
    }

    /* Change the pidfile's uid/gid now, before we drop privileges... */
    if(pf) {
        if(fchown(pidfile_fileno(pf), uid, gid)) {
            debug(DBG_WARN, "Cannot change pidfile owner: %s\n",
                  strerror(errno));
        }
    }

#ifdef HAVE_GETGROUPLIST
    /* Figure out what other groups the user is in... */
    getgrouplist(runas_user, gid, NULL, &gid_count);
    if(!(groups = malloc(gid_count * sizeof(gid_t)))) {
        perror("malloc");
        return -1;
    }

    if(getgrouplist(runas_user, gid, groups, &gid_count)) {
        perror("getgrouplist");
        free(groups);
        return -1;
    }

    if(setgroups(gid_count, groups)) {
        perror("setgroups");
        free(groups);
        return -1;
    }

    /* We're done with most of these, so clear this out now... */
    free(groups);
#else
    if(setgroups(1, &gid)) {
        perror("setgroups");
        return -1;
    }
#endif

    if(setgid(gid)) {
        perror("setgid");
        return -1;
    }

    if(setuid(uid)) {
        perror("setuid");
        return -1;
    }

    /* Make sure the privileges stick. */
    if(!getuid() || !geteuid()) {
        debug(DBG_ERROR, "Cannot set non-root privileges. Bailing out!\n");
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    int i, j;
    int dcsocks[NUM_DCSOCKS];
    int pcsocks[NUM_PCSOCKS];
    int gcsocks[NUM_GCSOCKS];
    int ep3socks[NUM_EP3SOCKS];
    int bbsocks[NUM_BBSOCKS];
    int xbsocks[NUM_XBSOCKS];
    int websocks[NUM_WEBSOCKS];
    char *initial_path;
    long size;
    pid_t op;

    parse_command_line(argc, argv);

    /* Save the initial path, so that if /restart is used we'll be starting from
       the same directory. */
    size = pathconf(".", _PC_PATH_MAX);
    if(!(initial_path = (char *)malloc(size))) {
        debug(DBG_WARN, "Out of memory, bailing out!\n");
    }
    else if(!getcwd(initial_path, size)) {
        debug(DBG_WARN, "Cannot save initial path, Restart may not work!\n");
    }

    load_config();

    if(!custom_dir)
        chdir(sylverant_directory);
    else
        chdir(custom_dir);

    if(!dont_daemonize) {
        /* Attempt to open and lock the pid file. */
        if(!pidfile_name) {
            char *pn = (char *)malloc(strlen(PID_DIR) + 32);
            sprintf(pn, "%s/login_server.pid", PID_DIR);
            pidfile_name = pn;
        }

        pf = pidfile_open(pidfile_name, 0660, &op);

        if(!pf) {
            if(errno == EEXIST) {
                debug(DBG_ERROR, "Login Server already running? (pid: %ld)\n",
                      (long)op);
                exit(EXIT_FAILURE);
            }

            debug(DBG_WARN, "Cannot create pidfile: %s!\n", strerror(errno));
        }
        else {
            atexit(&cleanup_pidfile);
        }

        if(daemon(1, 0)) {
            debug(DBG_ERROR, "Cannot daemonize\n");
            perror("daemon");
            exit(EXIT_FAILURE);
        }

        if(drop_privs())
            exit(EXIT_FAILURE);

        open_log();

        /* Write the pid file. */
        pidfile_write(pf);
    }
    else {
        if(drop_privs())
            exit(EXIT_FAILURE);
    }

restart:
    shutting_down = 0;
    load_config2();

    /* Init mini18n if we have it. */
    init_i18n();

    install_signal_handlers();

    debug(DBG_LOG, "Opening Dreamcast ports for connections.\n");

    for(i = 0; i < NUM_DCSOCKS; ++i) {
        dcsocks[i] = open_sock(dcports[i][0], dcports[i][1]);

        if(dcsocks[i] < 0) {
            sylverant_db_close(&conn);
            exit(EXIT_FAILURE);
        }
    }

    debug(DBG_LOG, "Opening PSO for PC ports for connections.\n");

    for(i = 0; i < NUM_PCSOCKS; ++i) {
        pcsocks[i] = open_sock(pcports[i][0], pcports[i][1]);

        if(pcsocks[i] < 0) {
            sylverant_db_close(&conn);
            exit(EXIT_FAILURE);
        }
    }

    debug(DBG_LOG, "Opening PSO for Gamecube ports for connections.\n");

    for(i = 0; i < NUM_GCSOCKS; ++i) {
        gcsocks[i] = open_sock(gcports[i][0], gcports[i][1]);

        if(gcsocks[i] < 0) {
            sylverant_db_close(&conn);
            exit(EXIT_FAILURE);
        }
    }

    debug(DBG_LOG, "Opening PSO Episode 3 ports for connections.\n");

    for(i = 0; i < NUM_EP3SOCKS; ++i) {
        ep3socks[i] = open_sock(ep3ports[i][0], ep3ports[i][1]);

        if(ep3socks[i] < 0) {
            sylverant_db_close(&conn);
            exit(EXIT_FAILURE);
        }
    }

    debug(DBG_LOG, "Opening Blue Burst ports for connections.\n");

    for(i = 0; i < NUM_BBSOCKS; ++i) {
        bbsocks[i] = open_sock(bbports[i][0], bbports[i][1]);

        if(bbsocks[i] < 0) {
            sylverant_db_close(&conn);
            exit(EXIT_FAILURE);
        }
    }

    debug(DBG_LOG, "Opening Xbox ports for connections.\n");

    for(i = 0; i < NUM_XBSOCKS; ++i) {
        xbsocks[i] = open_sock(xbports[i][0], xbports[i][1]);

        if(xbsocks[i] < 0) {
            sylverant_db_close(&conn);
            exit(EXIT_FAILURE);
        }
    }

    debug(DBG_LOG, "Opening Web access ports for connections.\n");

    for(i = 0; i < NUM_WEBSOCKS; ++i) {
        websocks[i] = open_sock(webports[i][0], webports[i][1]);

        if(websocks[i] < 0) {
            sylverant_db_close(&conn);
            exit(EXIT_FAILURE);
        }
    }

    /* Run the login server. */
    run_server(dcsocks, pcsocks, gcsocks, websocks, ep3socks, bbsocks, xbsocks);

    /* Clean up. */
    for(i = 0; i < NUM_DCSOCKS; ++i) {
        close(dcsocks[i]);
    }

    for(i = 0; i < NUM_PCSOCKS; ++i) {
        close(pcsocks[i]);
    }

    for(i = 0; i < NUM_GCSOCKS; ++i) {
        close(gcsocks[i]);
    }

    for(i = 0; i < NUM_EP3SOCKS; ++i) {
        close(ep3socks[i]);
    }

    for(i = 0; i < NUM_BBSOCKS; ++i) {
        close(bbsocks[i]);
    }

    for(i = 0; i < NUM_XBSOCKS; ++i) {
        close(xbsocks[i]);
    }

    for(i = 0; i < NUM_WEBSOCKS; ++i) {
        close(websocks[i]);
    }

    sylverant_db_close(&conn);

    for(i = 0; i < CLIENT_TYPE_COUNT; ++i) {
        for(j = 0; j < CLIENT_LANG_COUNT; ++j) {
            sylverant_quests_destroy(&qlist[i][j]);
        }
    }

    patch_list_free(patches_v2);
    patches_v2 = NULL;

    sylverant_free_config(cfg);
	cleanup_i18n();

    /* Restart if we're supposed to be doing so. */
    if(shutting_down == 2) {
        load_config();
        goto restart;
    }

    free(initial_path);

    return 0;
}
