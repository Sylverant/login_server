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
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <netdb.h>
#include <unistd.h>
#include <ctype.h>
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

#include "login.h"
#include "login_packets.h"

#ifndef ENABLE_IPV6
#define NUM_DCSOCKS  2
#define NUM_PCSOCKS  1
#define NUM_GCSOCKS  3
#define NUM_EP3SOCKS 3
#define NUM_WEBSOCKS 1
#define NUM_BBSOCKS  2
#else
#define NUM_DCSOCKS  4
#define NUM_PCSOCKS  2
#define NUM_GCSOCKS  6
#define NUM_EP3SOCKS 6
#define NUM_WEBSOCKS 2
#define NUM_BBSOCKS  4
#endif

static const int dcports[NUM_DCSOCKS][2] = {
    { AF_INET , 9200 },
    { AF_INET , 9201 },
#ifdef ENABLE_IPV6
    { AF_INET6, 9200 },
    { AF_INET6, 9201 }
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
    { AF_INET , 9000 },
    { AF_INET , 9001 },
#ifdef ENABLE_IPV6
    { AF_INET6, 9100 },
    { AF_INET6, 9000 },
    { AF_INET6, 9001 }
#endif
};

static const int ep3ports[NUM_EP3SOCKS][2] = {
    { AF_INET , 9103 },
    { AF_INET , 9003 },
    { AF_INET , 9203 },
#ifdef ENABLE_IPV6
    { AF_INET6, 9103 },
    { AF_INET6, 9003 },
    { AF_INET6, 9203 }
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

/* Stuff read from the config files */
sylverant_dbconn_t conn;
sylverant_config_t *cfg;
sylverant_limits_t *limits = NULL;

sylverant_quest_list_t qlist[CLIENT_TYPE_COUNT][CLIENT_LANG_COUNT];

static int dont_daemonize = 0;

/* Print information about this program to stdout. */
static void print_program_info() {
    printf("Sylverant Login Server version %s\n", VERSION);
    printf("Copyright (C) 2009, 2010, 2011 Lawrence Sebald\n\n");
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
           "--nodaemon      Don't daemonize\n"
           "--help          Print this help and exit\n\n"
           "Note that if more than one verbosity level is specified, the last\n"
           "one specified will be used. The default is --verbose.\n", bin);
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
        else if(!strcmp(argv[i], "--nodaemon")) {
            dont_daemonize = 1;
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
    if(sylverant_read_config(&cfg)) {
        debug(DBG_ERROR, "Cannot load configuration!\n");
        exit(EXIT_FAILURE);
    }

    /* Attempt to read each quests file... */
    read_quests();

    /* Attempt to read the legit items list */
    if(cfg->limits_file && cfg->limits_file[0]) {
        if(sylverant_read_limits(cfg->limits_file, &limits)) {
            debug(DBG_WARN, "Cannot read specified limits file\n");
        }
    }

    /* Read the Blue Burst param data */
    if(load_param_data()) {
        exit(EXIT_FAILURE);
    }

    if(load_bb_char_data()) {
        exit(EXIT_FAILURE);
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

    if(sylverant_db_query(&conn, query)) {
        return -1;
    }

    if(!(result = sylverant_db_result_store(&conn))) {
        return -2;
    }

    if(!(row = sylverant_db_result_fetch(result))) {
        return -3;
    }

    /* Grab the data from the row */
    if(c->type != CLIENT_TYPE_BB_CHARACTER) {
        port = (uint16_t)strtoul(row[1], NULL, 0) + c->type;
    }
    else {
        port = (uint16_t)strtoul(row[1], NULL, 0) + 4;
    }

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

static const void *my_ntop(struct sockaddr_storage *addr,
                           char str[INET6_ADDRSTRLEN]) {
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
                       int ep3socks[NUM_EP3SOCKS], int bbsocks[NUM_BBSOCKS]) {
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
                    debug(DBG_LOG, "Accepted Dreamcast connection from %s\n",
                          ipstr);

                    if(!create_connection(asock, CLIENT_TYPE_DC,addr_p, len)) {
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
                    debug(DBG_LOG, "Accepted PC connection from %s\n",
                          ipstr);

                    if(!create_connection(asock, CLIENT_TYPE_PC, addr_p, len)) {
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
                    debug(DBG_LOG, "Accepted Gamecube connection from %s\n",
                          ipstr);

                    if(!create_connection(asock, CLIENT_TYPE_GC, addr_p, len)) {
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
                    debug(DBG_LOG, "Accepted Episode 3 connection from %s\n",
                          ipstr);

                    if(!create_connection(asock, CLIENT_TYPE_EP3, addr_p,
                                          len)) {
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
                    debug(DBG_LOG, "Accepted Blue Burst connection from %s\n",
                          ipstr);

                    if(j & 1) {
                        type = CLIENT_TYPE_BB_CHARACTER;
                    }
                    else {
                        type = CLIENT_TYPE_BB_LOGIN;
                    }

                    if(!create_connection(asock, type, addr_p, len)) {
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
        addr.sin_family = family;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);
        memset(addr.sin_zero, 0, 8);

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

static void open_log() {
    FILE *dbgfp;

    dbgfp = fopen("logs/login_debug.log", "a");

    if(!dbgfp) {
        debug(DBG_ERROR, "Cannot open log file\n");
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    debug_set_file(dbgfp);
}

int main(int argc, char *argv[]) {
    int i, j;
    int dcsocks[NUM_DCSOCKS];
    int pcsocks[NUM_PCSOCKS];
    int gcsocks[NUM_GCSOCKS];
    int ep3socks[NUM_EP3SOCKS];
    int bbsocks[NUM_BBSOCKS];
    int websocks[NUM_WEBSOCKS];

    chdir(sylverant_directory);

    parse_command_line(argc, argv);

    /* If we're supposed to daemonize, do it now. */
    if(!dont_daemonize) {
        open_log();

        if(daemon(1, 0)) {
            debug(DBG_ERROR, "Cannot daemonize\n");
            perror("daemon");
            exit(EXIT_FAILURE);
        }
    }

    load_config();

    /* Init mini18n if we have it. */
    init_i18n();

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

    debug(DBG_LOG, "Opening Web access ports for connections.\n");

    for(i = 0; i < NUM_WEBSOCKS; ++i) {
        websocks[i] = open_sock(webports[i][0], webports[i][1]);

        if(websocks[i] < 0) {
            sylverant_db_close(&conn);
            exit(EXIT_FAILURE);
        }
    }

    /* Run the login server. */
    run_server(dcsocks, pcsocks, gcsocks, websocks, ep3socks, bbsocks);

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

    for(i = 0; i < NUM_WEBSOCKS; ++i) {
        close(websocks[i]);
    }

    sylverant_db_close(&conn);

    for(i = 0; i < CLIENT_TYPE_COUNT; ++i) {
        for(j = 0; j < CLIENT_LANG_COUNT; ++j) {
            sylverant_quests_destroy(&qlist[i][j]);
        }
    }

    sylverant_free_config(cfg);
	cleanup_i18n();

    return 0;
}
