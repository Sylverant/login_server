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
#include <sylverant/characters.h>
#include <sylverant/mtwist.h>
#include <sylverant/debug.h>
#include <sylverant/quest.h>

#include "login.h"
#include "login_packets.h"

#define VERSION "0.1.0"

/* Stuff read from the config files */
sylverant_dbconn_t conn;
sylverant_config_t cfg;
sylverant_quest_list_t qlist;

in_addr_t local_addr;
in_addr_t netmask;

/* Print information about this program to stdout. */
static void print_program_info() {
    printf("Sylverant Login Server version %s\n", VERSION);
    printf("Copyright (C) 2009 Lawrence Sebald\n\n");
    printf("This program is free software: you can redistribute it and/or\n"
           "modify it under the terms of the GNU General Public License\n"
           "version 3 as published by the Free Software Foundation.\n\n"
           "This program is distributed in the hope that it will be useful,\n"
           "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
           "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
           "GNU General Public License for more details.\n\n"
           "You should have received a copy of the GNU General Public License\n"
           "along with this program.  If not, see "
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
            exit(0);
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
        else if(!strcmp(argv[i], "--help")) {
            print_help(argv[0]);
            exit(0);
        }
        else {
            printf("Illegal command line argument: %s\n", argv[i]);
            print_help(argv[0]);
            exit(1);
        }
    }
}

/* Load the configuration file and print out parameters with DBG_LOG. */
static void load_config() {
    if(sylverant_read_config(&cfg)) {
        debug(DBG_ERROR, "Cannot load configuration!\n");
        exit(1);
    }

    if(cfg.quests_file[0] && sylverant_quests_read(cfg.quests_file, &qlist)) {
        debug(DBG_ERROR, "Cannot load offline quests list!\n");
        exit(1);
    }

    debug(DBG_LOG, "Connecting to the database...\n");

    if(sylverant_db_open(&cfg.dbcfg, &conn)) {
        debug(DBG_ERROR, "Can't connect to the database\n");
        exit(1);
    }
}

int ship_transfer(login_client_t *c, uint32_t shipid) {
    char query[256];
    void *result;
    char **row;
    in_addr_t ip, int_ip;
    uint16_t port;

    /* Query the database for the ship in question */
    sprintf(query, "SELECT ip, port, int_ip FROM online_ships WHERE "
            "ship_id='%lu'", (unsigned long)shipid);

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
    ip = htonl((in_addr_t)strtoul(row[0], NULL, 0));
    port = (uint16_t)strtoul(row[1], NULL, 0);
    int_ip = htonl((in_addr_t)strtoul(row[2], NULL, 0));

    /* Figure out which address we need to send the client. */
    if(c->ip_addr == ip) {
        /* The client and the ship are connecting from the same
           address, this one is obvious. */
        ip = int_ip;
    }
    else if(ip == cfg.override_ip &&
            (c->ip_addr & netmask) == (local_addr & netmask)) {
        /* The destination and the source are on the same
           network, and the client is on the same network as the
           source, thus the client must be on the same network
           as the destination, send the internal address. */
        ip = int_ip;
    }

    /* They should be on different networks if we get here,
       send the external IP. */

    /* If the client is on the PC version, connect to the PC version port,
       rather than the one for the DC version. */
    if(c->type == CLIENT_TYPE_PC) {
        ++port;
    }
    else if(c->type == CLIENT_TYPE_GC) {
        port += 2;
    }

    return send_redirect(c, ip, port);
}

/* Fetch the local address and netmask of the host. */
static int get_ip_info() {
    int rv;
    struct addrinfo hints, *servinfo;
    struct sockaddr_in *addr;
    char hostname[256];
    struct ifaddrs *ifaddr, *ifa;

    /* Get the host name for passing to getaddrinfo */
    gethostname(hostname, 255);

    /* Clear the hints out, we'll fill in what we want below. */
    memset(&hints, 0, sizeof(struct addrinfo));

    /* We want a IPv4 address... */
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    /* Query the OS for what we want. */
    rv = getaddrinfo(hostname, NULL, &hints, &servinfo);

    if(rv) {
        debug(DBG_ERROR, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    /* For now, assume we want the first one. */
    local_addr = ((struct sockaddr_in *)servinfo->ai_addr)->sin_addr.s_addr;

    freeaddrinfo(servinfo);

    /* We've got the IP address, now attempt to get the netmask associated with
       that IP. */
    if(getifaddrs(&ifaddr)) {
        perror("getifaddrs");
        return -2;
    }

    /* Look through the list for the interface we want. */
    for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if(ifa->ifa_addr->sa_family == AF_INET) {
            addr = (struct sockaddr_in *)ifa->ifa_addr;

            if(addr->sin_addr.s_addr == local_addr) {
                addr = (struct sockaddr_in *)ifa->ifa_netmask;
                netmask = addr->sin_addr.s_addr;
                break;
            }
        }
    }

    /* Clean up what was allocated by getifaddrs. */
    freeifaddrs(ifaddr);

    return 0;
}

static void run_server(int dcsock, int pcsock, int gcsock) {
    fd_set readfds, writefds;
    struct timeval timeout;
    int nfds;
    socklen_t len;
    struct sockaddr_in addr;
    int asock;
    login_client_t *i, *tmp;
    ssize_t sent;

    for(;;) {        
        /* Clear the fd_sets so we can use them. */
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        timeout.tv_sec = 9001;
        timeout.tv_usec = 0;

        /* Fill the sockets into the fd_set so we can use select below. */
        TAILQ_FOREACH(i, &clients, qentry) {
            FD_SET(i->sock, &readfds);

            /* Only add to the writing fd_set if we have something to write. */
            if(i->sendbuf_cur) {
                FD_SET(i->sock, &writefds);
            }

            nfds = nfds > i->sock ? nfds : i->sock;
        }

        /* Add the listening sockets for incoming connections to the fd_set. */
        FD_SET(dcsock, &readfds);
        nfds = nfds > dcsock ? nfds : dcsock;
        FD_SET(pcsock, &readfds);
        nfds = nfds > pcsock ? nfds : pcsock;
        FD_SET(gcsock, &readfds);
        nfds = nfds > pcsock ? nfds : gcsock;

        if(select(nfds + 1, &readfds, &writefds, NULL, &timeout) > 0) {
            /* See if we have an incoming client. */
            if(FD_ISSET(dcsock, &readfds)) {
                len = sizeof(struct sockaddr_in);

                if((asock = accept(dcsock, (struct sockaddr *)&addr,
                                   &len)) < 0) {
                    perror("accept");
                }

                debug(DBG_LOG, "Accepted Dreamcast connection from %s\n",
                      inet_ntoa(addr.sin_addr));

                if(create_connection(asock, addr.sin_addr.s_addr,
                                     CLIENT_TYPE_DC) == NULL) {
                    close(asock);
                }
            }

            if(FD_ISSET(pcsock, &readfds)) {
                len = sizeof(struct sockaddr_in);

                if((asock = accept(pcsock, (struct sockaddr *)&addr,
                                   &len)) < 0) {
                    perror("accept");
                }

                debug(DBG_LOG, "Accepted PC connection from %s\n",
                      inet_ntoa(addr.sin_addr));

                if(create_connection(asock, addr.sin_addr.s_addr,
                                     CLIENT_TYPE_PC) == NULL) {
                    close(asock);
                }
            }

            if(FD_ISSET(gcsock, &readfds)) {
                len = sizeof(struct sockaddr_in);

                if((asock = accept(gcsock, (struct sockaddr *)&addr,
                                   &len)) < 0) {
                    perror("accept");
                }

                debug(DBG_LOG, "Accepted Gamecube connection from %s\n",
                      inet_ntoa(addr.sin_addr));

                if(create_connection(asock, addr.sin_addr.s_addr,
                                     CLIENT_TYPE_GC) == NULL) {
                    close(asock);
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

static int open_sock(uint16_t port) {
    int sock = -1;
    struct sockaddr_in addr;

    /* Create the socket and listen for connections. */
    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    if(sock < 0) {
        perror("socket");
        sylverant_db_close(&conn);
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    memset(addr.sin_zero, 0, 8);

    if(bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in))) {
        perror("bind");
        sylverant_db_close(&conn);
        close(sock);
        return -1;
    }

    if(listen(sock, 10)) {
        perror("listen");
        sylverant_db_close(&conn);
        close(sock);
        return -1;
    }

    return sock;
}

int main(int argc, char *argv[]) {
    int dcsock, pcsock, gcsock;

    chdir(SYLVERANT_DIRECTORY);

    /* Parse the command line and read our configuration. */
    parse_command_line(argc, argv);
    load_config();

    get_ip_info();

    debug(DBG_LOG, "Opening Dreamcast port (9200) for connections.\n");
    dcsock = open_sock(9200);

    if(dcsock < 0) {
        exit(EXIT_FAILURE);
    }

    debug(DBG_LOG, "Opening PC port (9300) for connections.\n");
    pcsock = open_sock(9300);

    if(pcsock < 0) {
        exit(EXIT_FAILURE);
    }

    debug(DBG_LOG, "Opening GC port (9100) for connections.\n");
    gcsock = open_sock(9100);

    if(gcsock < 0) {
        exit(EXIT_FAILURE);
    }

    /* Run the login server. */
    run_server(dcsock, pcsock, gcsock);

    /* Clean up. */
    close(dcsock);
    close(pcsock);
    close(gcsock);
    sylverant_db_close(&conn);
    sylverant_quests_destroy(&qlist);

    return 0;
}
