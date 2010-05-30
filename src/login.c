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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include <sylverant/debug.h>
#include <sylverant/encryption.h>
#include <sylverant/mtwist.h>

#include "login.h"
#include "login_packets.h"

/* Storage for our client list. */
struct client_queue clients = TAILQ_HEAD_INITIALIZER(clients);

uint8_t recvbuf[65536];

/* Create a new connection, storing it in the list of clients. */
login_client_t *create_connection(int sock, in_addr_t ip, int type) {
    login_client_t *rv = (login_client_t *)malloc(sizeof(login_client_t));
    uint32_t client_seed_dc, server_seed_dc;

    if(!rv) {
        perror("malloc");
        return NULL;
    }

    memset(rv, 0, sizeof(login_client_t));

    /* Store basic parameters in the client structure. */
    rv->sock = sock;
    rv->ip_addr = ip;
    rv->type = type;

    switch(type) {
        case CLIENT_TYPE_DC:
        case CLIENT_TYPE_PC:
            /* Generate the encryption keys for the client and server. */
            rv->client_key = client_seed_dc = genrand_int32();
            rv->server_key = server_seed_dc = genrand_int32();

            CRYPT_CreateKeys(&rv->server_cipher, &server_seed_dc, CRYPT_PC);
            CRYPT_CreateKeys(&rv->client_cipher, &client_seed_dc, CRYPT_PC);
            rv->hdr_size = 4;

            /* Send the client the welcome packet, or die trying. */
            if(send_dc_welcome(rv, server_seed_dc, client_seed_dc)) {
                close(sock);
                free(rv);
                return NULL;
            }

            break;

        case CLIENT_TYPE_GC:
            /* Generate the encryption keys for the client and server. */
            rv->client_key = client_seed_dc = genrand_int32();
            rv->server_key = server_seed_dc = genrand_int32();

            CRYPT_CreateKeys(&rv->server_cipher, &server_seed_dc,
                             CRYPT_GAMECUBE);
            CRYPT_CreateKeys(&rv->client_cipher, &client_seed_dc,
                             CRYPT_GAMECUBE);
            rv->hdr_size = 4;

            /* Send the client the welcome packet, or die trying. */
            if(send_dc_welcome(rv, server_seed_dc, client_seed_dc)) {
                close(sock);
                free(rv);
                return NULL;
            }

            break;
    }

    /* Insert it at the end of our list, and we're done. */
    TAILQ_INSERT_TAIL(&clients, rv, qentry);
    return rv;
}

/* Destroy a connection, closing the socket and removing it from the list. */
void destroy_connection(login_client_t *c) {
    TAILQ_REMOVE(&clients, c, qentry);

    if(c->gc_data) {
        free(c->gc_data);
    }

    if(c->sock >= 0) {
        close(c->sock);
    }

    if(c->recvbuf) {
        free(c->recvbuf);
    }

    if(c->sendbuf) {
        free(c->sendbuf);
    }

    free(c);
}

/* Read data from a client that is connected to any port. */
int read_from_client(login_client_t *c) {
    ssize_t sz;
    uint16_t pkt_sz = 0;
    int rv = 0;
    unsigned char *rbp;
    void *tmp;

    /* If we've got anything buffered, copy it out to the main buffer to make
       the rest of this a bit easier. */
    if(c->recvbuf_cur) {
        memcpy(recvbuf, c->recvbuf, c->recvbuf_cur);
    }

    /* Attempt to read, and if we don't get anything, punt. */
    if((sz = recv(c->sock, recvbuf + c->recvbuf_cur, 65536 - c->recvbuf_cur,
                  0)) <= 0) {
        if(sz == -1) {
            perror("recv");
        }

        return -1;
    }

    sz += c->recvbuf_cur;
    c->recvbuf_cur = 0;
    rbp = recvbuf;

    /* Make sure the client is actually a DC client, since it could be a PSOGC
       client using the EU version @ 60Hz. */
    if(c->type == CLIENT_TYPE_DC && !c->got_first && sz >= 4) {
        memcpy(&c->pkt, rbp, 4);
        CRYPT_CryptData(&c->client_cipher, &c->pkt, 4, 0);

        /* Check if its one of the two packets we're expecting (0x90 for v1,
           0x9A for v2). Hopefully there's no way to get these particular
           combinations with the GC encryption... */
        if(c->pkt.dc.pkt_type == 0x90 && c->pkt.dc.flags == 0 &&
           LE16(c->pkt.dc.pkt_len) == 0x0028) {
            c->got_first = 1;
        }
        else if(c->pkt.dc.pkt_type == 0x9A && c->pkt.dc.flags == 0 &&
                LE16(c->pkt.dc.pkt_len) == 0x00E0) {
            c->got_first = 1;
        }
        /* If we end up in here, its pretty much gotta be a Gamecube client, or
           someone messing with us. */
        else {
            c->type = CLIENT_TYPE_GC;
            CRYPT_CreateKeys(&c->client_cipher, &c->client_key, CRYPT_GAMECUBE);
            CRYPT_CreateKeys(&c->server_cipher, &c->server_key, CRYPT_GAMECUBE);
            memset(&c->pkt, 0, 4);
        }
    }

    /* As long as what we have is long enough, decrypt it. */
    if(sz >= c->hdr_size) {
        while(sz >= c->hdr_size && rv == 0) {
            /* Decrypt the packet header so we know what exactly we're looking
               for, in terms of packet length. */
            if(!c->hdr_read) {
                memcpy(&c->pkt, rbp, c->hdr_size);
                CRYPT_CryptData(&c->client_cipher, &c->pkt, c->hdr_size, 0);
                c->hdr_read = 1;
            }

            switch(c->type) {
                case CLIENT_TYPE_DC:
                case CLIENT_TYPE_GC:
                    pkt_sz = LE16(c->pkt.dc.pkt_len);
                    break;

                case CLIENT_TYPE_PC:
                    pkt_sz = LE16(c->pkt.pc.pkt_len);
                    break;
            }

            /* We'll always need a multiple of 8 or 4 (depending on the type of
               the client) bytes. */
            if(pkt_sz & (c->hdr_size - 1)) {
                pkt_sz = (pkt_sz & (0x10000 - c->hdr_size)) + c->hdr_size;
            }

            /* Do we have the whole packet? */
            if(sz >= (ssize_t)pkt_sz) {
                /* Yes, we do, decrypt it. */
                CRYPT_CryptData(&c->client_cipher, rbp + c->hdr_size,
                                pkt_sz - c->hdr_size, 0);
                memcpy(rbp, &c->pkt, c->hdr_size);

                /* Pass it onto the correct handler. */
                switch(c->type) {
                    case CLIENT_TYPE_DC:
                    case CLIENT_TYPE_PC:
                    case CLIENT_TYPE_GC:
                        rv = process_dclogin_packet(c, rbp);
                        break;
                }

                rbp += pkt_sz;
                sz -= pkt_sz;
                
                c->hdr_read = 0;
            }
            else {
                /* Nope, we're missing part, break out of the loop, and buffer
                   the remaining data. */
                break;
            }
        }
    }

    /* If we've still got something left here, buffer it for the next pass. */
    if(sz) {
        /* Reallocate the recvbuf for the client if its too small. */
        if(c->recvbuf_size < sz) {
            tmp = realloc(c->recvbuf, sz);

            if(!tmp) {
                perror("realloc");
                return -1;
            }

            c->recvbuf = (unsigned char *)tmp;
            c->recvbuf_size = sz;
        }

        memcpy(c->recvbuf, rbp, sz);
        c->recvbuf_cur = sz;
    }
    else {
        /* Free the buffer, if we've got nothing in it. */
        free(c->recvbuf);
        c->recvbuf = NULL;
        c->recvbuf_size = 0;
    }

    return rv;
}
