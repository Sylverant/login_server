/*
    Sylverant Login Server
    Copyright (C) 2009, 2010, 2011, 2012 Lawrence Sebald

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
#include <errno.h>
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

/* Create a new connection, storing it in the list of clients. */
login_client_t *create_connection(int sock, int type, struct sockaddr *ip,
                                  socklen_t size) {
    login_client_t *rv = (login_client_t *)malloc(sizeof(login_client_t));
    uint32_t client_seed_dc, server_seed_dc;
    uint8_t client_seed_bb[48], server_seed_bb[48];
    int i;

    if(!rv) {
        perror("malloc");
        return NULL;
    }

    memset(rv, 0, sizeof(login_client_t));

    /* Store basic parameters in the client structure. */
    rv->sock = sock;
    rv->type = type;
    memcpy(&rv->ip_addr, ip, size);

    /* Is the user on IPv6? */
    if(ip->sa_family == AF_INET6) {
        rv->is_ipv6 = 1;
    }

    switch(type) {
        case CLIENT_TYPE_DC:
        case CLIENT_TYPE_PC:
            /* Generate the encryption keys for the client and server. */
            rv->client_key = client_seed_dc = genrand_int32();
            rv->server_key = server_seed_dc = genrand_int32();

            CRYPT_CreateKeys(&rv->server_cipher, &server_seed_dc, CRYPT_PC);
            CRYPT_CreateKeys(&rv->client_cipher, &client_seed_dc, CRYPT_PC);

            /* Send the client the welcome packet, or die trying. */
            if(send_dc_welcome(rv, server_seed_dc, client_seed_dc)) {
                close(sock);
                free(rv);
                return NULL;
            }

            break;

        case CLIENT_TYPE_GC:
            /* Send a selective redirect packet to get any PSOPC users to
               connect to the right port. We can safely do the rest here either
               way, because PSOPC users should disconnect immediately on getting
               this packet (and connect to port 9300 instead). */
            if(send_selective_redirect(rv)) {
                close(sock);
                free(rv);
                return NULL;
            }

            /* Fall through... */

        case CLIENT_TYPE_EP3:
            /* Generate the encryption keys for the client and server. */
            rv->client_key = client_seed_dc = genrand_int32();
            rv->server_key = server_seed_dc = genrand_int32();

            CRYPT_CreateKeys(&rv->server_cipher, &server_seed_dc,
                             CRYPT_GAMECUBE);
            CRYPT_CreateKeys(&rv->client_cipher, &client_seed_dc,
                             CRYPT_GAMECUBE);

            /* Send the client the welcome packet, or die trying. */
            if(send_dc_welcome(rv, server_seed_dc, client_seed_dc)) {
                close(sock);
                free(rv);
                return NULL;
            }

            break;

        case CLIENT_TYPE_BB_LOGIN:
        case CLIENT_TYPE_BB_CHARACTER:
            /* Generate the encryption keys for the client and server. */
            for(i = 0; i < 48; i += 4) {
                client_seed_dc = genrand_int32();
                server_seed_dc = genrand_int32();

                client_seed_bb[i + 0] = (uint8_t)(client_seed_dc >>  0);
                client_seed_bb[i + 1] = (uint8_t)(client_seed_dc >>  8);
                client_seed_bb[i + 2] = (uint8_t)(client_seed_dc >> 16);
                client_seed_bb[i + 3] = (uint8_t)(client_seed_dc >> 24);
                server_seed_bb[i + 0] = (uint8_t)(server_seed_dc >>  0);
                server_seed_bb[i + 1] = (uint8_t)(server_seed_dc >>  8);
                server_seed_bb[i + 2] = (uint8_t)(server_seed_dc >> 16);
                server_seed_bb[i + 3] = (uint8_t)(server_seed_dc >> 24);
            }

            CRYPT_CreateKeys(&rv->server_cipher, server_seed_bb,
                             CRYPT_BLUEBURST);
            CRYPT_CreateKeys(&rv->client_cipher, client_seed_bb,
                             CRYPT_BLUEBURST);

            /* Send the client the welcome packet, or die trying. */
            if(send_bb_welcome(rv, server_seed_bb, client_seed_bb)) {
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
    int pkt_sz = c->pkt_sz, pkt_cur = c->pkt_cur, rv;
    pkt_header_t tmp_hdr;
    dc_pkt_hdr_t dc;
    const int hs = hdr_sizes[c->type], hsm = 0x10000 - hs;

    if(!c->recvbuf) {
        /* Read in a new header... */
        if((sz = recv(c->sock, &tmp_hdr, hs, 0)) < hs) {
            /* If we have an error, disconnect the client */
            if(sz <= 0) {
                if(sz == -1)
                    debug(DBG_WARN, "recv: %s\n", strerror(errno));
                return -1;
            }

            /* Otherwise, its just not all there yet, so punt for now... */
            if(!(c->recvbuf = (unsigned char *)malloc(hs))) {
                debug(DBG_WARN, "malloc: %s\n", strerror(errno));
                return -1;
            }

            /* Copy over what we did get */
            memcpy(c->recvbuf, &tmp_hdr, sz);
            c->pkt_cur = sz;
            return 0;
        }
    }
    /* This case should be exceedingly rare... */
    else if(!pkt_sz) {
        /* Try to finish reading the header */
        if((sz = recv(c->sock, c->recvbuf + pkt_cur, hs - pkt_cur,
                      0)) < hs - pkt_cur) {
            /* If we have an error, disconnect the client */
            if(sz <= 0) {
                if(sz == -1)
                    debug(DBG_WARN, "recv: %s\n", strerror(errno));
                return -1;
            }

            /* Update the pointer... */
            c->pkt_cur += sz;
            return 0;
        }

        /* We now have the whole header, so ready things for that */
        memcpy(&tmp_hdr, c->recvbuf, hs);
        c->pkt_cur = 0;
        free(c->recvbuf);
    }

    /* If we haven't decrypted the packet header, do so now, since we definitely
       have the whole thing at this point. */
    if(!pkt_sz) {
        /* If the client says its DC, make sure it actually is, since it could
           be a PSOGC client using the EU version. */
        if(c->type == CLIENT_TYPE_DC && !c->got_first) {
            dc = tmp_hdr.dc;
            CRYPT_CryptData(&c->client_cipher, &dc, 4, 0);

            /* Check if its one of the two packets we're expecting (0x90 for v1,
               0x9A for v2). Hopefully there's no way to get these particular
               combinations with the GC encryption... */
            if(dc.pkt_type == 0x90 && dc.flags == 0 &&
               (LE16(dc.pkt_len) == 0x0028 || LE16(dc.pkt_len) == 0x0026)) {
                c->got_first = 1;
                tmp_hdr.dc = dc;
            }
            else if(dc.pkt_type == 0x9A && dc.flags == 0 &&
                    LE16(dc.pkt_len) == 0x00E0) {
                c->got_first = 1;
                tmp_hdr.dc = dc;
            }
            /* If we end up in here, its pretty much gotta be a Gamecube client,
               or someone messing with us. */
            else {
                c->type = CLIENT_TYPE_GC;
                CRYPT_CreateKeys(&c->client_cipher, &c->client_key,
                                 CRYPT_GAMECUBE);
                CRYPT_CreateKeys(&c->server_cipher, &c->server_key,
                                 CRYPT_GAMECUBE);
                CRYPT_CryptData(&c->client_cipher, &tmp_hdr, hs, 0);
            }
        }
        else {
            CRYPT_CryptData(&c->client_cipher, &tmp_hdr, hs, 0);
        }

        switch(c->type) {
            case CLIENT_TYPE_DC:
            case CLIENT_TYPE_GC:
            case CLIENT_TYPE_EP3:
                pkt_sz = LE16(tmp_hdr.dc.pkt_len);
                break;

            case CLIENT_TYPE_PC:
                pkt_sz = LE16(tmp_hdr.pc.pkt_len);
                break;

            case CLIENT_TYPE_BB_LOGIN:
            case CLIENT_TYPE_BB_CHARACTER:
                pkt_sz = LE16(tmp_hdr.bb.pkt_len);
                break;
        }

        sz = (pkt_sz & (hs - 1)) ? (pkt_sz & hsm) + hs : pkt_sz;

        /* Allocate space for the packet */
        if(!(c->recvbuf = (unsigned char *)malloc(sz)))  {
            debug(DBG_WARN, "malloc: %s\n", strerror(errno));
            return -1;
        }

        /* Bah, stupid buggy versions of PSO handling this case in two very
           different ways... When JPv1 sends a packet with a size not divisible
           by the encryption word-size, it expects the server to pad the packet.
           When Blue Burst does it, it sends padding itself. God only knows what
           the other versions would do (but thankfully, they don't appear to do
           any of that broken behavior, at least not that I've seen). */
        if(c->type == CLIENT_TYPE_DC)
            c->pkt_sz = pkt_sz;
        else
            c->pkt_sz = sz;

        memcpy(c->recvbuf, &tmp_hdr, hs);
        c->pkt_cur = hs;

        /* If this packet is only a header, short-circuit and process it now. */
        if(pkt_sz == hs)
            goto process;

        /* Return now, so we don't end up sleeping in the recv below. */
        return 0;
    }

    /* See if the rest of the packet is here... */
    if((sz = recv(c->sock, c->recvbuf + pkt_cur, pkt_sz - pkt_cur,
                  0)) < pkt_sz - pkt_cur) {
        if(sz <= 0) {
            if(sz == -1)
                debug(DBG_WARN, "recv: %s\n", strerror(errno));
            return -1;
        }

        /* Didn't get it all, return for now... */
        c->pkt_cur += sz;
        return 0;
    }

    /* If we get this far, we've got the whole packet, so process it. */
    CRYPT_CryptData(&c->client_cipher, c->recvbuf + hs, pkt_sz - hs, 0);

process:
    /* Pass it onto the correct handler. */
    switch(c->type) {
        case CLIENT_TYPE_DC:
        case CLIENT_TYPE_PC:
        case CLIENT_TYPE_GC:
        case CLIENT_TYPE_EP3:
            rv = process_dclogin_packet(c, c->recvbuf);
            break;

        case CLIENT_TYPE_BB_LOGIN:
            rv = process_bblogin_packet(c, c->recvbuf);
            break;

        case CLIENT_TYPE_BB_CHARACTER:
            rv = process_bbcharacter_packet(c, c->recvbuf);
            break;
    }

    free(c->recvbuf);
    c->recvbuf = NULL;
    c->pkt_cur = c->pkt_sz = 0;
    return rv;
}
