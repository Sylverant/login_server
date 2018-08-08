/*
    Sylverant Login Server
    Copyright (C) 2018 Lawrence Sebald

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

#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>

#include <sylverant/debug.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "patch.h"
#include "login.h"

#ifndef LIBXML_TREE_ENABLED
#error You must have libxml2 with tree support built-in.
#endif

#define XC (const xmlChar *)

static void free_patch(patch_t *p) {
    uint32_t j;

    for(j = 0; j < CLIENT_LANG_COUNT; ++j) {
        free(p->name[j]);
        free(p->desc[j]);
    }

    for(j = 0; j < p->patchset_count; ++j) {
        free(p->patches[j]->filename);
    }

    free(p->patches);
    free(p->requires);
    free(p->conflicts);
}

/* Handles name and description tags. */
static char *handle_str(xmlNode *n, int *lang_code) {
    xmlChar *desc;
    xmlChar *lang;
    int lc = -1;
    char *rv = NULL;

    lang = xmlGetProp(n, XC"lang");
    if(!lang) {
        debug(DBG_ERROR, "Language not specified for patch string\n");
        return NULL;
    }

    /* Make sure the language is sane. */
    if(!xmlStrcmp(lang, XC"en")) {
        lc = CLIENT_LANG_ENGLISH;
    }
    else if(!xmlStrcmp(lang, XC"jp")) {
        lc = CLIENT_LANG_JAPANESE;
    }
    else if(!xmlStrcmp(lang, XC"de")) {
        lc = CLIENT_LANG_GERMAN;
    }
    else if(!xmlStrcmp(lang, XC"fr")) {
        lc = CLIENT_LANG_FRENCH;
    }
    else if(!xmlStrcmp(lang, XC"es")) {
        lc = CLIENT_LANG_SPANISH;
    }

    /* Korean, Traditional Chinese, and Simplified Chinese are not supported by
       any versions of PSO that runtime patching works with, so they're omitted
       from this list. */
    if(lc == -1) {
        debug(DBG_ERROR, "Invalid language code: %s\n", (const char *)lang);
        xmlFree(lang);
        return NULL;
    }

    /* Grab the description from the node */
    if((desc = xmlNodeListGetString(n->doc, n->children, 1))) {
        rv = strdup((const char *)desc);
        xmlFree(desc);
    }

    *lang_code = lc;
    return rv;
}

/* Handles requires and conflicts tags. */
static uint32_t handle_id(xmlNode *n) {
    xmlChar *id;
    uint32_t rid;

    id = xmlGetProp(n, XC"id");

    if(!id) {
        debug(DBG_ERROR, "Missing id for tag!\n");
        return 0;
    }

    errno = 0;
    rid = (uint32_t)strtoul((const char *)id, NULL, 0);
    if(errno) {
        debug(DBG_ERROR, "Malformed ID: %s\n", strerror(errno));
        xmlFree(id);
        return 0;
    }

    xmlFree(id);
    return rid;
}

/* Handles requires and conflicts tags. */
static int handle_patchset(xmlNode *n, patchset_t **rv) {
    xmlChar *version;
    xmlChar *filename;
    int irv = 0;
    patchset_t *ps;

    /* Grab the attributes */
    version = xmlGetProp(n, XC"version");
    filename = xmlGetProp(n, XC"filename");

    if(!version || !filename) {
        debug(DBG_ERROR, "Missing attribute for patchset tag!\n");
        irv = -1;
        goto out;
    }

    ps = (patchset_t *)malloc(sizeof(patchset_t));
    if(!ps) {
        debug(DBG_ERROR, "Cannot allocate memory for patchset: %s\n",
              strerror(errno));
        irv = -2;
        goto out1;
    }

    /* Parse the version... */
    errno = 0;
    ps->version = (uint32_t)strtoul((const char *)version, NULL, 0);
    if(errno) {
        debug(DBG_ERROR, "Invalid version ID: %s\n", (const char *)version);
        irv = -3;
        goto out1;
    }

    /* Copy the filename. */
    if(!(ps->filename = strdup((const char *)filename))) {
        debug(DBG_ERROR, "Can't copy filename!\n");
        irv = -4;
        goto out1;
    }

    /* Done. */
    *rv = ps;
    xmlFree(filename);
    xmlFree(version);
    return 0;

out1:
    free(ps);
out:
    xmlFree(filename);
    xmlFree(version);
    return irv;
}

static int handle_patch(xmlNode *n, patch_list_t *l) {
    xmlChar *id, *gmonly;
    int rv = 0;
    uint32_t rid;
    patch_t *p;
    patchset_t *ps;
    char *txt;
    int lang_code;
    void *tmp;

    p = (patch_t *)malloc(sizeof(patch_t));
    if(!p) {
        debug(DBG_ERROR, "Cannot allocate memory for patch: %s\n",
              strerror(errno));
        return -1;
    }

    memset(p, 0, sizeof(patch_t));

    /* Allocate space for some basic things... */
    p->name = (char **)malloc(sizeof(char *) * CLIENT_LANG_COUNT);
    if(!p->name) {
        debug(DBG_ERROR, "Cannot allocate memory for patch: %s\n",
              strerror(errno));
        free(p);
        return -2;
    }

    p->desc = (char **)malloc(sizeof(char *) * CLIENT_LANG_COUNT);
    if(!p->desc) {
        debug(DBG_ERROR, "Cannot allocate memory for patch: %s\n",
              strerror(errno));
        free(p->name);
        return -3;
    }

    memset(p->name, 0, sizeof(char *) * CLIENT_LANG_COUNT);
    memset(p->desc, 0, sizeof(char *) * CLIENT_LANG_COUNT);

    /* Grab the attributes we're expecting. */
    id = xmlGetProp(n, XC"id");
    gmonly = xmlGetProp(n, XC"gmonly");

    if(!id || !gmonly) {
        debug(DBG_ERROR, "patch tag missing attribute.\n");
        xmlFree(id);
        xmlFree(gmonly);
        free(p->desc);
        free(p->name);
        free(p);
        return -4;
    }

    /* Make sure the ID is sane. */
    errno = 0;
    rid = (uint32_t)strtoul((const char *)id, NULL, 0);

    if(errno) {
        debug(DBG_ERROR, "Invalid ID for patch: %s\n", (const char *)id);
        xmlFree(id);
        xmlFree(gmonly);
        free(p->desc);
        free(p->name);
        free(p);
        return -5;
    }

    xmlFree(id);
    p->id = rid;

    /* Make sure the value for gmonly is sane. */
    if(!xmlStrcmp(gmonly, XC"true")) {
        p->gmonly = 1;
    }
    else if(!xmlStrcmp(gmonly, XC"false")) {
        p->gmonly = 0;
    }
    else {
        debug(DBG_ERROR, "Invalid value for gmonly for patch\n");
        xmlFree(gmonly);
        free(p->desc);
        free(p->name);
        free(p);
        return -17;
    }

    xmlFree(gmonly);

    /* Now that we're done with that, deal with any children of the node */
    n = n->children;
    while(n) {
        if(n->type != XML_ELEMENT_NODE) {
            /* Ignore non-elements. */
            n = n->next;
            continue;
        }
        else if(!xmlStrcmp(n->name, XC"name")) {
            if(!(txt = handle_str(n, &lang_code))) {
                rv = -6;
                goto err;
            }

            if(lang_code == -1 || lang_code > CLIENT_LANG_COUNT) {
                rv = -7;
                goto err;
            }

            p->name[lang_code] = txt;
        }
        else if(!xmlStrcmp(n->name, XC"description")) {
            if(!(txt = handle_str(n, &lang_code))) {
                rv = -8;
                goto err;
            }

            if(lang_code == -1 || lang_code > CLIENT_LANG_COUNT) {
                rv = -9;
                goto err;
            }

            p->desc[lang_code] = txt;
        }
        else if(!xmlStrcmp(n->name, XC"requires")) {
            if(!(rid = handle_id(n))) {
                rv = -10;
                goto err;
            }

            tmp = realloc(p->requires, ++p->requires_count * sizeof(uint32_t));
            if(!tmp) {
                rv = -11;
                goto err;
            }

            p->requires = (uint32_t *)tmp;
            p->requires[p->requires_count - 1] = rid;
        }
        else if(!xmlStrcmp(n->name, XC"conflicts")) {
            if(!(rid = handle_id(n))) {
                rv = -12;
                goto err;
            }

            tmp = realloc(p->conflicts,
                          ++p->conflicts_count * sizeof(uint32_t));
            if(!tmp) {
                rv = -13;
                goto err;
            }

            p->conflicts = (uint32_t *)tmp;
            p->conflicts[p->conflicts_count - 1] = rid;
        }
        else if(!xmlStrcmp(n->name, XC"patchset")) {
            if(handle_patchset(n, &ps)) {
                rv = -14;
                goto err;
            }

            tmp = realloc(p->patches,
                          (p->patchset_count + 1) * sizeof(patchset_t *));
            if(!tmp) {
                rv = -15;
                goto err;
            }

            p->patches = (patchset_t **)tmp;
            p->patches[p->patchset_count++] = ps;
        }
        else {
            debug(DBG_WARN, "Invalid Tag %s on line %hu\n", (char *)n->name,
                  n->line);
        }

        n = n->next;
    }

    /* Add it to the patch list... */
    tmp = realloc(l->patches, (l->patch_count + 1) * sizeof(patch_t *));
    if(!tmp) {
        debug(DBG_ERROR, "Cannot add patch to list: %s\n", strerror(errno));
        rv = -16;
        goto err;
    }

    l->patches = (patch_t **)tmp;
    l->patches[l->patch_count++] = p;
    return 0;

err:
    free_patch(p);
    return rv;
}

int patch_list_read(const char *fn, patch_list_t **cfg) {
    xmlParserCtxtPtr cxt;
    xmlDoc *doc;
    xmlNode *n;
    int irv = 0;
    patch_list_t *rv;

    /* Allocate space for the base of the config. */
    rv = (patch_list_t *)malloc(sizeof(patch_list_t));

    if(!rv) {
        *cfg = NULL;
        debug(DBG_ERROR, "Couldn't allocate space for patch list\n");
        perror("malloc");
        return -1;
    }

    /* Clear out the config. */
    memset(rv, 0, sizeof(patch_list_t));

    /* Create an XML Parsing context */
    cxt = xmlNewParserCtxt();
    if(!cxt) {
        debug(DBG_ERROR, "Couldn't create parsing context for patch list\n");
        irv = -2;
        goto err;
    }

    /* Open the configuration file for reading. */
    doc = xmlReadFile(fn, NULL, XML_PARSE_DTDVALID);

    if(!doc) {
        xmlParserError(cxt, "Error in parsing patch list");
        irv = -3;
        goto err_cxt;
    }

    /* Make sure the document validated properly. */
    if(!cxt->valid) {
        xmlParserValidityError(cxt, "Validity Error parsing patch list");
        irv = -4;
        goto err_doc;
    }

    /* If we've gotten this far, we have a valid document, now go through and
       add in entries for everything... */
    n = xmlDocGetRootElement(doc);

    if(!n) {
        debug(DBG_WARN, "Empty patch list document\n");
        irv = -5;
        goto err_doc;
    }

    /* Make sure the config looks sane. */
    if(xmlStrcmp(n->name, XC"patches")) {
        debug(DBG_WARN, "Patch list does not appear to be the right type\n");
        irv = -6;
        goto err_doc;
    }

    n = n->children;
    while(n) {
        if(n->type != XML_ELEMENT_NODE) {
            /* Ignore non-elements. */
            n = n->next;
            continue;
        }
        else if(!xmlStrcmp(n->name, XC"patch")) {
            if(handle_patch(n, rv)) {
                irv = -7;
                goto err_doc;
            }
        }
        else {
            debug(DBG_WARN, "Invalid Tag %s on line %hu\n", (char *)n->name,
                  n->line);
        }

        n = n->next;
    }

    *cfg = rv;

    /* Cleanup/error handling below... */
err_doc:
    xmlFreeDoc(doc);
err_cxt:
    xmlFreeParserCtxt(cxt);
err:
    if(irv && irv > -7) {
        free(rv);
        *cfg = NULL;
    }
    else if(irv) {
        patch_list_free(rv);
        *cfg = NULL;
    }

    return irv;
}

void patch_list_free(patch_list_t *l) {
    uint32_t i;

    if(!l)
        return;

    for(i = 0; i < l->patch_count; ++i) {
        free_patch(l->patches[i]);
    }

    free(l->patches);
    free(l);
}

const patchset_t *patch_find(patch_list_t *l, uint32_t version, uint32_t id) {
    uint32_t i, j;
    patch_t *p;

    for(i = 0; i < l->patch_count; ++i) {
        p = l->patches[i];

        if(p->id == id) {
            for(j = 0; j < p->patchset_count; ++j) {
                if(p->patches[j]->version == version) {
                    return p->patches[j];
                }
            }
        }
    }

    return NULL;
}

const char *patch_get_desc(patch_list_t *l, uint32_t id, int lang) {
    uint32_t i, j;
    patch_t *p;

    for(i = 0; i < l->patch_count; ++i) {
        p = l->patches[i];

        if(p->id == id) {
            if(p->desc[lang]) {
                return p->desc[lang];
            }
            else if(p->desc[CLIENT_LANG_ENGLISH]) {
                return p->desc[CLIENT_LANG_ENGLISH];
            }
            else {
                for(j = 0; j < CLIENT_LANG_COUNT; ++j) {
                    if(p->desc[j])
                        return p->desc[j];
                }
            }
        }
    }

    return NULL;
}

patch_file_t *patch_file_read(const char *fn) {
    FILE *fp;
    long len;
    uint8_t *buf;
    uint32_t tmp;
    patch_file_t *rv;

    fp = fopen(fn, "rb");
    if(!fp) {
        debug(DBG_ERROR, "Cannot open patch file '%s': %s\n", fn,
              strerror(errno));
        return NULL;
    }

    /* Figure out the length */
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    /* Make sure it's at least somewhat sane */
    if(len < 24) {
        debug(DBG_ERROR, "Patch file '%s' is too short\n", fn);
        fclose(fp);
        return NULL;
    }

    /* Allocate space */
    buf = (uint8_t *)malloc(len);
    if(!buf) {
        debug(DBG_ERROR, "Cannot allocate space for patch file: %s\n",
              strerror(errno));
        fclose(fp);
        return NULL;
    }

    /* Read it */
    if(fread(buf, 1, len, fp) != len) {
        debug(DBG_ERROR, "Cannot read patch file: %s\n", strerror(errno));
        free(buf);
        fclose(fp);
        return NULL;
    }

    /* Done with the file */
    fclose(fp);

    /* Parse it... */
    if(buf[0] != 'S' || buf[1] != 'Y' || buf[2] != 'L' || buf[3] != 'P') {
        debug(DBG_ERROR, "Patch file '%s' appears invalid (bad sig)\n", fn);
        free(buf);
        return NULL;
    }

    /* Check the version... */
    tmp = buf[4] | (buf[5] << 8) | (buf[6] << 16) | (buf[7] << 24);
    if(tmp != 0x00010001 && tmp != 0x00010002) {
        debug(DBG_ERROR, "Patch file '%s' has bad version\n", fn);
        free(buf);
        return NULL;
    }

    /* Grab the number of patches */
    tmp = buf[8] | (buf[9] << 8) | (buf[10] << 16) | (buf[11] << 24);

    /* Filling in the struct */
    rv = (patch_file_t *)malloc(sizeof(patch_file_t));
    if(!rv) {
        debug(DBG_ERROR, "Cannot allocate space for patch file: %s\n",
              strerror(errno));
        free(buf);
        return NULL;
    }

    rv->patch_count = tmp;
    rv->length = (uint32_t)(len - 16);

    rv->data = (uint8_t *)malloc(rv->length);
    if(!rv->data) {
        debug(DBG_ERROR, "Cannot allocate space for patch data: %s\n",
              strerror(errno));
        free(rv);
        free(buf);
        return NULL;
    }

    memcpy(rv->data, buf + 16, rv->length);

    /* Done */
    return rv;
}

void patch_file_free(patch_file_t *f) {
    if(!f)
        return;

    free(f->data);
    free(f);
}
