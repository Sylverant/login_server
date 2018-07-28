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

#ifndef PATCH_H
#define PATCH_H

#include <stdint.h>

typedef struct patchset {
    uint32_t version;
    char *filename;
} patchset_t;

typedef struct patch {
    uint32_t id;
    uint32_t requires_count;
    uint32_t conflicts_count;
    uint32_t patchset_count;

    char **name;
    char **desc;
    uint32_t *requires;
    uint32_t *conflicts;
    patchset_t **patches;
} patch_t;

typedef struct patch_list {
    uint32_t patch_count;
    patch_t **patches;
} patch_list_t;

int patch_list_read(const char *fn, patch_list_t **rv);
void patch_list_free(patch_list_t *l);

const patchset_t *patch_find(patch_list_t *l, uint32_t version, uint32_t id);
const char *patch_get_desc(patch_list_t *l, uint32_t id, int lang);

typedef struct patch_file {
    uint32_t patch_count;
    uint32_t length;
    uint8_t *data;
} patch_file_t;

patch_file_t *patch_file_read(const char *fn);
void patch_file_free(patch_file_t *f);


#endif /* !PATCH_H */
