/*
    Sylverant Login Server
    Copyright (C) 2011, 2012 Lawrence Sebald

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
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include <unistd.h>

#include <zlib.h>

#include <openssl/sha.h>

#include <sylverant/checksum.h>
#include <sylverant/debug.h>
#include <sylverant/database.h>
#include <sylverant/prs.h>

#include "login.h"
#include "player.h"
#include "packets.h"
#include "login_packets.h"

#define NUM_PARAM_FILES 9

/* The list of parameter files. These should be in blueburst/param */
const static char *param_files[NUM_PARAM_FILES] = {
    "ItemMagEdit.prs",
    "ItemPMT.prs",
    "BattleParamEntry.dat",
    "BattleParamEntry_on.dat",
    "BattleParamEntry_lab.dat",
    "BattleParamEntry_lab_on.dat",
    "BattleParamEntry_ep4.dat",
    "BattleParamEntry_ep4_on.dat",
    "PlyLevelTbl.prs"
};

/* Default key configuration for Blue Burst clients... */
const static uint8_t default_keys[420] = {
    0x00, 0x00, 0x00, 0x00, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x59, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x5e, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x5d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x5c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5f, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x5d, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x5c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x5f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x56, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5e, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x46, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x49, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x4b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x2b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2d, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x32, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0xff, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    0x00, 0x02, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x80, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00
};

const static uint8_t default_symbolchats[1248] = {
	0x01, 0x00, 0x00, 0x00, 0x09, 0x00, 0x45, 0x00, 0x48, 0x00, 
    0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0xff, 0xff, 
    0x0d, 0x00, 0xff, 0xff, 0xff, 0xff, 0x05, 0x18, 0x1d, 0x00, 
    0x05, 0x28, 0x1d, 0x01, 0x36, 0x20, 0x2a, 0x00, 0x3c, 0x00, 
    0x32, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 
    0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x02, 0xff, 0x00, 
    0x00, 0x02, 0xff, 0x00, 0x00, 0x02, 0xff, 0x00, 0x00, 0x02, 
    0xff, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x09, 0x00, 
    0x45, 0x00, 0x47, 0x00, 0x6f, 0x00, 0x6f, 0x00, 0x64, 0x00, 
    0x2d, 0x00, 0x62, 0x00, 0x79, 0x00, 0x65, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x00, 
    0x00, 0x00, 0x76, 0x04, 0x0c, 0x00, 0xff, 0xff, 0xff, 0xff, 
    0x06, 0x15, 0x14, 0x00, 0x06, 0x2b, 0x14, 0x01, 0x05, 0x18, 
    0x1f, 0x00, 0x05, 0x28, 0x1f, 0x01, 0x36, 0x20, 0x2a, 0x00, 
    0x3c, 0x00, 0x32, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 
    0x00, 0x02, 0xff, 0x00, 0x00, 0x02, 0xff, 0x00, 0x00, 0x02, 
    0xff, 0x00, 0x00, 0x02, 0xff, 0x00, 0x00, 0x02, 0x01, 0x00, 
    0x00, 0x00, 0x09, 0x00, 0x45, 0x00, 0x48, 0x00, 0x75, 0x00, 
    0x72, 0x00, 0x72, 0x00, 0x61, 0x00, 0x68, 0x00, 0x21, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x62, 0x03, 0x62, 0x03, 
    0xff, 0xff, 0xff, 0xff, 0x09, 0x16, 0x1b, 0x00, 0x09, 0x2b, 
    0x1b, 0x01, 0x37, 0x20, 0x2c, 0x00, 0xff, 0x00, 0x00, 0x00, 
    0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 
    0x00, 0x00, 0xff, 0x00, 0x00, 0x02, 0xff, 0x00, 0x00, 0x02, 
    0xff, 0x00, 0x00, 0x02, 0xff, 0x00, 0x00, 0x02, 0xff, 0x00, 
    0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x09, 0x00, 0x45, 0x00, 
    0x43, 0x00, 0x72, 0x00, 0x79, 0x00, 0x69, 0x00, 0x6e, 0x00, 
    0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x00, 0x00, 0x00, 
    0x4f, 0x07, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x06, 0x15, 
    0x14, 0x00, 0x06, 0x2b, 0x14, 0x01, 0x05, 0x18, 0x1f, 0x00, 
    0x05, 0x28, 0x1f, 0x01, 0x21, 0x20, 0x2e, 0x00, 0xff, 0x00, 
    0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x02, 
    0xff, 0x00, 0x00, 0x02, 0xff, 0x00, 0x00, 0x02, 0xff, 0x00, 
    0x00, 0x02, 0xff, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 
    0x09, 0x00, 0x45, 0x00, 0x49, 0x00, 0x27, 0x00, 0x6d, 0x00, 
    0x20, 0x00, 0x61, 0x00, 0x6e, 0x00, 0x67, 0x00, 0x72, 0x00, 
    0x79, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x5c, 0x00, 0x00, 0x00, 0x16, 0x01, 0x01, 0x00, 0xff, 0xff, 
    0xff, 0xff, 0x0b, 0x18, 0x1b, 0x01, 0x0b, 0x28, 0x1b, 0x00, 
    0x33, 0x20, 0x2a, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 
    0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 
    0xff, 0x00, 0x00, 0x02, 0xff, 0x00, 0x00, 0x02, 0xff, 0x00, 
    0x00, 0x02, 0xff, 0x00, 0x00, 0x02, 0xff, 0x00, 0x00, 0x02, 
    0x01, 0x00, 0x00, 0x00, 0x09, 0x00, 0x45, 0x00, 0x48, 0x00, 
    0x65, 0x00, 0x6c, 0x00, 0x70, 0x00, 0x20, 0x00, 0x6d, 0x00, 
    0x65, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0xec, 0x00, 0x00, 0x00, 0x5e, 0x06, 
    0x38, 0x01, 0xff, 0xff, 0xff, 0xff, 0x02, 0x17, 0x1b, 0x01, 
    0x02, 0x2a, 0x1b, 0x00, 0x31, 0x20, 0x2c, 0x00, 0xff, 0x00, 
    0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 
    0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x02, 0xff, 0x00, 
    0x00, 0x02, 0xff, 0x00, 0x00, 0x02, 0xff, 0x00, 0x00, 0x02, 
    0xff, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 
    0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 
    0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 
    0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 
    0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 
    0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0xff, 0x00, 
    0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 
    0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 
    0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 
    0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 
    0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 
    0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 
    0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 
    0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 
    0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 
    0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 
    0xff, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 
    0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 
    0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 
    0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 
    0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 
    0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0x00, 0x00, 
    0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 
    0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 
    0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 
    0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 
    0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 
    0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 
    0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 
    0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 
    0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 
    0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00
};

#define MIN(a, b) (a < b ? a : b)

#define MAX_PARAMS_SIZE 0x100000

/* This stuff is cached at the start of the program */
static bb_param_hdr_pkt *param_hdr = NULL;
static bb_param_chunk_pkt **param_chunks = NULL;
static int num_param_chunks = 0;
static sylverant_bb_db_char_t default_chars[12];
static bb_level_table_t char_stats;

static int handle_bb_login(login_client_t *c, bb_login_93_pkt *pkt) {
    char query[256];
    int len;
    char tmp[32];
    void *result;
    char **row;
    uint8_t hash[32];

    /* Make sure the username string is sane... */
    len = strlen(pkt->username);
    if(len > 16 || strlen(pkt->password) > 16) {
        send_bb_security(c, 0, LOGIN_93BB_FORCED_DISCONNECT, 0, NULL, 0);
        return -1;
    }

    sylverant_db_escape_str(&conn, tmp, pkt->username, len);
    sprintf(query, "SELECT account_data.account_id, isbanned, teamid, "
            "privlevel, guildcard, blueburst_clients.password, dressflag FROM "
            "account_data INNER JOIN blueburst_clients ON "
            "account_data.account_id = blueburst_clients.account_id WHERE "
            "blueburst_clients.username='%s'", tmp);

    /* Query the database for the user... */
    if(sylverant_db_query(&conn, query)) {
        send_bb_security(c, 0, LOGIN_93BB_UNKNOWN_ERROR, 0, NULL, 0);
        return -2;
    }

    result = sylverant_db_result_store(&conn);
    if(!result) {
        send_bb_security(c, 0, LOGIN_93BB_UNKNOWN_ERROR, 0, NULL, 0);
        return -2;
    }

    row = sylverant_db_result_fetch(result);
    if(!row) {
        send_bb_security(c, 0, LOGIN_93BB_NO_USER_RECORD, 0, NULL, 0);
        sylverant_db_result_free(result);
        return -3;
    }

    /* Make sure some simple checks pass first... */
    if(atoi(row[1])) {
        /* User is banned by account. */
        send_bb_security(c, 0, LOGIN_93BB_BANNED, 0, NULL, 0);
        sylverant_db_result_free(result);
        return -4;
    }

    /* If we've gotten this far, we have an account! Check the password. */
    sprintf(tmp, "%s_salt_%s", pkt->password, row[4]);
    SHA256((unsigned char *)tmp, strlen(tmp), hash);

    if(memcmp(hash, row[5], 32)) {
        /* Password check failed... */
        send_bb_security(c, 0, LOGIN_93BB_BAD_USER_PWD, 0, NULL, 0);
        sylverant_db_result_free(result);
        return -6;
    }

    /* Grab the rest of what we care about from the query... */
    errno = 0;
    c->team_id = (uint32_t)strtoul(row[2], NULL, 0);
    c->is_gm = (uint32_t)strtoul(row[3], NULL, 0);
    c->guildcard = (uint32_t)strtoul(row[4], NULL, 0);
    c->account_id = (uint32_t)strtoul(row[0], NULL, 0);
    c->flags = (uint32_t)strtoul(row[6], NULL, 0);
    sylverant_db_result_free(result);

    if(errno) {
        send_bb_security(c, 0, LOGIN_93BB_UNKNOWN_ERROR, 0, NULL, 0);
        return -2;
    }

    /* Copy in the security data */
    memcpy(&c->sec_data, pkt->security_data, sizeof(bb_security_data_t));

    if(c->sec_data.magic != LE32(0xDEADBEEF)) {
        send_bb_security(c, 0, LOGIN_93BB_FORCED_DISCONNECT, 0, NULL, 0);
        return -8;
    }

    /* Send the security data packet */
    if(send_bb_security(c, c->guildcard, LOGIN_93BB_OK, c->team_id,
                        &c->sec_data, sizeof(bb_security_data_t))) {
        return -7;
    }

    /* Has the user picked a character already? */
    if(c->sec_data.sel_char) {
        if(send_timestamp(c)) {
            return -9;
        }

        if(send_ship_list(c, 0)) {
            return -10;
        }

        if(send_scroll_msg(c, "Welcome to Sylverant!")) {
            return -11;
        }
    }

    return 0;
}

static int handle_option_request(login_client_t *c) {
    char query[sizeof(sylverant_bb_db_opts_t) * 2 + 256];
    void *result;
    char **row;
    sylverant_bb_db_opts_t opts;

    /* Look up the user's saved config */
    sprintf(query, "SELECT options FROM blueburst_options WHERE "
            "guildcard='%" PRIu32 "'", c->guildcard);

    if(!sylverant_db_query(&conn, query)) {
        result = sylverant_db_result_store(&conn);

        /* See if we got a hit... */
        if(sylverant_db_result_rows(result)) {
            row = sylverant_db_result_fetch(result);
            memcpy(&opts, row[0], sizeof(sylverant_bb_db_opts_t));
        }
        else {
            /* Initialize to defaults */
            memset(&opts, 0, sizeof(sylverant_bb_db_opts_t));
            memcpy(&opts.key_config, default_keys, 420);
            memcpy(&opts.symbol_chats, default_symbolchats, 0x4E0);

            sprintf(query, "INSERT INTO blueburst_options (guildcard, "
                    "options) VALUES ('%" PRIu32"', '", c->guildcard);
            sylverant_db_escape_str(&conn, query + strlen(query),
                                    (char *)&opts,
                                    sizeof(sylverant_bb_db_opts_t));
            strcat(query, "')");

            if(sylverant_db_query(&conn, query)) {
                debug(DBG_WARN, "Couldn't add key data to database for "
                      "guildcard %" PRIu32 "\n", c->guildcard);
                debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
            }
        }

        sylverant_db_result_free(result);
    }
    else {
        send_large_msg(c, __(c, "\tEDatabase error.\n\n"
                       "Please contact the server administrator."));
        return -1;
    }

    return send_bb_option_reply(c, opts.key_config);
}

static int handle_char_select(login_client_t *c, bb_char_select_pkt *pkt) {
    char query[256];
    void *result;
    char **row;
    unsigned long *len, sz;
    int rv = 0;
    sylverant_bb_db_char_t *char_data;
    sylverant_bb_mini_char_t mc;
    uLong sz2;

    /* Make sure the slot is sane */
    if(pkt->slot > 3) {
        return -1;
    }

    /* Query the database for the data */
    sprintf(query, "SELECT data, size FROM character_data WHERE guildcard='%"
            PRIu32 "' AND slot='%d'", c->guildcard, (int)pkt->slot);

    if(sylverant_db_query(&conn, query)) {
        return -2;
    }

    if(!(result = sylverant_db_result_store(&conn))) {
        return -3;
    }

    row = sylverant_db_result_fetch(result);

    if(pkt->reason == 0) {
        /* The client wants the preview data for character select... */
        if(row) {
            /* Grab the length of the character data */
            if(!(len = sylverant_db_result_lengths(result))) {
                sylverant_db_result_free(result);
                debug(DBG_WARN, "Couldn't get length of character data\n");
                debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
                return -1;
            }

            sz = len[0];
            char_data =
                (sylverant_bb_db_char_t*)malloc(sizeof(sylverant_bb_db_char_t));

            if(!char_data) {
                debug(DBG_WARN, "Couldn't allocate space for char data\n");
                debug(DBG_WARN, "%s\n", strerror(errno));
                sylverant_db_result_free(result);
                return -2;
            }

            if(row[1]) {
                if(atoi(row[1]) != sizeof(sylverant_bb_db_char_t)) {
                    sylverant_db_result_free(result);
                    free(char_data);
                    debug(DBG_WARN, "Invalid character data length!\n");
                    return -2;
                }

                sz2 = sizeof(sylverant_bb_db_char_t);

                if(uncompress((Bytef *)char_data, &sz2, (Bytef *)row[0],
                              (uLong)sz) != Z_OK) {
                    sylverant_db_result_free(result);
                    free(char_data);
                    debug(DBG_WARN, "Can't uncompress character data\n");
                    return -3;
                }
            }
            else {
                if(sz != sizeof(sylverant_bb_db_char_t)) {
                    sylverant_db_result_free(result);
                    free(char_data);
                    debug(DBG_WARN, "Invalid (unc) character data length!\n");
                    return -2;
                }

                memcpy(char_data, row[0], sizeof(sylverant_bb_db_char_t));
            }

            /* We've got it... Copy it out of the row retrieved. */
            memcpy(mc.guildcard_str, char_data->character.guildcard_str, 0x70);
            mc.level = char_data->character.level;
            mc.exp = char_data->character.exp;
            mc.play_time = char_data->character.play_time;
            mc.unused[11] = mc.unused[12] = mc.unused[13] = mc.unused[14] = 0;

            free(char_data);

            rv = send_bb_char_preview(c, &mc, pkt->slot);
        }
        else {
            /* No data's there, so let the client know */
            rv = send_bb_char_ack(c, pkt->slot, BB_CHAR_ACK_NONEXISTANT);
        }
    }
    else {
        /* The client is actually selecting the character to play with. Update
           the data on the client, then send the acknowledgement. */
        c->sec_data.slot = pkt->slot;
        c->sec_data.sel_char = 1;

        if(send_bb_security(c, c->guildcard, 0, c->team_id, &c->sec_data,
                            sizeof(bb_security_data_t))) {
            rv = -4;
        }
        else {
            rv = send_bb_char_ack(c, pkt->slot, BB_CHAR_ACK_SELECT);
        }
    }

    sylverant_db_result_free(result);

    return rv;
}

static int handle_checksum(login_client_t *c, bb_checksum_pkt *pkt) {
    /* XXXX: Do something with this some time... */
    return send_bb_checksum_ack(c, 1);
}

static int handle_guild_request(login_client_t *c) {
    char query[256];
    void *result;
    char **row;
    unsigned long *lengths;
    uint32_t checksum;
    int i = 0;
    uint32_t gc;

    if(!c->gc_data) {
        c->gc_data = (bb_gc_data_t *)malloc(sizeof(bb_gc_data_t));

        if(!c->gc_data) {
            /* XXXX: Should send an error message to the user */
            return -1;
        }
    }

    /* Clear it out */
    memset(c->gc_data, 0, sizeof(bb_gc_data_t));

    /* Query the DB for the user's guildcard data */
    sprintf(query, "SELECT friend_gc, name, team_name, text, language, "
            "section_id, class, comment FROM blueburst_guildcards WHERE "
            "guildcard='%" PRIu32 "' ORDER BY priority ASC", c->guildcard);

    if(sylverant_db_query(&conn, query)) {
        /* Should send an error message to the user */
        debug(DBG_WARN, "Couldn't fetch guildcards (gc=%" PRIu32 "):\n"
              "%s\n", c->guildcard, sylverant_db_error(&conn));
        return -1;
    }

    if(!(result = sylverant_db_result_store(&conn))) {
        /* Should send an error message to the user */
        debug(DBG_WARN, "Couldn't store guildcard result (gc=%" PRIu32 "):\n"
              "%s\n", c->guildcard, sylverant_db_error(&conn));
        return -1;
    }

    /* Fill in guildcard data */
    while((row = sylverant_db_result_fetch(result)) && i < 104) {
        lengths = sylverant_db_result_lengths(result);

        gc = (uint32_t)strtoul(row[0], NULL, 0);
        c->gc_data->entries[i].guildcard = LE32(gc);
        memcpy(c->gc_data->entries[i].name, row[1], MIN(48, lengths[1]));
        memcpy(c->gc_data->entries[i].team, row[2], MIN(32, lengths[2]));
        memcpy(c->gc_data->entries[i].desc, row[3], MIN(176, lengths[3]));
        memcpy(c->gc_data->entries[i].comment, row[7], MIN(176, lengths[7]));
        c->gc_data->entries[i].reserved1 = 1;
        c->gc_data->entries[i].language = (uint8_t)strtoul(row[4], NULL, 0);
        c->gc_data->entries[i].section = (uint8_t)strtoul(row[5], NULL, 0);
        c->gc_data->entries[i].ch_class = (uint8_t)strtoul(row[6], NULL, 0);

        ++i;
    }

    /* Clean up... */
    sylverant_db_result_free(result);

    /* Query the DB for the user's blacklist data */
    sprintf(query, "SELECT blocked_gc, name, team_name, text, language, "
            "section_id, class FROM blueburst_blacklist WHERE guildcard='%"
            PRIu32 "' ORDER BY blocked_gc ASC", c->guildcard);

    if(sylverant_db_query(&conn, query)) {
        /* Should send an error message to the user */
        debug(DBG_WARN, "Couldn't fetch blaclist (gc=%" PRIu32 "):\n"
              "%s\n", c->guildcard, sylverant_db_error(&conn));
        return -1;
    }

    if(!(result = sylverant_db_result_store(&conn))) {
        /* Should send an error message to the user */
        debug(DBG_WARN, "Couldn't store blacklist result (gc=%" PRIu32 "):\n"
              "%s\n", c->guildcard, sylverant_db_error(&conn));
        return -1;
    }

    /* Fill in blacklist data */
    i = 0;

    while((row = sylverant_db_result_fetch(result)) && i < 29) {
        lengths = sylverant_db_result_lengths(result);

        gc = (uint32_t)strtoul(row[0], NULL, 0);
        c->gc_data->blocked[i].guildcard = LE32(gc);
        memcpy(c->gc_data->blocked[i].name, row[1], MIN(48, lengths[1]));
        memcpy(c->gc_data->blocked[i].team, row[2], MIN(32, lengths[2]));
        memcpy(c->gc_data->blocked[i].desc, row[3], MIN(176, lengths[3]));
        c->gc_data->blocked[i].reserved1 = 1;
        c->gc_data->blocked[i].language = (uint8_t)strtoul(row[4], NULL, 0);
        c->gc_data->blocked[i].section = (uint8_t)strtoul(row[5], NULL, 0);
        c->gc_data->blocked[i].ch_class = (uint8_t)strtoul(row[6], NULL, 0);

        ++i;
    }

    /* Clean up... */
    sylverant_db_result_free(result);

    /* Calculate the checksum, and send the header */
    checksum = sylverant_crc32((uint8_t *)c->gc_data, sizeof(bb_gc_data_t));

    return send_bb_guild_header(c, checksum);
}

static int handle_guild_chunk(login_client_t *c, bb_guildcard_req_pkt *pkt) {
    uint32_t chunk, cont;

    chunk = LE32(pkt->chunk);
    cont = LE32(pkt->cont);

    /* Send data as long as the client is still looking for it. */
    if(cont) {
        /* Send the chunk */
        return send_bb_guild_chunk(c, chunk);
    }

    return 0;
}

static int handle_param_hdr_req(login_client_t *c) {
    return send_bb_pkt(c, (bb_pkt_hdr_t *)param_hdr);
}

static int handle_param_chunk_req(login_client_t *c, bb_pkt_hdr_t *pkt) {
    uint32_t chunk = LE32(pkt->flags);

    if(chunk < num_param_chunks) {
        return send_bb_pkt(c, (bb_pkt_hdr_t *)param_chunks[chunk]);
    }

    return -1;
}

static int handle_setflag(login_client_t *c, bb_setflag_pkt *pkt) {
    uint32_t val = LE32(pkt->flags);
    char query[256];

    sprintf(query, "UPDATE account_data SET dressflag='%" PRIu32 "' WHERE "
            "account_id='%" PRIu32 "'", val, c->account_id);

    if(sylverant_db_query(&conn, query)) {
        /* Should send an error message to the user */
        debug(DBG_WARN, "Couldn't set flags (account=%" PRIu32 ", flags=%"
              PRIu8 "):\n%s\n", c->account_id, val,
              sylverant_db_error(&conn));
        return -1;
    }

    return 0;
}

static int handle_update_char(login_client_t *c, bb_char_preview_pkt *pkt) {
    uint32_t flags = c->flags;
    sylverant_bb_db_char_t char_data;
    uint8_t cl = pkt->data.ch_class;
    static char query[sizeof(sylverant_bb_db_char_t) * 2 + 256];
    void *result;
    char **row;

    if(flags & 0x00000001) {
        /* Copy in the default data */
        memcpy(&char_data, &default_chars[cl], sizeof(sylverant_bb_db_char_t));

        /* Copy in the starting stats */
        memcpy(&char_data.character.atp, &char_stats.start_stats[cl],
               7 * sizeof(uint16_t));

        /* Copy in the appearance data */
        memcpy(char_data.character.guildcard_str, pkt->data.guildcard_str,
               0x70);

        sprintf(query, "DELETE FROM character_data WHERE guildcard="
                "'%" PRIu32 "' AND slot='%" PRIu8 "'", c->guildcard,
                pkt->slot);

        if(sylverant_db_query(&conn, query)) {
            debug(DBG_WARN, "Couldn't clear old character data (gc=%"
                  PRIu32 ", slot=%" PRIu8 "):\n%s\n", c->guildcard, pkt->slot,
                  sylverant_db_error(&conn));
            /* XXXX: Send the user an error message */
            return -1;
        }

        sprintf(query, "INSERT INTO character_data (guildcard, slot, data) "
                "VALUES ('%" PRIu32"', '%" PRIu8 "', '", c->guildcard,
                pkt->slot);
        sylverant_db_escape_str(&conn, query + strlen(query),
                                (char *)&char_data,
                                sizeof(sylverant_bb_db_char_t));
        strcat(query, "')");

        if(sylverant_db_query(&conn, query)) {
            debug(DBG_WARN, "Couldn't clear create character data (gc=%"
                  PRIu32 ", slot=%" PRIu8 "):\n%s\n", c->guildcard, pkt->slot,
                  sylverant_db_error(&conn));
            /* XXXX: Send the user an error message */
            return -2;
        }
    }
    else if(flags & 0x00000002) {
        /* Using the dressing room */
        sprintf(query, "SELECT data FROM character_data WHERE guildcard='%"
                PRIu32 "' AND slot='%" PRIu8 "'", c->guildcard, pkt->slot);

        /* Grab the old data... */
        if(sylverant_db_query(&conn, query)) {
            debug(DBG_WARN, "Couldn't fetch character data (gc=%" PRIu32 ", "
                  "slot=%" PRIu8 "):\n%s\n", c->guildcard, pkt->slot,
                  sylverant_db_error(&conn));
            /* XXXX: Send the user an error message */
            return -3;
        }

        if(!(result = sylverant_db_result_store(&conn))) {
            /* XXXX: Send the user an error message */
            return -4;
        }

        if(!(row = sylverant_db_result_fetch(result))) {
            /* XXXX: Send the user an error message */
            sylverant_db_result_free(result);
            return -5;
        }

        /* Copy the data out, update it, and update the db. */
        memcpy(&char_data, row[0], sizeof(sylverant_bb_db_char_t));
        sylverant_db_result_free(result);

        memcpy(char_data.character.guildcard_str, pkt->data.guildcard_str,
               0x70);

        strcpy(query, "UPDATE character_data SET data='");
        sylverant_db_escape_str(&conn, query + strlen(query),
                                (char *)&char_data,
                                sizeof(sylverant_bb_db_char_t));
        sprintf(query + strlen(query), "' WHERE guildcard='%" PRIu32 "' AND "
                "slot='%" PRIu8 "'", c->guildcard, pkt->slot);

        if(sylverant_db_query(&conn, query)) {
            debug(DBG_WARN, "Couldn't update character data (gc=%" PRIu32 ", "
                  "slot=%" PRIu8 "):\n%s\n", c->guildcard, pkt->slot,
                  sylverant_db_error(&conn));
            /* XXXX: Send the user an error message */
            return -6;
        }
    }

    sprintf(query, "UPDATE account_data SET dressflag='0' WHERE account_id='%"
            PRIu32 "'", c->account_id);

    if(sylverant_db_query(&conn, query)) {
        /* XXXX: Send the user an error message */
        debug(DBG_WARN, "Couldn't clear flags (account=%" PRIu32 "):\n%s\n",
              c->account_id, sylverant_db_error(&conn));
        return -7;
    }

    /* Send state information down to the client to have them inform the
       server when they connect again... */
    c->sec_data.slot = pkt->slot;
    c->sec_data.sel_char = 1;
    c->flags = 0;

    if(send_bb_security(c, c->guildcard, 0, c->team_id, &c->sec_data,
                        sizeof(bb_security_data_t))) {
        return -8;
    }

    return send_bb_char_ack(c, pkt->slot, BB_CHAR_ACK_UPDATE);
}

static int handle_info_req(login_client_t *c, bb_select_pkt *pkt) {
    uint32_t menu_id = LE32(pkt->menu_id);
    uint32_t item_id = LE32(pkt->item_id);
    uint16_t menu_code;
    int ship_num;
    char str[256];
    void *result;
    char **row;

    switch(menu_id & 0xFF) {
        /* Ship */
        case 0x01:
            /* If its a list, say nothing */
            if(item_id == 0) {
                return send_info_reply(c, __(c, "\tENothing here."));
            }

            /* We should have a ship ID as the item_id at this point, so query
               the db for the info we want. */
            sprintf(str, "SELECT name, players, games, menu_code, ship_number "
                    "FROM online_ships WHERE ship_id='%lu'",
                    (unsigned long)item_id);

            /* Query for what we're looking for */
            if(sylverant_db_query(&conn, str)) {
                return -1;
            }

            if(!(result = sylverant_db_result_store(&conn))) {
                return -2;
            }

            /* If we don't have a row, then the ship is offline */
            if(!(row = sylverant_db_result_fetch(result))) {
                return send_info_reply(c, __(c, "\tE\tC4That ship is now\n"
                                             "offline."));
            }

            /* Parse out the menu code */
            menu_code = (uint16_t)atoi(row[3]);
            ship_num = atoi(row[4]);

            /* Send the info reply */
            if(!menu_code) {
                sprintf(str, "%02X:%s\n%s %s\n%s %s", ship_num, row[0], row[1],
                        __(c, "Users"), row[2], __(c, "Teams"));
            }
            else {
                sprintf(str, "%02X:%c%c/%s\n%s %s\n%s %s", ship_num,
                        (char)menu_code, (char)(menu_code >> 8), row[0], row[1],
                        __(c, "Users"), row[2], __(c, "Teams"));
            }

            sylverant_db_result_free(result);

            return send_info_reply(c, str);

        default:
            /* Ignore any other info requests. */
            return 0;
    }
}

/* Handle a client's ship select packet. */
static int handle_ship_select(login_client_t *c, bb_select_pkt *pkt) {
    uint32_t menu_id = LE32(pkt->menu_id);
    uint32_t item_id = LE32(pkt->item_id);

    switch(menu_id & 0xFF) {
        /* Initial menu */
        case 0x00:
            if(item_id == ITEM_ID_INIT_SHIP) {
                /* Ship Select */
                return send_ship_list(c, 0);
            }

            return -1;

        /* Ship */
        case 0x01:
            if(item_id == 0) {
                /* A "Ship List" menu item */
                return send_ship_list(c, (uint16_t)(menu_id >> 8));
            }
            else {
                /* An actual ship */
                return ship_transfer(c, item_id);
            }

        default:
            return -1;
    }
}

int process_bbcharacter_packet(login_client_t *c, void *pkt) {
    bb_pkt_hdr_t *bb = (bb_pkt_hdr_t *)pkt;
    uint16_t type = LE16(bb->pkt_type);

    switch(type) {
        case LOGIN_93_TYPE:
            return handle_bb_login(c, (bb_login_93_pkt *)pkt);

        case TYPE_05:
            c->disconnected = 1;
            return 0;

        case BB_OPTION_REQUEST_TYPE:
            return handle_option_request(c);

        case BB_CHARACTER_SELECT_TYPE:
            return handle_char_select(c, (bb_char_select_pkt *)pkt);

        case BB_CHECKSUM_TYPE:
            return handle_checksum(c, (bb_checksum_pkt *)pkt);

        case BB_GUILD_REQUEST_TYPE:
            return handle_guild_request(c);

        case BB_GUILDCARD_CHUNK_REQ_TYPE:
            return handle_guild_chunk(c, (bb_guildcard_req_pkt *)pkt);

        case BB_PARAM_HEADER_REQ_TYPE:
            return handle_param_hdr_req(c);

        case BB_PARAM_CHUNK_REQ_TYPE:
            return handle_param_chunk_req(c, (bb_pkt_hdr_t *)pkt);

        case BB_SETFLAG_TYPE:
            return handle_setflag(c, (bb_setflag_pkt *)pkt);

        case BB_CHARACTER_UPDATE_TYPE:
            return handle_update_char(c, (bb_char_preview_pkt *)pkt);

        case INFO_REQUEST_TYPE:
            return handle_info_req(c, (bb_select_pkt *)pkt);

        case BB_FULL_CHARACTER_TYPE:
            /* Ignore these... they're meaningless and very broken when they
               manage to get sent to the login server... */
            return 0;

        case MENU_SELECT_TYPE:
            return handle_ship_select(c, (bb_select_pkt *)pkt);

        default:
            printf("Unknown packet (BB Character)!\n");
            print_packet(pkt, LE16(bb->pkt_len));
            return -1;
    }
}

int load_param_data(void) {
    FILE *fp2;
    const char *fn;
    int i = 0, len;
    long filelen;
    uint32_t checksum, offset = 0;
    uint8_t *rawbuf;

    /* Allocate space for the buffer first */
    rawbuf = (uint8_t *)malloc(MAX_PARAMS_SIZE);
    if(!rawbuf) {
        debug(DBG_ERROR, "Couldn't allocate param buffer:\n%s\n",
              strerror(errno));
        return -1;
    }

    /* Allocate space for the parameter header */
    len = 0x08 + (NUM_PARAM_FILES * 0x4C);
    param_hdr = (bb_param_hdr_pkt *)malloc(len);
    if(!param_hdr) {
        debug(DBG_ERROR, "Couldn't allocate parameter header:\n%s\n",
              strerror(errno));
        free(rawbuf);
        return -3;
    }

    /* Go to the parameter file directory... */
    chdir("blueburst/param");

    param_hdr->hdr.pkt_type = LE16(BB_PARAM_HEADER_TYPE);
    param_hdr->hdr.pkt_len = LE16(len);
    param_hdr->hdr.flags = LE32(NUM_PARAM_FILES);

    /* Load each of the parameter files. */
    for(i = 0; i < NUM_PARAM_FILES; ++i) {
        fn = param_files[i];
        debug(DBG_LOG, "Loading param file: %s\n", fn);

        if(!(fp2 = fopen(fn, "rb"))) {
            debug(DBG_WARN, "Couldn't open param file: %s\n", fn);
            fclose(fp2);
            free(rawbuf);
            return -3;
        }

        /* Figure out how long it is, and make sure its not going to overflow
           the buffer */
        fseek(fp2, 0, SEEK_END);
        filelen = ftell(fp2);
        fseek(fp2, 0, SEEK_SET);

        if(filelen > 0x10000) {
            debug(DBG_WARN, "Param file %s too long (%l)\n", fn, filelen);
            fclose(fp2);
            free(rawbuf);
            return -3;
        }

        /* Make sure we aren't going over the max size... */
        if(filelen + offset > MAX_PARAMS_SIZE) {
            debug(DBG_WARN, "Params buffer would overflow reading %s\n", fn);
            fclose(fp2);
            free(rawbuf);
            return -3;
        }

        /* Read it in */
        fread(rawbuf + offset, 1, filelen, fp2);
        fclose(fp2);

        /* Fill in the stuff in the header first */
        checksum = sylverant_crc32(rawbuf + offset, filelen);

        param_hdr->entries[i].size = LE32(((uint32_t)filelen));
        param_hdr->entries[i].checksum = LE32(checksum);
        param_hdr->entries[i].offset = LE32(offset);
        strncpy(param_hdr->entries[i].filename, fn, 0x40);

        offset += filelen;
    }

    /* Now that the header is built, time to make the chunks */
    num_param_chunks = offset / 0x6800;

    if(offset % 0x6800) {
        ++num_param_chunks;
    }

    /* Allocate space for the array of chunks */
    param_chunks = (bb_param_chunk_pkt **)malloc(sizeof(bb_param_chunk_pkt *) *
                                                 num_param_chunks);
    if(!param_chunks) {
        debug(DBG_ERROR, "Couldn't make param chunk array:\n%s\n",
              strerror(errno));
        free(rawbuf);
        return -4;
    }

    /* Scrub it, for safe-keeping */
    memset(param_chunks, 0, sizeof(bb_param_chunk_pkt *) * num_param_chunks);

    for(i = 0; i < num_param_chunks; ++i) {
        if(offset < (i + 1) * 0x6800) {
            len = (offset % 0x6800) + 0x0C;
        }
        else {
            len = 0x680C;
        }

        param_chunks[i] = (bb_param_chunk_pkt *)malloc(len);

        if(!param_chunks[i]) {
            debug(DBG_ERROR, "Couldn't make chunk:\n%s\n", strerror(errno));
            free(rawbuf);
            return -5;
        }

        /* Fill in the chunk */
        param_chunks[i]->hdr.pkt_type = LE16(BB_PARAM_CHUNK_TYPE);
        param_chunks[i]->hdr.pkt_len = LE16(len);
        param_chunks[i]->hdr.flags = 0;
        param_chunks[i]->chunk = LE32(i);
        memcpy(param_chunks[i]->data, rawbuf + (i * 0x6800), len - 0x0C);
    }

    /* Cleanup time */
    free(rawbuf);
    chdir("../..");
    debug(DBG_LOG, "Read %" PRIu32 " files into %d chunks\n", NUM_PARAM_FILES,
          num_param_chunks);

    return 0;
}

void cleanup_param_data(void) {
    int i;

    for(i = 0; i < num_param_chunks; ++i) {
        free(param_chunks[i]);
    }

    free(param_chunks);
    param_chunks = NULL;
    num_param_chunks = 0;
    free(param_hdr);
    param_hdr = NULL;
}

int load_bb_char_data(void) {
    int i;
    char filename[64];
    FILE *fp;
    sylverant_bb_db_char_t *cur;
    uint8_t *buf, *buf2;
    long size;
    uint32_t decsize;

    chdir("blueburst");

    /* Loop through each character class and grab the defaults */
    for(i = 0; i < 12; ++i) {
        cur = &default_chars[i];
        sprintf(filename, "default_%s.nsc", classes[i]);
        debug(DBG_LOG, "Loading default character file: %s\n", filename);

        fp = fopen(filename, "rb");

        if(!fp) {
            debug(DBG_ERROR, "Missing default data for class %s\n",
                  classes[i]);
            chdir("..");
            return -1;
        }

        /* Skip over the parts we don't care about, then read in the data. */
        fseek(fp, 0x40 + sizeof(sylverant_bb_mini_char_t), SEEK_SET);
        fread(cur->autoreply, 1, 344, fp);
        fread(&cur->bank, 1, sizeof(sylverant_bank_t), fp);
        fread(cur->challenge_data, 1, 320, fp);
        fread(&cur->character, 1, sizeof(sylverant_bb_char_t), fp);
        fread(cur->guildcard_desc, 1, 176, fp);
        fread(cur->infoboard, 1, 344, fp);
        fread(&cur->inv, 1, sizeof(sylverant_inventory_t), fp);
        fread(cur->quest_data1, 1, 520, fp);
        fread(cur->quest_data2, 1, 88, fp);
        fread(cur->tech_menu, 1, 40, fp);
        fclose(fp);
    }

    /* Read the stats table */
    debug(DBG_LOG, "Loading levelup table.\n");
    fp = fopen("param/PlyLevelTbl.prs", "rb");
 
    if(!fp) {
        debug(DBG_ERROR, "Missing Blue Burst levelup table!\n");
        chdir("..");
        return -2;
    }

    /* Figure out how long it is and read it in... */
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    buf = (uint8_t *)malloc(size);
    if(!buf) {
        debug(DBG_ERROR, "Couldn't allocate space for level table.\n%s\n",
              strerror(errno));
        fclose(fp);
        chdir("..");
        return -3;
    }

    fread(buf, 1, size, fp);
    fclose(fp);

    /* Decompress the data */
    decsize = prs_decompress_size(buf);
    buf2 = (uint8_t *)malloc(decsize);

    if(!buf2) {
        debug(DBG_ERROR, "Couldn't allocate space for decompressing level "
              "table.\n%s\n", strerror(errno));
        fclose(fp);
        free(buf);
        chdir("..");
        return -4;
    }

    prs_decompress(buf, buf2);
    memcpy(&char_stats, buf2, sizeof(bb_level_table_t));

    /* Clean up... */
    free(buf);
    free(buf2);
    chdir("..");

    return 0;
}
