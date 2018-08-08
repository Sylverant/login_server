#   This file is part of Sylverant PSO Server
#   Copyright (C) 2018 Lawrence Sebald
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU Affero General Public License version 3
#   as published by the Free Software Foundation.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU Affero General Public License for more details.
#
#   You should have received a copy of the GNU Affero General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

# This code is sent to clients to figure out what region/version of the game
# they are running.
# Note that the Plus versions of PSO Episode I & II will never call this code,
# due to the removal of packet 0xB2 from them, but they're still accounted for
# in here for historical reasons.
    .text
start:
    lis     5, 0x3139                   # All comparisons are against '1999'
    ori     5, 5, 0x3939
    lis     6, 0x8044                   # Upper 16-bits of all important addrs.
    xor     3, 3, 3                     # Clear r3
    ori     7, 6, 0x587c                # US v1.0 @ 0x8044587c
    lwz     7, 0(7)                     # Read value into r7
    addi    3, 3, 1                     # r3 = 1
    cmplw   5, 7                        # Does r7 equal '1999'?
    beq     done
    ori     7, 6, 0x5cfc                # US v1.01 @ 0x80445cfc
    lwz     7, 0(7)                     # Read value into r7
    addi    3, 3, 1                     # r3 = 2
    cmplw   5, 7                        # Does r7 equal '1999'?
    beq     done
    ori     7, 6, 0x959c                # US Plus @ 0x8044959c
    lwz     7, 0(7)                     # Read value into r7
    addi    3, 3, 1                     # r3 = 3
    cmplw   5, 7                        # Does r7 equal '1999'?
    beq     done
    ori     7, 6, 0x93f4                # EU @ 0x804493f4
    lwz     7, 0(7)                     # Read value into r7
    addi    3, 3, 1                     # r3 = 4
    cmplw   5, 7                        # Does r7 equal '1999'?
    beq     done
    ori     7, 6, 0x4ac4                # JP v1.02 @ 0x80444ac4
    lwz     7, 0(7)                     # Read value into r7
    addi    3, 3, 1                     # r3 = 5
    cmplw   5, 7                        # Does r7 equal '1999'?
    beq     done
    ori     7, 6, 0x78e4                # JP v1.03 @ 0x804478e4
    lwz     7, 0(7)                     # Read value into r7
    addi    3, 3, 1                     # r3 = 6
    cmplw   5, 7                        # Does r7 equal '1999'?
    beq     done
    ori     7, 6, 0x96bc                # JP Plus @ 0x804496bc
    lwz     7, 0(7)                     # Read value into r7
    addi    3, 3, 1                     # r3 = 7
    beq     done
    addi    3, 3, -8                    # Failed to find anything, r3 = -1.
done:
    blr
