!   This file is part of Sylverant PSO Server
!   Copyright (C) 2018 Lawrence Sebald
!
!   This program is free software: you can redistribute it and/or modify
!   it under the terms of the GNU Affero General Public License version 3
!   as published by the Free Software Foundation.
!
!   This program is distributed in the hope that it will be useful,
!   but WITHOUT ANY WARRANTY; without even the implied warranty of
!   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
!   GNU Affero General Public License for more details.
!
!   You should have received a copy of the GNU Affero General Public License
!   along with this program.  If not, see <http://www.gnu.org/licenses/>.

! This code is sent to clients to figure out what region/version of the game
! they are running. Since v1 doesn't support 0xB2, we don't bother trying to
! detect it here, so there's only the 3 different versions of v2 to detect.
    .little
    .text
    .org        0
start:
    mov.l       us_loc, r2
    mov.l       magic, r1
    mov.l       @r2, r3
    cmp/eq      r1, r3
    bt          us_detected
    mov.l       eu_loc, r2
    mov.l       @r2, r3
    cmp/eq      r1, r3
    bt          eu_detected
    mov.l       jp_loc, r2
    mov.l       @r2, r3
    cmp/eq      r1, r3
    bt          jp_detected
    bra         end
    mov         #-1, r0
jp_detected:
    bra         end
    mov         #3, r0
eu_detected:
    bra         end
    mov         #2, r0
us_detected:
    mov         #1, r0
end:
    rts
    nop

    .balign     4
magic:
    .long       0x39393931
us_loc:
    .long       0x8c2f376c
eu_loc:
    .long       0x8c2e7d14
jp_loc:
    .long       0x8c2f1204
