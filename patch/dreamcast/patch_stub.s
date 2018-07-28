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

! This code is prepended to any patches sent to the client through packet 0xB2.
! It is responsible for unpacking the patches and applying them.
    .little
    .text
    .org        0
start:
    mova        data_start, r0      ! Grab the patch header address
    mov         #24, r2             ! This is useful for many things...
    mov         #0x8c, r6           ! This will be needed for fixing addresses
    mov         r0, r7              ! We need r0 for other things below
    mov.l       @r7+, r1            ! Grab the count of patches
    shld        r2, r6              ! r6 = 0x8c000000 (base of cached ram)
    neg         r2, r2              ! r2 is now -24, as we need it below.
patch_loop:
    tst         r1, r1              ! T = 1 if count = 0
    bt          end                 ! If we're done, then get outta here
    dt          r1                  ! Subtract one from the patch count
    mov.l       @r7+, r0            ! Read address/control
    mov.l       @r7+, r4            ! We'll always use this, at least
    mov         r0, r5              ! Move the copy of the address we'll use
    shll8       r5                  ! Get rid of the control byte...
    shlr8       r5                  ! ...and readjust the rest of the pointer
    shld        r2, r0              ! Move control byte to lsb
    or          r6, r5              ! Get final address by pasting in the MSB
    tst         #0xE0, r0           ! ctl: 000 -> patch32
    bt          patch32
    tst         #0x60, r0           ! ctl: 100 -> patch16
    bt          patch16
    tst         #0xA0, r0           ! ctl: 010 -> patch8
    bt          patch8
    tst         #0xC0, r0           ! ctl: 001 -> multi32
    bt          multi32
    tst         #0x40, r0           ! ctl: 101 -> multi16
    bt          multi16
    tst         #0x80, r0           ! ctl: 011 -> multi8
    bt          multi8
block32_loop:                       ! ctl: 11X -> block32
    mov.l       @r7+, r0            ! Read data
    dt          r4                  ! Sets T if count reaches 0
    mov.l       r0, @r5             ! Write data
    bf/s        block32_loop        ! If we have more to do, loop
    add         #4, r0              ! Increment the address
patch32:
    bra         patch_loop          ! Do the next patch
    mov.l       r4, @r5             ! After writing the data
patch16:
    bra         patch_loop          ! Do the next patch
    mov.w       r4, @r5             ! After writing the data
patch8:
    bra         patch_loop          ! Do the next patch
    mov.b       r4, @r5             ! After writing the data
multi32:
    mov.l       @r7+, r0            ! Read Data
    dt          r4                  ! We ignore this T bit set
    mov.l       r0, @r5             ! Write first data
multi32_loop:
    dt          r4                  ! Sets T bit if count reaches 0
    mov.l       @r7+, r5            ! Read address
    bf/s        multi32_loop        ! If we have more to do, loop
    mov.l       r0, @r5             ! Write data
    bra         patch_loop          ! Do the next patch
    nop
multi16:
    mov.l       @r7+, r0            ! Read Data
    dt          r4                  ! We ignore this T bit set
    mov.w       r0, @r5             ! Write first data
multi16_loop:
    dt          r4                  ! Sets T bit if count reaches 0
    mov.l       @r7+, r5            ! Read address
    bf/s        multi16_loop        ! If we have more to do, loop
    mov.w       r0, @r5             ! Write data
    bra         patch_loop          ! Do the next patch
    nop
multi8:
    mov.l       @r7+, r0            ! Read Data
    dt          r4                  ! We ignore this T bit set
    mov.b       r0, @r5             ! Write first data
multi8_loop:
    dt          r4                  ! Sets T bit if count reaches 0
    mov.l       @r7+, r5            ! Read address
    bf/s        multi8_loop         ! If we have more to do, loop
    mov.b       r0, @r5             ! Write data
    bra         patch_loop          ! Do the next patch
    nop
end:
    rts                             ! Return to the caller...
    mov         #0, r0              ! ...with status 0.

    .balign     4
data_start:
    ! Data gets placed here by login_server.
