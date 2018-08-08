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

# This code is prepended to any patches sent to the client through packet 0xB2.
# It is responsible for unpacking the patches and applying them.

    .text
start:
    mflr        9                       # Curse you PowerPC for not having
    bl          before_data             # PC-relative loads...
    mflr        4                       # r4 now has data_start's address
    lwz         3, 0(4)                 # r3 = count of patches
    cmplwi      3, 0                    # Make sure we have something
    beq         end                     # If not, bail now
    mtctr       3                       # CTR = count of patches
    addi        4, 4, 4                 # Point r4 at the first patch
patch_loop:
    lwz         5, 0(4)                 # Read the patch address/flags into r5
    lwz         6, 4(4)                 # We always use this one too
    addi        4, 4, 8                 # Move the pointer up
    srwi        7, 5, 29                # Get the type bits (into r7)
    rlwinm      5, 5, 0, 3, 31          # Mask out the type bits...
    oris        5, 5, 0x8000            # Fix the address to ram
    cmplwi      7, 0                    # ctl: 000 -> patch32
    beq         patch32
    cmplwi      7, 4                    # ctl: 100 -> patch16
    beq         patch16
    cmplwi      7, 2                    # ctl: 010 -> patch8
    beq         patch8
    mfctr       10                      # Move the counter to r10
    mtctr       6                       # All the rest have a counter now in r6
    cmplwi      7, 1                    # ctl: 001 -> multi32
    beq         multi32
    cmplwi      7, 5                    # ctl: 101 -> multi16
    beq         multi16
    cmplwi      7, 3                    # ctl: 011 -> multi8
    beq         multi8
block32:                                # Otherwise, fall through...
    mr          8, 5
    lwz         7, 0(4)                 # Read the data value
    stw         7, 0(5)                 # Store it
    addi        4, 4, 4                 # Increment both pointers
    addi        5, 5, 4
    bdnz        block32                 # If there's more to do, continue
block32_inval:                          # Otherwise, clean up the cache
    dcbst       0, 8                    # Store the dcache
    sync                                # Wait for it to finish
    icbi        0, 8                    # Invalidate the icache
    addi        8, 8, 32                # Move to the next block
    cmplw       8, 5                    # Compare current to the last written
    blt         block32_inval           # Keep going, if needed
done_multi_block:                       # Otherwise, fall through
    mtctr       10                      # Restore the counter to be the total
done_patch:
    bdnz        patch_loop              # Do the next patch, if any are left
    b           end                     # Otherwise, exit
patch16:
    sth         6, 0(5)                 # Store the value
    b           done_single
patch8:
    stb         6, 0(5)                 # Store the value
    b           done_single
patch32:
    stw         6, 0(5)                 # Store the value
done_single:
    dcbst       0, 5                    # Store the value out of the dcache
    sync                                # Ensure the writes are all done
    icbi        0, 5                    # Invalidate the icache
    b           done_patch
multi32:
    lwz         7, 0(4)                 # Read the data value
    stw         7, 0(5)                 # Store the first value
    bl          inval_multi             # Invalidate the icache
    addi        4, 4, 4                 # Increment the pointer
    bdz         done_multi_block        # In case there's something naughty...
multi32_loop:
    lwz         5, 0(4)                 # Read the address
    stw         7, 0(5)                 # Store the data at the next address
    bl          inval_multi             # Invalidate the icache
    addi        4, 4, 4                 # Increment the pointer
    bdnz        multi32_loop            # If there's more, continue
    b           done_multi_block        # Otherwise, end it now.
multi16:
    lwz         7, 0(4)                 # Read the data value
    sth         7, 0(5)                 # Store the first value
    bl          inval_multi             # Invalidate the icache
    addi        4, 4, 4                 # Increment the pointer
    bdz         done_multi_block        # In case there's something naughty...
multi16_loop:
    lwz         5, 0(4)                 # Read the address
    sth         7, 0(5)                 # Store the data at the next address
    bl          inval_multi             # Invalidate the icache
    addi        4, 4, 4                 # Increment the pointer
    bdnz        multi16_loop            # If there's more, continue
    b           done_multi_block        # Otherwise, end it now.
multi8:
    lwz         7, 0(4)                 # Read the data value
    stb         7, 0(5)                 # Store the first value
    bl          inval_multi             # Invalidate the icache
    addi        4, 4, 4                 # Increment the pointer
    bdz         done_multi_block        # In case there's something naughty...
multi8_loop:
    lwz         5, 0(4)                 # Read the address
    stb         7, 0(5)                 # Store the data at the next address
    bl          inval_multi             # Invalidate the icache
    addi        4, 4, 4                 # Increment the pointer
    bdnz        multi8_loop             # If there's more, continue
    b           done_multi_block        # Otherwise, end it now.
inval_multi:
    dcbst       0, 5                    # Store the value out of the dcache
    sync                                # Ensure the writes are all done
    icbi        0, 5                    # Invalidate the icache
    blr                                 # Return to the caller
end:
    xor         3, 3, 3                 # Clear r3
    isync                               # Wait for the icache to catch up
    mtlr        9                       # Restore the link register
    blr                                 # Return to the game...
before_data:
    blrl                                # Here to find out where data_start is
data_start:
    # Data gets placed here by login_server.
