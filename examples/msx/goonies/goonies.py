#!/usr/bin/env python
# (c) 2019 Felipe Correa da Silva Sanches <juca@members.fsf.org>
# Released under the terms of the GNU GPL version 3 or later.
#

RELOCATION_BLOCKS = (
# physical, logical, length 
   (0x0000,  0x4000, 0x8000),
)

ENTRY_POINTS = [
  0x406a, # main entry-point
  0x4028, # interrupt handler routine called from 0xFD9B
]

KNOWN_VARS = {
  0x4000: ("ROM_HEADER", "label"),
  0x43E7: ("JUMP_TABLE_43E7", "jump_table", 1), # referenced from 0x40EA
}

KNOWN_SUBROUTINES = {
  0x406a: ("ENTRY_POINT", ""),
}

# Stack manipulation instructions found at:
#
STACK_WHITELIST = [
  0x4097, # stack pointer setup: "ld sp, 0xE600"
]


import sys
from exectrace import ERROR
from exectrace.msx import MSX_Trace

if len(sys.argv) != 2:
  print("usage: {} <filename.rom>".format(sys.argv[0]))
else:
  gamerom = sys.argv[1]
  print("disassembling {}...".format(gamerom))

  trace = MSX_Trace(gamerom,
                    loglevel=ERROR,
                    relocation_blocks=RELOCATION_BLOCKS,
                    variables=KNOWN_VARS,
                    subroutines=KNOWN_SUBROUTINES,
                    stack_whitelist=STACK_WHITELIST)

  trace.run(entry_points=ENTRY_POINTS)
  trace.print_jp_HLs()
  trace.print_stack_manipulation()
  trace.save_disassembly_listing("{}.asm".format(gamerom.split(".")[0]))

