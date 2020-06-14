#!/usr/bin/env python
# (c) 2019 Felipe Correa da Silva Sanches <juca@members.fsf.org>
# Released under the terms of the GNU GPL version 3 or later.
#

RELOCATION_BLOCKS = (
# physical, logical, length 
   (0x0000,  0x4000, 0x2000),
#  (0x2000,  0x6000, 0x2000), # duplicate, ignore.
   (0x4000,  0x8000, 0x2000),
#  (0x6000,  0xA000, 0x2000), # duplicate, ignore.
)

ENTRY_POINTS = [
  0x4017, # main entry-point
  0x404C, # interrupt handler
#------ Guesses: -----------
#  0x44A1,
#  0x44AA,
#  0x44B9,
#  0x44FC,
#  0x4550, 
]

KNOWN_VARS = {
  0x4000: ("ROM_HEADER", "label"),
  0x4010: ("ROM_TITLE", "n-1_str"),
  0x8675: ("GREAT_STR", "str", 6),
  0x997B: ("NAMCO_TILES", "gfx"),
  0x9A23: ("A_Z_TILES", "gfx"),
  0x9B1B: ("LIFE", "gfx"),
  0x9CA3: ("SHIP_00", "gfx"), # 16 bytes
  0x9CB3: ("SHIP_45", "gfx"), # 32 bytes
  0x9CD3: ("MOTHERSHIP_A_00", "gfx"), # 16 bytes
  0x9CE3: ("MOTHERSHIP_B_00", "gfx"), # 16 bytes
  0x9CF3: ("MOTHERSHIP_B_45", "gfx"), # 32 bytes
  0x90E8: ("JUMP_TABLE_90E8", "jump_table", 6),

#------
  0x4197: ("JUMP_TABLE_4197", "jump_table", 11),
  0x5357: ("JUMP_TABLE_5357", "jump_table", 12),
  0x5BE5: ("POINTERS_5BE5", "pointers", 9),
  0x95ED: ("POINTERS_95ED", "pointers", 8), # Note: A jump table would lead to weird BIOS call addresses...
  0x95FD: ("JUMP_TABLE_95FD", "jump_table", 13),
  0x97EC: ("POINTERS_97EC", "pointers", 3),
  0x97F2: ("LABEL_97F2", "label"), #gfx?
  0x980C: ("LABEL_980C", "label"), #gfx?
  0x98E6: ("LABEL_98E6", "label"), #gfx?
}

KNOWN_SUBROUTINES = {
  0x4017: ("ENTRY_POINT", ""),
  0x404A: ("LOOP", "wait for interrupts"),
  0x404C: ("INTERRUPT_HANDLER", ""),
  0x907E: ("_EXPLOSION_NOISE", ""),
  0x8A9C: ("SETUP_GRAPHICS_MODE_1", ""),
  0x8AA1: ("SETUP_GRAPHICS_MODE_2", ""),
}

# Stack manipulation instructions found at:
#
STACK_WHITELIST = [
 0x4026, # ld sp, 0xE700 # Stack init right after ENTRY_POINT
 0x404E, # ld sp, 0xE700 # Stack init at INTERRUPT_HANDLER 
# 0x4066 = suspeito.
# 0x4169 / 0x416C = suspeitos.
 0x8AE5, 0x8AF6, # OK
]


import sys
from exec_trace import ERROR
from msx_trace import MSX_Trace

if len(sys.argv) != 2:
  print("usage: {} <filename.rom>".format(sys.argv[0]))
else:
  gamerom = sys.argv[1]
  print("disassembling {}...".format(gamerom))

  trace = MSX_Trace(gamerom,
                    loglevel=0,
                    relocation_blocks=RELOCATION_BLOCKS,
                    variables=KNOWN_VARS,
                    subroutines=KNOWN_SUBROUTINES,
                    stack_whitelist=STACK_WHITELIST)

  trace.run(entry_points=ENTRY_POINTS)
  trace.print_jp_HLs()
  trace.print_stack_manipulation()
  trace.save_disassembly_listing("{}.asm".format(gamerom.split(".")[0]))
  #trace.generate_graph(True)

