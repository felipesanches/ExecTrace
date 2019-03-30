# exec_trace.py

Offers a CPU-agnostic mechanism for analysing binaries by mapping all possible code-paths.
In order to use it, one needs to provide a child-class that inherits from the abtract ExecTrace class.
One example is the MSX disassembler below.

Yet another example is the tooling for disassembling the bytecode of the virtual machine of the Another World game, by Eric Chahi, which I implemented in a separate repo at: https://github.com/felipesanches/AnotherWorld_VMTools/

# msx_trace.py

Targetting the Z80 CPU and the MSX1 architecture. Initially focused on generating a nice disassembly of the Galaga ROM, so there are a few hardcoded jump_table addresses and the entry_point. But later I indend to cleanup and separate those galaga-specific portions and keep the code generic to disassemble other MSX ROMs.

This works perfectly for disassembling the Galaga ROM, but surely still lacks support for CPU instructions not used in this particular ROM.
