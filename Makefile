all: rom disasm check

check: disasm rom
	md5sum new.rom galaga.rom


disasm:
	./msx_trace.py galaga.rom
	rm -f xaa xab

rom:
	z80asm galaga.asm
	split -b 8192 a.bin
	rm a.bin
	cat xaa xaa xab xab > new.rom

run: rom
	openmsx new.rom
