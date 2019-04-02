all: rom

rom:
	./msx_trace.py galaga.rom
	rm -f xaa xab
	z80asm galaga.asm
	split -b 8192 a.bin
	cat xaa xaa xab xab > a.bin
	md5sum a.bin galaga.rom
