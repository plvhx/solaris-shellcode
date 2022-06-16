CC := gcc
CFLAGS := -Wall -Werror
ARCH32 := -m32
ARCH64 := -m64

all:
	# [i386]
	$(CC) $(ARCH32) $(CFLAGS) -o 1-i386.bin 1-i386.c
	$(CC) $(ARCH32) $(CFLAGS) -o 2-i386.bin 2-i386.c
	$(CC) $(ARCH32) $(CFLAGS) -o 3-i386.bin 3-i386.c
	$(CC) $(ARCH32) $(CFLAGS) -o 4-i386.bin 4-i386.c
	$(CC) $(ARCH32) $(CFLAGS) -o 5-i386.bin 5-i386.c
	$(CC) $(ARCH32) $(CFLAGS) -o 6-i386.bin 6-i386.c
	$(CC) $(ARCH32) $(CFLAGS) -o 7-i386.bin 7-i386.c
	$(CC) $(ARCH32) $(CFLAGS) -o 8-i386.bin 8-i386.c

	# [sun4u/sparc32]
	$(CC) $(ARCH32) $(CFLAGS) -o 1-sparc32.bin 1-sparc32.c
	$(CC) $(ARCH32) $(CFLAGS) -o 2-sparc32.bin 2-sparc32.c
	$(CC) $(ARCH32) $(CFLAGS) -o 3-sparc32.bin 3-sparc32.c
	$(CC) $(ARCH32) $(CFLAGS) -o 4-sparc32.bin 4-sparc32.c

clean:
	rm -f *.bin core
