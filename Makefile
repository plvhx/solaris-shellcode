CC     := gcc
CFLAGS := -DTHREAD_DEBUG -DUSE_FUNCTION_TRACE -Wall -Werror
MARCH  := $(shell uname -m)
ARCH32 := -m32
ARCH64 := -m64

all:
ifeq ($(MARCH), i86pc)
	# [i386]
	$(CC) $(ARCH32) $(CFLAGS) -o 1-i386.bin 1-i386.c
	$(CC) $(ARCH32) $(CFLAGS) -o 2-i386.bin 2-i386.c
	$(CC) $(ARCH32) $(CFLAGS) -o 3-i386.bin 3-i386.c
	$(CC) $(ARCH32) $(CFLAGS) -o 4-i386.bin 4-i386.c
	$(CC) $(ARCH32) $(CFLAGS) -o 5-i386.bin 5-i386.c
	$(CC) $(ARCH32) $(CFLAGS) -o 6-i386.bin 6-i386.c
	$(CC) $(ARCH32) $(CFLAGS) -o 7-i386.bin 7-i386.c
	$(CC) $(ARCH32) $(CFLAGS) -o 8-i386.bin 8-i386.c
endif

ifeq ($(MARCH), sparc)
	# [sun4u/sparc32]
	$(CC) $(ARCH32) $(CFLAGS) -o 1-sparc32.bin 1-sparc32.c
	$(CC) $(ARCH32) $(CFLAGS) -o 2-sparc32.bin 2-sparc32.c
	$(CC) $(ARCH32) $(CFLAGS) -o 3-sparc32.bin 3-sparc32.c
	$(CC) $(ARCH32) $(CFLAGS) -o 4-sparc32.bin 4-sparc32.c
endif

clean:
	rm -f *.bin core
