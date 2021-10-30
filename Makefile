CC := gcc
CFLAGS := -Wall -Werror
ARCH32 := -m32
ARCH64 := -m64

all:
	$(CC) $(ARCH32) $(CFLAGS) -o 1.bin 1.c
	$(CC) $(ARCH32) $(CFLAGS) -o 2.bin 2.c
clean:
	rm -f *.bin core
