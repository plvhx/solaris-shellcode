CC := gcc
CFLAGS := -m32 -Wall -Werror

all:
	$(CC) $(CFLAGS) -o 1.bin 1.c
clean:
	rm -f *.bin core
