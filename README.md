### SunOS Solaris (x86 / x86_64) shellcode

```
- SunOS (Solaris) / x86 execve("/bin/sh", {"/bin/sh", NULL}, NULL) 30 bytes shellcode
- SunOS (Solaris) / x86 '/usr/bin/cat /etc/passwd' 54 bytes shellcode
- SunOS (Solaris) / x86 '/usr/bin/chmod 0777 /etc/passwd' 77 bytes shellcode
- SunOS (Solaris) / x86 setuid(0) + execve("/bin/sh", {"/bin/sh", NULL}, NULL) 39 bytes shellcode
- SunOS (Solaris) / x86 setgid(0) + execve("/bin/sh", {"/bin/sh", NULL}, NULL) 39 bytes shellcode

'make' command in Solaris sucks. So, i use 'gmake' instead of 'make'. :(
```
