### SunOS Solaris (x86 / x86_64) shellcode

```
[i386]
- SunOS (Solaris) / x86 execve("/bin/sh", {"/bin/sh", NULL}, NULL) 30 bytes shellcode
- SunOS (Solaris) / x86 '/usr/bin/cat /etc/passwd' 54 bytes shellcode
- SunOS (Solaris) / x86 '/usr/bin/chmod 0777 /etc/passwd' 77 bytes shellcode
- SunOS (Solaris) / x86 setuid(0) + execve("/bin/sh", {"/bin/sh", NULL}, NULL) 39 bytes shellcode
- SunOS (Solaris) / x86 setgid(0) + execve("/bin/sh", {"/bin/sh", NULL}, NULL) 39 bytes shellcode
- SunOS (Solaris) / x86 setuid(0) + setgid(0) + execve("/bin/sh", {"/bin/sh", NULL}, NULL) 48 bytes shellcode
- SunOS (Solaris) / x86 (connectback / reverse shell) TCP:9898 149 bytes shellcode
- SunOS (Solaris) / x86 (port bind / bindshell) TCP:9898 170 bytes shellcode

[sparc32/sun4u]
- SunOS (Solaris) / (sun4u / sparc32) execve("/bin/sh", {"/bin/sh", NULL}, NULL) 85 bytes shellcode

'make' command in Solaris sucks. So, i use 'gmake' instead of 'make'. :(
```
