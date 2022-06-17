/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2022, Paulus Gandung Prakosa
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __X86_32_H__
#define __X86_32_H__

typedef struct {
  unsigned long eax;
  unsigned long ebx;
  unsigned long ecx;
  unsigned long edx;
  unsigned long edi;
  unsigned long esi;
  unsigned long ebp;
  unsigned long esp;
} __x86_32_regs;

#define __eax(regs) ((regs)->eax)
#define __ebx(regs) ((regs)->ebx)
#define __ecx(regs) ((regs)->ecx)
#define __edx(regs) ((regs)->edx)
#define __edi(regs) ((regs)->edi)
#define __esi(regs) ((regs)->esi)
#define __ebp(regs) ((regs)->ebp)
#define __esp(regs) ((regs)->esp)

static inline void __save_eax(__x86_32_regs *regs) {
  __asm__ __volatile__("movl %%eax, %0\n" : "=r"(__eax(regs)));
}

static inline void __save_ebx(__x86_32_regs *regs) {
  __asm__ __volatile__("movl %%ebx, %0\n" : "=r"(__ebx(regs)));
}

static inline void __save_ecx(__x86_32_regs *regs) {
  __asm__ __volatile__("movl %%ecx, %0\n" : "=r"(__ecx(regs)));
}

static inline void __save_edx(__x86_32_regs *regs) {
  __asm__ __volatile__("movl %%edx, %0\n" : "=r"(__edx(regs)));
}

static inline void __save_edi(__x86_32_regs *regs) {
  __asm__ __volatile__("movl %%edi, %0\n" : "=r"(__edi(regs)));
}

static inline void __save_esi(__x86_32_regs *regs) {
  __asm__ __volatile__("movl %%esi, %0\n" : "=r"(__esi(regs)));
}

static inline void __save_ebp(__x86_32_regs *regs) {
  __asm__ __volatile__("movl %%ebp, %0\n" : "=r"(__ebp(regs)));
}

static inline void __save_esp(__x86_32_regs *regs) {
  __asm__ __volatile__("movl %%esp, %0\n" : "=r"(__esp(regs)));
}

static inline void __store_eax(__x86_32_regs *regs) {
  __asm__ __volatile__("movl %0, %%eax\n" : : "r"(__eax(regs)));
}

static inline void __store_ebx(__x86_32_regs *regs) {
  __asm__ __volatile__("movl %0, %%ebx\n" : : "r"(__ebx(regs)));
}

static inline void __store_ecx(__x86_32_regs *regs) {
  __asm__ __volatile__("movl %0, %%ecx\n" : : "r"(__ecx(regs)));
}

static inline void __store_edx(__x86_32_regs *regs) {
  __asm__ __volatile__("movl %0, %%edx\n" : : "r"(__edx(regs)));
}

static inline void __store_edi(__x86_32_regs *regs) {
  __asm__ __volatile__("movl %0, %%edi\n" : : "r"(__edi(regs)));
}

static inline void __store_esi(__x86_32_regs *regs) {
  __asm__ __volatile__("movl %0, %%esi\n" : : "r"(__esi(regs)));
}

static inline void __store_ebp(__x86_32_regs *regs) {
  __asm__ __volatile__("movl %0, %%ebp\n" : : "r"(__ebp(regs)));
}

static inline void __store_esp(__x86_32_regs *regs) {
  __asm__ __volatile__("movl %0, %%esp\n" : : "r"(__esp(regs)));
}

static inline void __x86_32_save_regs(void *ptr) {
  __x86_32_regs *regs = (__x86_32_regs *)ptr;

  __save_eax(regs);
  __save_ebx(regs);
  __save_ecx(regs);
  __save_edx(regs);
  __save_edi(regs);
  __save_esi(regs);
  __save_ebp(regs);
  __save_esp(regs);
}

static inline void __x86_32_store_regs(void *ptr) {
  __x86_32_regs *regs = (__x86_32_regs *)ptr;

  __store_eax(regs);
  __store_ebx(regs);
  __store_ecx(regs);
  __store_edx(regs);
  __store_edi(regs);
  __store_esi(regs);
  __store_ebp(regs);
  __store_esp(regs);
}

#endif /* __X86_32_H__ */
