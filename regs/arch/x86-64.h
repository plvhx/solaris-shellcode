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

#ifndef __X86_64_H__
#define __X86_64_H__

typedef struct {
  unsigned long rax;
  unsigned long rbx;
  unsigned long rcx;
  unsigned long rdx;
  unsigned long rdi;
  unsigned long rsi;
  unsigned long rbp;
  unsigned long rsp;
  unsigned long r8;
  unsigned long r9;
  unsigned long r10;
  unsigned long r11;
  unsigned long r12;
  unsigned long r13;
  unsigned long r14;
  unsigned long r15;
} __x86_64_regs;

#define __rax(regs) ((regs)->rax)
#define __rbx(regs) ((regs)->rbx)
#define __rcx(regs) ((regs)->rcx)
#define __rdx(regs) ((regs)->rdx)
#define __rdi(regs) ((regs)->rdi)
#define __rsi(regs) ((regs)->rsi)
#define __rbp(regs) ((regs)->rbp)
#define __rsp(regs) ((regs)->rsp)

#define __r8(regs) ((regs)->r8)
#define __r9(regs) ((regs)->r9)
#define __r10(regs) ((regs)->r10)
#define __r11(regs) ((regs)->r11)
#define __r12(regs) ((regs)->r12)
#define __r13(regs) ((regs)->r13)
#define __r14(regs) ((regs)->r14)
#define __r15(regs) ((regs)->r15)

static inline void __save_rax(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %%rax, %0\n" : "=r"(__rax(regs)));
}

static inline void __save_rbx(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %%rbx, %0\n" : "=r"(__rbx(regs)));
}

static inline void __save_rcx(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %%rcx, %0\n" : "=r"(__rcx(regs)));
}

static inline void __save_rdx(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %%rdx, %0\n" : "=r"(__rdx(regs)));
}

static inline void __save_rdi(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %%rdi, %0\n" : "=r"(__rdi(regs)));
}

static inline void __save_rsi(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %%rsi, %0\n" : "=r"(__rsi(regs)));
}

static inline void __save_rbp(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %%rbp, %0\n" : "=r"(__rbp(regs)));
}

static inline void __save_rsp(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %%rsp, %0\n" : "=r"(__rsp(regs)));
}

static inline void __save_r8(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %%r8, %0\n" : "=r"(__r8(regs)));
}

static inline void __save_r9(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %%r9, %0\n" : "=r"(__r9(regs)));
}

static inline void __save_r10(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %%r10, %0\n" : "=r"(__r10(regs)));
}

static inline void __save_r11(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %%r11, %0\n" : "=r"(__r11(regs)));
}

static inline void __save_r12(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %%r12, %0\n" : "=r"(__r12(regs)));
}

static inline void __save_r13(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %%r13, %0\n" : "=r"(__r13(regs)));
}

static inline void __save_r14(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %%r14, %0\n" : "=r"(__r14(regs)));
}

static inline void __save_r15(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %%r15, %0\n" : "=r"(__r15(regs)));
}

static inline void __store_rax(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %0, %%rax\n" : : "r"(__rax(regs)));
}

static inline void __store_rbx(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %0, %%rbx\n" : : "r"(__rbx(regs)));
}

static inline void __store_rcx(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %0, %%rcx\n" : : "r"(__rcx(regs)));
}

static inline void __store_rdx(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %0, %%rdx\n" : : "r"(__rdx(regs)));
}

static inline void __store_rdi(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %0, %%rdi\n" : : "r"(__rdi(regs)));
}

static inline void __store_rsi(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %0, %%rsi\n" : : "r"(__rsi(regs)));
}

static inline void __store_rbp(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %0, %%rbp\n" : : "r"(__rbp(regs)));
}

static inline void __store_rsp(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %0, %%rsp\n" : : "r"(__rsp(regs)));
}

static inline void __store_r8(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %0, %%r8\n" : : "r"(__r8(regs)));
}

static inline void __store_r9(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %0, %%r9\n" : : "r"(__r9(regs)));
}

static inline void __store_r10(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %0, %%r10\n" : : "r"(__r10(regs)));
}

static inline void __store_r11(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %0, %%r11\n" : : "r"(__r11(regs)));
}

static inline void __store_r12(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %0, %%r12\n" : : "r"(__r12(regs)));
}

static inline void __store_r13(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %0, %%r13\n" : : "r"(__r13(regs)));
}

static inline void __store_r14(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %0, %%r14\n" : : "r"(__r14(regs)));
}

static inline void __store_r15(__x86_64_regs *regs) {
  __asm__ __volatile__("movq %0, %%r15\n" : : "r"(__r15(regs)));
}

static inline void __x86_64_save_regs(void *ptr) {
  __x86_64_regs *regs = (__x86_64_regs *)ptr;

  __save_rax(regs);
  __save_rbx(regs);
  __save_rcx(regs);
  __save_rdx(regs);
  __save_rdi(regs);
  __save_rsi(regs);
  __save_rbp(regs);
  __save_rsp(regs);
  __save_r8(regs);
  __save_r9(regs);
  __save_r10(regs);
  __save_r11(regs);
  __save_r12(regs);
  __save_r13(regs);
  __save_r14(regs);
  __save_r15(regs);
}

static inline void __x86_64_store_regs(void *ptr) {
  __x86_64_regs *regs = (__x86_64_regs *)ptr;

  __store_rax(regs);
  __store_rbx(regs);
  __store_rcx(regs);
  __store_rdx(regs);
  __store_rdi(regs);
  __store_rsi(regs);
  __store_rbp(regs);
  __store_rsp(regs);
  __store_r8(regs);
  __store_r9(regs);
  __store_r10(regs);
  __store_r11(regs);
  __store_r12(regs);
  __store_r13(regs);
  __store_r14(regs);
  __store_r15(regs);
}

#endif /* __X86_64_H__ */
