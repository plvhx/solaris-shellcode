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

#ifndef __SPARC_32__
#define __SPARC_32__

typedef struct {
  // g0 - g7
  unsigned long g0;
  unsigned long g1;
  unsigned long g2;
  unsigned long g3;
  unsigned long g4;
  unsigned long g5;
  unsigned long g6;
  unsigned long g7;

  // o0 - o7
  unsigned long o0;
  unsigned long o1;
  unsigned long o2;
  unsigned long o3;
  unsigned long o4;
  unsigned long o5;
  unsigned long o6;
  unsigned long o7;

  // l0 - l7
  unsigned long l0;
  unsigned long l1;
  unsigned long l2;
  unsigned long l3;
  unsigned long l4;
  unsigned long l5;
  unsigned long l6;
  unsigned long l7;

  // i0 - i7
  unsigned long i0;
  unsigned long i1;
  unsigned long i2;
  unsigned long i3;
  unsigned long i4;
  unsigned long i5;
  unsigned long i6;
  unsigned long i7;

  // fp
  unsigned long fp;

  // sp
  unsigned long sp;
} __sparc32_regs;

// g0 - g7
#define __g0(regs) ((regs)->g0)
#define __g1(regs) ((regs)->g1)
#define __g2(regs) ((regs)->g2)
#define __g3(regs) ((regs)->g3)
#define __g4(regs) ((regs)->g4)
#define __g5(regs) ((regs)->g5)
#define __g6(regs) ((regs)->g6)
#define __g7(regs) ((regs)->g7)

// o0 - o7
#define __o0(regs) ((regs)->o0)
#define __o1(regs) ((regs)->o1)
#define __o2(regs) ((regs)->o2)
#define __o3(regs) ((regs)->o3)
#define __o4(regs) ((regs)->o4)
#define __o5(regs) ((regs)->o5)
#define __o6(regs) ((regs)->o6)
#define __o7(regs) ((regs)->o7)

// l0 - l7
#define __l0(regs) ((regs)->l0)
#define __l1(regs) ((regs)->l1)
#define __l2(regs) ((regs)->l2)
#define __l3(regs) ((regs)->l3)
#define __l4(regs) ((regs)->l4)
#define __l5(regs) ((regs)->l5)
#define __l6(regs) ((regs)->l6)
#define __l7(regs) ((regs)->l7)

// i0 - i7
#define __i0(regs) ((regs)->i0)
#define __i1(regs) ((regs)->i1)
#define __i2(regs) ((regs)->i2)
#define __i3(regs) ((regs)->i3)
#define __i4(regs) ((regs)->i4)
#define __i5(regs) ((regs)->i5)
#define __i6(regs) ((regs)->i6)
#define __i7(regs) ((regs)->i7)

// fp
#define __fp(regs) ((regs)->fp)

// sp
#define __sp(regs) ((regs)->sp)

static inline void __save_g0(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%g0, %0\n" : "=r"(__g0(regs)));
}

static inline void __save_g1(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%g1, %0\n" : "=r"(__g1(regs)));
}

static inline void __save_g2(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%g2, %0\n" : "=r"(__g2(regs)));
}

static inline void __save_g3(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%g3, %0\n" : "=r"(__g3(regs)));
}

static inline void __save_g4(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%g4, %0\n" : "=r"(__g4(regs)));
}

static inline void __save_g5(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%g5, %0\n" : "=r"(__g5(regs)));
}

static inline void __save_g6(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%g6, %0\n" : "=r"(__g6(regs)));
}

static inline void __save_g7(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%g7, %0\n" : "=r"(__g7(regs)));
}

static inline void __store_g0(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%g0\n" : : "r"(__g0(regs)));
}

static inline void __store_g1(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%g1\n" : : "r"(__g1(regs)));
}

static inline void __store_g2(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%g2\n" : : "r"(__g2(regs)));
}

static inline void __store_g3(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%g3\n" : : "r"(__g3(regs)));
}

static inline void __store_g4(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%g4\n" : : "r"(__g4(regs)));
}

static inline void __store_g5(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %g5\n" : : "r"(__g5(regs)));
}

static inline void __store_g6(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%g6\n" : : "r"(__g6(regs)));
}

static inline void __store_g7(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%g7\n" : : "r"(__g7(regs)));
}

static inline void __save_o0(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%o0, %0\n" : "=r"(__o0(regs)));
}

static inline void __save_o1(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%o1, %0\n" : "=r"(__o1(regs)));
}

static inline void __save_o2(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%o2, %0\n" : "=r"(__o2(regs)));
}

static inline void __save_o3(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%o3, %0\n" : "=r"(__o3(regs)));
}

static inline void __save_o4(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%o4, %0\n" : "=r"(__o4(regs)));
}

static inline void __save_o5(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%o5, %0\n" : "=r"(__o5(regs)));
}

static inline void __save_o6(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%o6, %0\n" : "=r"(__o6(regs)));
}

static inline void __save_o7(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%o7, %0\n" : "=r"(__o7(regs)));
}

static inline void __store_o0(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%o0\n" : : "r"(__o0(regs)));
}

static inline void __store_o1(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%o1\n" : : "r"(__o1(regs)));
}

static inline void __store_o2(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%o2\n" : : "r"(__o2(regs)));
}

static inline void __store_o3(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%o3\n" : : "r"(__o3(regs)));
}

static inline void __store_o4(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%o4\n" : : "r"(__o4(regs)));
}

static inline void __store_o5(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%o5\n" : : "r"(__o5(regs)));
}

static inline void __store_o6(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%o6\n" : : "r"(__o6(regs)));
}

static inline void __store_o7(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%o7\n" : : "r"(__o7(regs)));
}

static inline void __save_l0(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%l0, %0\n" : "=r"(__l0(regs)));
}

static inline void __save_l1(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%l1, %0\n" : "=r"(__l1(regs)));
}

static inline void __save_l2(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%l2, %0\n" : "=r"(__l2(regs)));
}

static inline void __save_l3(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%l3, %0\n" : "=r"(__l3(regs)));
}

static inline void __save_l4(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%l4, %0\n" : "=r"(__l4(regs)));
}

static inline void __save_l5(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%l5, %0\n" : "=r"(__l5(regs)));
}

static inline void __save_l6(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%l6, %0\n" : "=r"(__l6(regs)));
}

static inline void __save_l7(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%l7, %0\n" : "=r"(__l7(regs)));
}

static inline void __store_l0(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%l0\n" : : "r"(__l0(regs)));
}

static inline void __store_l1(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%l1\n" : : "r"(__l1(regs)));
}

static inline void __store_l2(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%l2\n" : : "r"(__l2(regs)));
}

static inline void __store_l3(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%l3\n" : : "r"(__l3(regs)));
}

static inline void __store_l4(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%l4\n" : : "r"(__l4(regs)));
}

static inline void __store_l5(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%l5\n" : : "r"(__l5(regs)));
}

static inline void __store_l6(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%l6\n" : : "r"(__l6(regs)));
}

static inline void __store_l7(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%l7\n" : : "r"(__l7(regs)));
}

static inline void __save_i0(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%i0, %0\n" : "=r"(__i0(regs)));
}

static inline void __save_i1(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%i1, %0\n" : "=r"(__i1(regs)));
}

static inline void __save_i2(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%i2, %0\n" : "=r"(__i2(regs)));
}

static inline void __save_i3(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%i3, %0\n" : "=r"(__i3(regs)));
}

static inline void __save_i4(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%i4, %0\n" : "=r"(__i4(regs)));
}

static inline void __save_i5(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%i5, %0\n" : "=r"(__i5(regs)));
}

static inline void __save_i6(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%i6, %0\n" : "=r"(__i6(regs)));
}

static inline void __save_i7(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%i7, %0\n" : "=r"(__i7(regs)));
}

static inline void __store_i0(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%i0\n" : : "r"(__i0(regs)));
}

static inline void __store_i1(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%i1\n" : : "r"(__i1(regs)));
}

static inline void __store_i2(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%i2\n" : : "r"(__i2(regs)));
}

static inline void __store_i3(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%i3\n" : : "r"(__i3(regs)));
}

static inline void __store_i4(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%i4\n" : : "r"(__i4(regs)));
}

static inline void __store_i5(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%i5\n" : : "r"(__i5(regs)));
}

static inline void __store_i6(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%i6\n" : : "r"(__i6(regs)));
}

static inline void __store_i7(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%i7\n" : : "r"(__i7(regs)));
}

static inline void __save_fp(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%fp, %0\n" : "=r"(__fp(regs)));
}

static inline void __store_fp(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%fp\n" : : "r"(__fp(regs)));
}

static inline void __save_sp(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %%sp, %0\n" : "=r"(__sp(regs)));
}

static inline void __store_sp(__sparc32_regs *regs) {
  __asm__ __volatile__("mov %0, %%sp\n" : : "r"(__sp(regs)));
}

static inline void __sparc32_save_regs(void *ptr) {
  __sparc32_regs *regs = (__sparc32_regs *)ptr;

  // g0 - g7
  __save_g0(regs);
  __save_g1(regs);
  __save_g2(regs);
  __save_g3(regs);
  __save_g4(regs);
  __save_g5(regs);
  __save_g6(regs);
  __save_g7(regs);

  // o0 - o7
  __save_o0(regs);
  __save_o1(regs);
  __save_o2(regs);
  __save_o3(regs);
  __save_o4(regs);
  __save_o5(regs);
  __save_o6(regs);
  __save_o7(regs);

  // l0 - l7
  __save_l0(regs);
  __save_l1(regs);
  __save_l2(regs);
  __save_l3(regs);
  __save_l4(regs);
  __save_l5(regs);
  __save_l6(regs);
  __save_l7(regs);

  // i0 - i7
  __save_i0(regs);
  __save_i1(regs);
  __save_i2(regs);
  __save_i3(regs);
  __save_i4(regs);
  __save_i5(regs);
  __save_i6(regs);
  __save_i7(regs);

  // fp
  __save_fp(regs);

  // sp
  __save_sp(regs);
}

static inline void __sparc32_store_regs(void *ptr) {
  __sparc32_regs *regs = (__sparc32_regs *)ptr;

  // g0 - g7
  __store_g0(regs);
  __store_g1(regs);
  __store_g2(regs);
  __store_g3(regs);
  __store_g4(regs);
  __store_g5(regs);
  __store_g6(regs);
  __store_g7(regs);

  // o0 - o7
  __store_o0(regs);
  __store_o1(regs);
  __store_o2(regs);
  __store_o3(regs);
  __store_o4(regs);
  __store_o5(regs);
  __store_o6(regs);
  __store_o7(regs);

  // l0 - l7
  __store_l0(regs);
  __store_l1(regs);
  __store_l2(regs);
  __store_l3(regs);
  __store_l4(regs);
  __store_l5(regs);
  __store_l6(regs);
  __store_l7(regs);

  // i0 - i7
  __store_i0(regs);
  __store_i1(regs);
  __store_i2(regs);
  __store_i3(regs);
  __store_i4(regs);
  __store_i5(regs);
  __store_i6(regs);
  __store_i7(regs);

  // fp
  __store_fp(regs);

  // sp
  __store_sp(regs);
}

#endif /* __SPARC_32__ */
