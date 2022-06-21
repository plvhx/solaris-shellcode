/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2022, Paulus Gandung Prakosa
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
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
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __COMPILER_H__
#define __COMPILER_H__

#include "../regs/state.h"

#ifndef __constant
#if defined(__builtin_constant_p)
#define __constant(x) __builtin_constant_p(x)
#else
#define __constant(x) (0)
#endif
#endif

#ifndef __expect
#if defined(__builtin_expect)
#define __expect(x, e) __builtin_expect(x, e)
#else
#define __expect(x, e) (x)
#endif
#endif

#ifndef __aligned
#define __aligned(x) __attribute__((aligned(x)))
#endif

#ifndef __section
#define __section(x) __attribute__((__section__(x)))
#endif

#ifdef USE_FUNCTION_TRACE

struct ftrace_branch_data {
  const char *func;
  const char *file;
  unsigned line;

  union {
    struct {
      unsigned long correct;
      unsigned long incorrect;
    };

    struct {
      unsigned long miss;
      unsigned long hit;
    };

    unsigned long miss_hit[2];
  };
};

struct ftrace_likely_data {
  struct ftrace_branch_data data;
  unsigned long constant;
};

static inline void trace_likely_condition(struct ftrace_likely_data *f, int val,
                                          int expect) {}

static void ftrace_likely_update(struct ftrace_likely_data *f, int val,
                                 int expect, int is_constant) {
  save_regs(&__serialize_regs(cregs));

  if (is_constant) {
    f->constant++;
    val = expect;
  }

  trace_likely_condition(f, val, expect);

  if (val == expect) {
#if defined(__sparc) || defined(__sparc__)
    // fix this using sparc atomic locking
    // mechanism in assembly.
    f->data.correct++;
#elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
    __asm__ __volatile__("lock; incl %0\n"
                         : "+m"(f->data.correct)
                         :
                         : "memory");
#elif defined(__x86_64__) || defined(_M_X64)
    __asm__ __volatile__("lock; incq %0\n"
                         : "+m"(f->data.correct)
                         :
                         : "memory");
#endif
  } else {
#if defined(__sparc) || defined(__sparc__)
    // fix this using sparc atomic locking
    // mechanism in assembly.
    f->data.incorrect++;
#elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
    __asm__ __volatile__("lock; incl %0\n"
                         : "+m"(f->data.incorrect)
                         :
                         : "memory");
#elif defined(__x86_64__) || defined(_M_X64)
    __asm__ __volatile__("lock; incq %0\n"
                         : "+m"(f->data.incorrect)
                         :
                         : "memory");
#endif
  }

  store_regs(&__serialize_regs(cregs));
}

#define __branch_check__(x, expect, is_constant)                               \
  ({                                                                           \
    long __r;                                                                  \
    static struct ftrace_likely_data __aligned(4)                              \
        __section(".sect.ftrace_annotated_branch") __f = {                     \
            .data.func = __func__,                                             \
            .data.file = __FILE__,                                             \
            .data.line = __LINE__,                                             \
        };                                                                     \
    __r = __expect(!!(x), expect);                                             \
    ftrace_likely_update(&__f, __r, expect, is_constant);                      \
    __r;                                                                       \
  })

#ifndef likely
#define likely(x) (__branch_check__(x, 1, __constant(x)))
#endif

#ifndef unlikely
#define unlikely(x) (__branch_check__(x, 0, __constant(x)))
#endif

#else

#ifndef likely
#define likely(x) __expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __expect(!!(x), 0)
#endif

#endif

#endif /* __COMPILER_H__ */
