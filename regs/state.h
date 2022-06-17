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

#ifndef __STATE_H__
#define __STATE_H__

#include <stddef.h>

#include "arch/sparc-32.h"
#include "arch/x86-32.h"
#include "arch/x86-64.h"

typedef struct {
  void (*__save_regs)(void *);
  void (*__store_regs)(void *);
  int __init_count;
} __state_regs_hook_t;

#define __initiate_state_regs_hook(x)                                          \
  static __state_regs_hook_t __##x = {                                         \
      .__save_regs = NULL,                                                     \
      .__store_regs = NULL,                                                    \
      .__set = 0,                                                              \
  };

#define __serialize_state_regs_hook(x) (__##x)

#define get_save_regs_fcall(regs) ((regs)->__save_regs)
#define set_save_regs_fcall(regs, fptr) ((regs)->__save_regs = (fptr))

#define get_store_regs_fcall(regs) ((regs)->__store_regs)
#define set_store_regs_fcall(regs, fptr) ((regs)->__store_regs = (fptr))

#define inc_init_count(regs) ((regs)->__init_count++)
#define dec_init_count(regs) ((regs)->__init_count--)

__initiate_state_regs_hook(current);

static inline void init_once(__state_regs_hook_t *regs) {
  if (regs->__init_count > 0)
    return;

#if (defined __sparc || defined __sparc__)
  set_save_regs_fcall(regs, __sparc32_save_regs);
  set_store_regs_fcall(regs, __sparc32_store_regs);
#elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
  set_save_regs_fcall(regs, __x86_32_save_regs);
  set_store_regs_fcall(regs, __x86_32_store_regs);
#elif defined(__x86_64__) || defined(_M_X64)
  set_save_regs_fcall(regs, __x86_64_save_regs);
  set_store_regs_fcall(regs, __x86_64_store_regs);
#endif

  inc_init_count(regs);
}

static inline void save_regs(void *ptr) {
  init_once(&__serialize_state_regs_hook(current));
  get_save_regs_fcall (&__serialize_state_regs_hook(current))(ptr);
}

static inline void store_regs(void *ptr) {
  init_once(&__serialize_state_regs_hook(current));
  get_save_regs_fcall (&__serialize_state_regs_hook(current))(ptr);
}

#endif /* __STATE_H__ */
