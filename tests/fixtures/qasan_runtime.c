/* Build with -fno-builtin and run under AFL_USE_QASAN=1 afl-qemu-trace.
   No argument: successful initialization, overlap, and exact-range checks.
   oob-load/oob-store/uaf must report a QASAN error, never reach return 3. */
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "qasan.h"

int main(int argc, char **argv) {

#if defined(__x86_64__)
  /* A ModRM read after the three-byte action would consume the following
     REX prefix, leaving r8 unchanged instead of receiving the result. */
  register uintptr_t action_result __asm__("r8") = UINTPTR_MAX;
  __asm__ volatile("mov %1, %%eax\n\txor %%edi, %%edi\n\t"
                   ".byte 0x0f, 0x3a, 0xf2\n\tmov %%rax, %%r8"
                   : "+r"(action_result) : "i"(QASAN_ACTION_SWAP_STATE)
                   : "rax", "rdi", "cc", "memory");
  if (action_result > 1) return 4;
#endif

  unsigned char *p = malloc(259);
  unsigned char *q = calloc(259, 1);
  assert(p && q);
  for (size_t i = 0; i < 259; ++i) {

    assert(p[i] == 0xff);
    assert(q[i] == 0);
    p[i] = (unsigned char)i;

  }

  if (argc > 1) {

    if (!strcmp(argv[1], "oob-load")) memcpy(q, p + 1, 259);
    else if (!strcmp(argv[1], "oob-store")) memcpy(q + 1, p, 259);
    else if (!strcmp(argv[1], "interior-poison")) {

      QASAN_CALL3(QASAN_ACTION_POISON, p + 128, 8, ASAN_USER);
      memcpy(q, p, 259);

    } else if (!strcmp(argv[1], "uaf")) {

      uintptr_t saved = (uintptr_t)p;
      free(p);
      memcpy(q, (void *)saved, 259);

    }
    return 3;

  }

  /* Unaligned head, multiple shadow words, partial last granule. */
  memcpy(q + 1, p + 1, 258);
  for (size_t i = 1; i < 259; ++i) assert(q[i] == (unsigned char)i);

  memmove(p + 1, p, 258);
  for (size_t i = 1; i < 259; ++i) assert(p[i] == (unsigned char)(i - 1));
  memmove(p, p + 1, 258);
  for (size_t i = 0; i < 258; ++i) assert(p[i] == (unsigned char)i);
  memmove(p, p, 259);
  memmove(p + 259, p + 259, 0);

  /* Every tail length and source/destination alignment, including a pointer
     exactly at the allocation boundary for a zero-length operation. */
  for (size_t len = 0; len < 32; ++len) {

    unsigned char *r = malloc(len + 7);
    assert(r);
    for (size_t offset = 0; offset < 8; ++offset) {

      for (size_t i = 0; i < len + 7; ++i) r[i] = 0x3c;
      memset(r + offset, 0x1a5, len);
      for (size_t i = 0; i < len + 7; ++i)
        assert(r[i] == (i >= offset && i < offset + len ? 0xa5 : 0x3c));
      memcpy(r + offset, p + offset, len);
      for (size_t i = 0; i < len + 7; ++i)
        assert(r[i] == (i >= offset && i < offset + len ? p[i] : 0x3c));

    }
    free(r);

  }
  /* Short overlap distances must not overwrite the next source word. */
  for (size_t len = 0; len < 32; ++len) {

    for (size_t distance = 1; distance <= 8; ++distance) {

      for (size_t i = 0; i < 64; ++i) p[i] = (unsigned char)i;
      memmove(p + distance, p, len);
      for (size_t i = 0; i < 64; ++i)
        assert(p[i] == (i >= distance && i < distance + len ? i - distance : i));
      for (size_t i = 0; i < 64; ++i) p[i] = (unsigned char)i;
      memmove(p, p + distance, len);
      for (size_t i = 0; i < 64; ++i)
        assert(p[i] == (i < len ? i + distance : i));

    }

  }
  free(p);
  free(q);
  return 0;

}
