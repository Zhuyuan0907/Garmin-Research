/* Bounded, single-context allocator and libc subset for offline emulation.
 * This is not a general-purpose allocator or an OS integration layer.
 */
#include <stddef.h>
#include <stdint.h>
#include "decoder.h"

static uint8_t arena[16384] __attribute__((aligned(32)));
static uint32_t used;

void prototype_arena_reset(void) { used = 0; }
uint32_t prototype_arena_used(void) { return used; }

void *malloc(size_t size)
{
    uint32_t start = (used + 31u) & ~31u;
    if (size > sizeof(arena) || start > sizeof(arena) - size)
        return NULL;
    used = start + size;
    return arena + start;
}

void free(void *pointer) { (void)pointer; }

void *memset(void *destination, int value, size_t length)
{
    uint8_t *dst = destination;
    for (size_t i = 0; i < length; i++) dst[i] = (uint8_t)value;
    return destination;
}

void *memcpy(void *destination, const void *source, size_t length)
{
    uint8_t *dst = destination;
    const uint8_t *src = source;
    for (size_t i = 0; i < length; i++) dst[i] = src[i];
    return destination;
}

/* libgcc's Linux default would call raise(). The freestanding experiment
 * treats unexpected divide-by-zero as an instruction fault, never as PCM.
 */
__attribute__((noreturn)) void __aeabi_idiv0(void) { __builtin_trap(); }
__attribute__((noreturn)) void __aeabi_ldiv0(void) { __builtin_trap(); }
