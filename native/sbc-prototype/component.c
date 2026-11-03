/* Emulator-only component. Its two exports do NOT implement the original
 * Garmin component's 40 APIs and must never be installed on the navigator.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "decoder.h"

struct component_descriptor {
    uint32_t version;
    uint32_t reserved_4;
    uint32_t reserved_8;
    const void *const *exports;
    uint32_t reserved_16;
    uint32_t export_count;
};

struct loader_descriptor {
    uint32_t words[11];
    int (*register_exports)(struct loader_descriptor *,
                            const struct component_descriptor *);
};

extern uint8_t __component_bss_start[];
extern uint8_t __component_bss_end[];

static const void *const exports[] = {
    (const void *)garmin_sbc_reset,
    (const void *)garmin_sbc_decode_frame
};

static const struct component_descriptor descriptor = {
    .version = 0x50000,
    .exports = exports,
    .export_count = sizeof(exports) / sizeof(exports[0])
};

_Static_assert(offsetof(struct loader_descriptor, register_exports) == 44,
               "Expected ARM32 loader callback offset");
_Static_assert(offsetof(struct component_descriptor, exports) == 12,
               "Expected export table offset");
_Static_assert(offsetof(struct component_descriptor, export_count) == 20,
               "Expected export count offset");

int garmin_component_entry(struct loader_descriptor *loader)
{
    /* The observed file loader copies bytes, but does not initialize BSS.
     * Prove independence from stale RAM rather than relying on boot zeros.
     */
    memset(__component_bss_start, 0,
           (uintptr_t)__component_bss_end - (uintptr_t)__component_bss_start);
    if (loader == NULL || loader->register_exports == NULL) return 5;
    return loader->register_exports(loader, &descriptor);
}
