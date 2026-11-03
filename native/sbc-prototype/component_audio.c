/* Emulator-only extension: this does not preserve the original 40 TTS APIs. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "decoder.h"

struct component_descriptor {
    uint32_t version, reserved_4, reserved_8;
    const void *const *exports;
    uint32_t reserved_16, export_count;
};

typedef int (*output_callback)(uint32_t, uint32_t, const uint8_t *, uint32_t);
struct loader_descriptor {
    uint32_t words[9];
    const void *const *host_functions;
    uint32_t host_function_count;
    int (*register_exports)(struct loader_descriptor *,
                            const struct component_descriptor *);
};

extern uint8_t __component_bss_start[], __component_bss_end[];
static output_callback host_output;
static uint8_t pcm[512] __attribute__((aligned(4)));

/* -7: resampling/downmix not implemented, -8: missing host callback,
 * -9: callback returned an error. The remaining statuses are decoder.h's.
 * The stock callback's 5120-byte reservation exceeds our bounded frame.
 * The emulation verifies byte transfer, not the physical sample clock.
 */
int garmin_sbc_submit_frame(const uint8_t *input, uint32_t input_len,
                           struct decoder_result *result)
{
    if (result == NULL) return DECODER_BAD_HEADER;
    memset(result, 0, sizeof(*result));
    if (host_output == NULL) return -8;
    if (input == NULL) return DECODER_BAD_HEADER;
    if (input_len < 4) return DECODER_TRUNCATED;
    if (input[0] != 0x9c) return DECODER_BAD_HEADER;
    /* Explicitly reject other rates/channels until a conversion exists. */
    if ((input[1] >> 6) != 0 || ((input[1] >> 2) & 3u) != 0) return -7;
    int status = garmin_sbc_decode_frame(input, input_len, pcm, sizeof(pcm), result);
    if (status != 0) return status;
    if (host_output(0, 0, pcm, result->written) != 0) return -9;
    return 0;
}

static const void *const exports[] = {
    (const void *)garmin_sbc_reset,
    (const void *)garmin_sbc_decode_frame,
    (const void *)garmin_sbc_submit_frame
};
static const struct component_descriptor descriptor = {
    .version = 0x50000,
    .exports = exports,
    .export_count = sizeof(exports) / sizeof(exports[0])
};

_Static_assert(offsetof(struct loader_descriptor, host_functions) == 36,
               "Expected ARM32 host table offset");
_Static_assert(offsetof(struct loader_descriptor, register_exports) == 44,
               "Expected ARM32 registration offset");
_Static_assert(offsetof(struct component_descriptor, exports) == 12,
               "Expected module export offset");
_Static_assert(offsetof(struct component_descriptor, export_count) == 20,
               "Expected module count offset");

int garmin_component_entry(struct loader_descriptor *loader)
{
    memset(__component_bss_start, 0,
           (uintptr_t)__component_bss_end - (uintptr_t)__component_bss_start);
    if (loader == NULL || loader->register_exports == NULL) return 5;
    if (loader->host_functions != NULL && loader->host_function_count > 0)
        host_output = (output_callback)loader->host_functions[0];
    return loader->register_exports(loader, &descriptor);
}
