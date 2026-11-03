/* Offline coexistence experiment: retain the original module's 40 exports.
 * No native UI, Bluetooth registration or device installation is supplied.
 */
#include <stdint.h>
#include <string.h>
#include "decoder.h"

extern uint8_t __extension_bss_start[], __extension_bss_end[];
/* Linker binds this to the original ARM entry branch, at its unchanged address. */
extern int original_tts_entry(void *loader);
volatile int32_t extension_decoder_init_status;
typedef int (*pcm_callback)(uint32_t, uint32_t, const uint8_t *, uint32_t);
static pcm_callback host_output;
static uint8_t pcm[512] __attribute__((aligned(4)));

/* Same bounded 16 kHz mono route as the separate PCM experiment. */
int voice_extension_submit_frame(const uint8_t *input, uint32_t input_len,
                                 struct decoder_result *result)
{
    if (result == NULL) return DECODER_BAD_HEADER;
    memset(result, 0, sizeof(*result));
    if (host_output == NULL) return -8;
    if (input == NULL) return DECODER_BAD_HEADER;
    if (input_len < 4) return DECODER_TRUNCATED;
    if (input[0] != 0x9c) return DECODER_BAD_HEADER;
    if ((input[1] >> 6) != 0 || ((input[1] >> 2) & 3u) != 0) return -7;
    int status = garmin_sbc_decode_frame(input, input_len, pcm, sizeof(pcm), result);
    if (status != 0) return status;
    return host_output(0, 0, pcm, result->written) == 0 ? 0 : -9;
}

const void *const voice_extension_decoder_api[]
    __attribute__((used, section(".extension_exports"))) = {
        (const void *)garmin_sbc_reset,
        (const void *)garmin_sbc_decode_frame,
        (const void *)voice_extension_submit_frame
    };

int voice_extension_entry(void *loader)
{
    memset(__extension_bss_start, 0,
           (uintptr_t)__extension_bss_end - (uintptr_t)__extension_bss_start);
    int status = original_tts_entry(loader);
    if (status == 11 || status == 6) {
        /* The original module imports the same table; leave its slots intact. */
        uint32_t *descriptor = loader;
        const void *const *host = (const void *const *)descriptor[9];
        if (host != NULL && descriptor[10] > 0)
            host_output = (pcm_callback)host[0];
        extension_decoder_init_status = garmin_sbc_reset();
    }
    /* The original bootstrap already registered the original export table.
     * Never replace those slots with decoder functions.
     */
    return status;
}
