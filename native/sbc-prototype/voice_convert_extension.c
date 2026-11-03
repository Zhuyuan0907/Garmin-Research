/* Offline preserving extension: decoded SBC -> native mono16k PCM.
 * No real SEP registration, UI, package generation or device installation.
 */
#include <stdint.h>
#include <string.h>
#include "decoder.h"
#include "pcm_converter.h"

extern int voice_extension_entry(void *loader);
extern volatile int32_t extension_decoder_init_status;
typedef int (*pcm_callback)(uint32_t, uint32_t, const uint8_t *, uint32_t);
static pcm_callback convert_host_output;
static int16_t source_pcm[256] __attribute__((aligned(4)));
static int16_t converted_pcm[128] __attribute__((aligned(4)));
static uint32_t configured_rate, configured_channels;
volatile int32_t voice_convert_init_status;

int voice_convert_reset(void)
{
    pcm_converter_clear();
    configured_rate = configured_channels = 0;
    return garmin_sbc_reset();
}

/* Result consumption/config/bitpool describe the source SBC frame; the
 * written/rate/channels/samples fields describe submitted mono16k output.
 * There is no automatic flush of the causal FIR tail at stream end.
 */
int voice_convert_submit_frame(const uint8_t *input, uint32_t input_len,
                               struct decoder_result *result)
{
    if (result == 0) return DECODER_BAD_HEADER;
    memset(result, 0, sizeof(*result));
    if (convert_host_output == 0) return -8;
    int status = garmin_sbc_decode_frame(input, input_len,
                                        (uint8_t *)source_pcm,
                                        sizeof(source_pcm), result);
    if (status != 0) {
        /* Decoder resets after CRC failure; also discard stale FIR history.
         * Other framing/format failures do not advance synthesis or history.
         */
        if (status == DECODER_CODEC_ERROR) {
            pcm_converter_clear();
            configured_rate = configured_channels = 0;
        }
        return status;
    }
    if (configured_rate == 0) {
        status = pcm_converter_reset(result->sample_rate, result->channels);
        if (status != 0) return status;
        configured_rate = result->sample_rate;
        configured_channels = result->channels;
    } else if (configured_rate != result->sample_rate ||
               configured_channels != result->channels) {
        return DECODER_FORMAT_CHANGE;
    }
    uint32_t written = 0;
    status = pcm_converter_process(source_pcm, result->samples_per_channel,
                                   converted_pcm, sizeof(converted_pcm), &written);
    if (status != 0) return status;
    result->written = written;
    result->sample_rate = 16000;
    result->channels = 1;
    result->samples_per_channel = written/2;
    if (written && convert_host_output(0, 0, (uint8_t *)converted_pcm, written) != 0)
        return -9;
    return 0;
}

const void *const voice_convert_decoder_api[]
    __attribute__((used, section(".extension_exports"))) = {
        (const void *)voice_convert_reset,
        (const void *)garmin_sbc_decode_frame,
        (const void *)voice_convert_submit_frame
    };

int voice_convert_entry(void *loader)
{
    /* The existing preserving entry clears the entire appended BSS and
     * executes the original TTS bootstrap/imports/40-export registration.
     */
    int status = voice_extension_entry(loader);
    if (status == 11 || status == 6) {
        uint32_t *descriptor = loader;
        const void *const *host = (const void *const *)descriptor[9];
        if (host != 0 && descriptor[10] > 0)
            convert_host_output = (pcm_callback)host[0];
        /* The preserving entry already reset the codec. Do not allocate and
         * clear its context twice during load; only initialize FIR state.
         */
        pcm_converter_clear();
        configured_rate = configured_channels = 0;
        voice_convert_init_status = extension_decoder_init_status;
    }
    return status;
}
