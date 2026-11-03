/* Freestanding integer streaming conversion; no OS or device access.
 * Downmix averages two channels with truncation toward zero. Rational FIR
 * downsampling uses precomputed Q15 coefficients, int64 accumulation and
 * saturation to S16. 16 kHz bypasses the filter but still downmixes.
 */
#include "pcm_converter.h"
#include "pcm_converter_tables.h"

static int16_t history[PCM_CONVERTER_TAPS];
static uint32_t head, phase, until_next, step, phases, input_channels, ready;
static const int16_t *coefficients;

void pcm_converter_clear(void)
{
    for (uint32_t i = 0; i < PCM_CONVERTER_TAPS; i++) history[i] = 0;
    head = phase = until_next = step = phases = input_channels = ready = 0;
    coefficients = 0;
}

int pcm_converter_reset(uint32_t rate, uint32_t channels)
{
    if ((channels != 1 && channels != 2) ||
        (rate != 16000 && rate != 32000 && rate != 44100 && rate != 48000))
        return PCM_CONVERTER_BAD_FORMAT;
    pcm_converter_clear();
    input_channels = channels;
    ready = 1;
    if (rate == 44100) {
        step = 441; phases = 160; coefficients = &pcm_44100[0][0];
    } else if (rate == 32000) {
        step = 2; phases = 1; coefficients = pcm_32000;
    } else if (rate == 48000) {
        step = 3; phases = 1; coefficients = pcm_48000;
    }
    return 0;
}

static int16_t filtered(void)
{
    const int16_t *kernel = coefficients + phase*PCM_CONVERTER_TAPS;
    uint32_t index = head;
    int64_t value = 0;
    for (uint32_t tap = 0; tap < PCM_CONVERTER_TAPS; tap++) {
        if (index == 0) index = PCM_CONVERTER_TAPS;
        index--;
        value += (int32_t)history[index] * (int32_t)kernel[tap];
    }
    /* Round to nearest, with half-integers away from zero, then saturate. */
    value = value >= 0 ? (value+16384)/32768 : -((-value+16384)/32768);
    if (value > 32767) value = 32767;
    if (value < -32768) value = -32768;
    return (int16_t)value;
}

int pcm_converter_process(const int16_t *input, uint32_t sample_frames,
                          int16_t *output, uint32_t output_cap_bytes,
                          uint32_t *written_bytes)
{
    if (written_bytes == 0) return PCM_CONVERTER_BAD_ARGUMENT;
    *written_bytes = 0;
    if (!ready) return PCM_CONVERTER_NOT_READY;
    if (sample_frames > 128 || output == 0 || (sample_frames && input == 0))
        return PCM_CONVERTER_BAD_ARGUMENT;
    /* Conservative capacity check ensures no synthesis state advances on
     * failure. At all supported rates, output cannot exceed input frames.
     */
    if (output_cap_bytes < sample_frames*2) return PCM_CONVERTER_OUTPUT_SMALL;
    uint32_t count = 0;
    for (uint32_t frame = 0; frame < sample_frames; frame++) {
        int32_t sample = *input++;
        if (input_channels == 2) sample = (sample + *input++) / 2;
        if (coefficients == 0) {
            output[count++] = (int16_t)sample;
            continue;
        }
        history[head++] = (int16_t)sample;
        if (head == PCM_CONVERTER_TAPS) head = 0;
        if (until_next == 0) {
            output[count++] = filtered();
            uint32_t next = phase + step;
            until_next = next / phases;
            phase = next % phases;
        }
        until_next--;
    }
    *written_bytes = count*2;
    return 0;
}
