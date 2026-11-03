#ifndef GARMIN_PCM_CONVERTER_H
#define GARMIN_PCM_CONVERTER_H
#include <stdint.h>

/* Experimental single-stream ABI, not an original firmware export.
 * Output is mono S16_LE at the verified logical TTS source rate (16 kHz).
 * Reset before use; callers must serialize and supply valid non-overlapping
 * pointers. Downsampling is causal and has no implicit end-of-stream flush.
 */
enum pcm_converter_status {
    PCM_CONVERTER_OK = 0,
    PCM_CONVERTER_BAD_FORMAT = -20,
    PCM_CONVERTER_BAD_ARGUMENT = -21,
    PCM_CONVERTER_NOT_READY = -22,
    PCM_CONVERTER_OUTPUT_SMALL = -23
};
void pcm_converter_clear(void);
int pcm_converter_reset(uint32_t rate, uint32_t channels);
int pcm_converter_process(const int16_t *input, uint32_t sample_frames,
                          int16_t *output, uint32_t output_cap_bytes,
                          uint32_t *written_bytes);
#endif
