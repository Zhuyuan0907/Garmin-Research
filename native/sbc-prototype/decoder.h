/* Offline ARMv6 experiment; this API is not an identified Garmin ABI. */
#ifndef GARMIN_SBC_PROTOTYPE_H
#define GARMIN_SBC_PROTOTYPE_H
#include <stdint.h>

enum decoder_status {
    DECODER_OK = 0,
    DECODER_BAD_HEADER = -1,
    DECODER_NOT_READY = -2,
    DECODER_TRUNCATED = -3,
    DECODER_OUTPUT_SMALL = -4,
    DECODER_FORMAT_CHANGE = -5,
    DECODER_CODEC_ERROR = -6
};

struct decoder_result {
    uint32_t consumed;
    uint32_t written;
    uint32_t sample_rate;
    uint32_t channels;
    uint32_t samples_per_channel;
    uint32_t frame_config;
    uint32_t bitpool;
    int32_t codec_error;
    uint32_t arena_used;
};

int garmin_sbc_reset(void);
int garmin_sbc_decode_frame(const uint8_t *input, uint32_t input_len,
                           uint8_t *output, uint32_t output_cap,
                           struct decoder_result *result);
void prototype_arena_reset(void);
uint32_t prototype_arena_used(void);
#endif
