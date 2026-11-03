/* Prototype only: no Bluetooth, device access, native UI or speaker output.
 * Decode whole SBC frames without silently discarding PCM on small buffers.
 */
#include <stddef.h>
#include <string.h>
#include "sbc.h"
#include "decoder.h"

static sbc_t decoder;
static uint32_t ready;
static uint32_t have_config;
static uint8_t stream_config;

int garmin_sbc_reset(void)
{
    /* Only one context owns the arena. Reset invalidates its old allocation. */
    prototype_arena_reset();
    ready = 0;
    have_config = 0;
    int status = sbc_init(&decoder, 0);
    if (status == 0) {
        decoder.endian = SBC_LE;
        ready = 1;
    }
    return status;
}

int garmin_sbc_decode_frame(const uint8_t *input, uint32_t input_len,
                           uint8_t *output, uint32_t output_cap,
                           struct decoder_result *result)
{
    static const uint32_t rates[4] = {16000, 32000, 44100, 48000};
    if (result == NULL) return DECODER_BAD_HEADER;
    memset(result, 0, sizeof(*result));
    result->arena_used = prototype_arena_used();
    if (!ready) return DECODER_NOT_READY;
    if (input == NULL || output == NULL) return DECODER_BAD_HEADER;
    if (input_len < 4) return DECODER_TRUNCATED;
    if (input[0] != 0x9c) return DECODER_BAD_HEADER;

    uint32_t mode = (input[1] >> 2) & 3u;
    uint32_t channels = mode == SBC_MODE_MONO ? 1u : 2u;
    uint32_t subbands = (input[1] & 1u) ? 8u : 4u;
    uint32_t blocks = 4u * (((input[1] >> 4) & 3u) + 1u);
    uint32_t bitpool = input[2];
    uint32_t max_bitpool = (mode <= SBC_MODE_DUAL_CHANNEL ? 16u : 32u) * subbands;
    if (bitpool < 2 || bitpool > 250 || bitpool > max_bitpool)
        return DECODER_BAD_HEADER;
    uint32_t payload_bits = blocks * bitpool;
    if (mode <= SBC_MODE_DUAL_CHANNEL) payload_bits *= channels;
    if (mode == SBC_MODE_JOINT_STEREO) payload_bits += subbands;
    uint32_t frame_length = 4u + (subbands * channels) / 2u + (payload_bits + 7u) / 8u;
    uint32_t pcm_length = blocks * subbands * channels * 2u;
    if (input_len < frame_length) return DECODER_TRUNCATED;
    if (output_cap < pcm_length) return DECODER_OUTPUT_SMALL;
    /* libsbc assumes stable subbands and channel format between frames. */
    if (have_config && input[1] != stream_config) return DECODER_FORMAT_CHANGE;

    size_t written = 0;
    ssize_t consumed = sbc_decode(&decoder, input, frame_length, output,
                                 pcm_length, &written);
    if (consumed <= 0 || (uint32_t)consumed != frame_length || written != pcm_length) {
        result->codec_error = (int32_t)consumed;
        /* Do not retain decoder state initialized from a CRC-invalid frame. */
        garmin_sbc_reset();
        result->arena_used = prototype_arena_used();
        return DECODER_CODEC_ERROR;
    }
    stream_config = input[1];
    have_config = 1;
    result->consumed = (uint32_t)consumed;
    result->written = (uint32_t)written;
    result->sample_rate = rates[input[1] >> 6];
    result->channels = channels;
    result->samples_per_channel = blocks * subbands;
    result->frame_config = input[1];
    result->bitpool = bitpool;
    return DECODER_OK;
}
