/* Offline AVDTP callback integration. No registration or installation.
 * Accept complete, non-fragmented RTP/SBC packets in arrival order. Default
 * is mono16k; VOICE_MEDIA_CONVERT admits the decoder's four rates/modes and
 * uses an optional converted submit function. No negotiation, jitter/reorder
 * handling or concurrency is implemented here.
 */
#include <stdint.h>
#include "decoder.h"

extern int voice_extension_submit_frame(const uint8_t *, uint32_t,
                                        struct decoder_result *);
struct voice_media_counters {
    uint32_t callbacks, accepted_packets, rejected_packets;
    uint32_t submitted_frames, submitted_pcm_bytes;
    int32_t last_error;
};
volatile struct voice_media_counters voice_media_stats;

static int fail(int error)
{
    voice_media_stats.rejected_packets++;
    voice_media_stats.last_error = error;
    return error;
}

static uint32_t be16(const uint8_t *p)
{
    return ((uint32_t)p[0] << 8) | p[1];
}

/* ABI derived from original incoming handler 0x50bbc0 and BX R7 veneer.
 * The handler doesn't initialize handle bytes0..3; we don't read the handle.
 */
int voice_extension_media_callback(uint32_t event, uint32_t status,
                                   const void *handle, const uint8_t *packet,
                                   uint32_t length)
{
    (void)handle;
    voice_media_stats.callbacks++;
    voice_media_stats.last_error = 0;
    if (event != 0xf1) return fail(-10);
    if (status != 0) return fail(-11);
    if (packet == 0 || length < 13 || length > 4096 || (packet[0] >> 6) != 2)
        return fail(-12);
    uint32_t end = length;
    if (packet[0] & 0x20) {
        uint32_t padding = packet[length-1];
        if (padding == 0 || padding > length-12) return fail(-12);
        end -= padding;
    }
    uint32_t offset = 12u + 4u * (packet[0] & 0xf);
    if (offset >= end) return fail(-12);
    if (packet[0] & 0x10) {
        if (end-offset < 4) return fail(-12);
        uint32_t extension_bytes = 4u + 4u * be16(packet+offset+2);
        if (extension_bytes >= end-offset) return fail(-12);
        offset += extension_bytes;
    }
    uint32_t payload_header = packet[offset++];
    if (payload_header & 0xe0) return fail(-13); /* F, S, L unsupported. */
    if (payload_header & 0x10) return fail(-14); /* Reserved bit. */
    uint32_t frames = payload_header & 0xf;
    if (frames == 0) return fail(-14);
    uint32_t lengths[15];
    uint32_t cursor = offset;
    uint32_t config = 0;
    /* Validate the whole packet's framing before any PCM is submitted.
     * SBC CRC is checked by the decoder. A later CRC/host failure can still
     * leave an already-submitted prefix; counters record that explicitly.
     */
    for (uint32_t i = 0; i < frames; i++) {
        if (end-cursor < 4 || packet[cursor] != 0x9c) return fail(-15);
        uint32_t header = packet[cursor+1];
#ifndef VOICE_MEDIA_CONVERT
        if ((header >> 6) != 0 || ((header >> 2) & 3u) != 0) return fail(-16);
#endif
        if (i != 0 && config != header) return fail(-16);
        config = header;
        uint32_t subbands = (header & 1u) ? 8u : 4u;
        uint32_t blocks = 4u * (((header >> 4) & 3u) + 1u);
        uint32_t bitpool = packet[cursor+2];
        uint32_t mode = (header >> 2) & 3u;
        uint32_t channels = mode == 0 ? 1u : 2u;
        uint32_t maximum = (mode <= 1 ? 16u : 32u)*subbands;
        if (bitpool < 2 || bitpool > 250 || bitpool > maximum) return fail(-15);
        uint32_t payload_bits = blocks*bitpool;
        if (mode <= 1) payload_bits *= channels;
        if (mode == 3) payload_bits += subbands;
        uint32_t size = 4u + subbands*channels/2u + (payload_bits+7u)/8u;
        if (size > end-cursor) return fail(-15);
        lengths[i] = size;
        cursor += size;
    }
    if (cursor != end) return fail(-17);
    for (uint32_t i = 0; i < frames; i++) {
        struct decoder_result result;
        int error = voice_extension_submit_frame(packet+offset, lengths[i], &result);
        if (error != 0) return fail(error);
        voice_media_stats.submitted_frames++;
        voice_media_stats.submitted_pcm_bytes += result.written;
        offset += lengths[i];
    }
    voice_media_stats.accepted_packets++;
    return 0;
}

const void *const voice_extension_media_api[]
    __attribute__((used, section(".extension_exports"))) = {
        (const void *)voice_extension_media_callback
    };
