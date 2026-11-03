/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef AA_AUDIO_H
#define AA_AUDIO_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
enum {
    AA_AUDIO_OK=0, AA_AUDIO_PAUSED=1, AA_AUDIO_FINISHED=2, AA_AUDIO_PROGRESS=3,
    AA_AUDIO_E_ARGUMENT=-700001, AA_AUDIO_E_SESSION=-700002,
    AA_AUDIO_E_STATE=-700003, AA_AUDIO_E_CAPACITY=-700004,
    AA_AUDIO_E_PROTOCOL=-700005, AA_AUDIO_E_REENTRANT=-700006,
    AA_AUDIO_E_BACKEND=-700007, AA_AUDIO_E_TRUNCATED=-700008,
    AA_AUDIO_E_FOCUS=-700009
};
enum { AA_AUDIO_MEDIA=1, AA_AUDIO_SPEECH=2, AA_AUDIO_SYSTEM=4,
       AA_AUDIO_PACKET_CAPACITY=16384, AA_AUDIO_OUTPUT_CAPACITY=4096 };
enum { AA_AUDIO_FOCUS_NOTIFY_ONLY=0, AA_AUDIO_FOCUS_GATE=1 };
struct aa_audio_config {
    uint32_t enabled_mask; /* MEDIA/SPEECH/SYSTEM; actual caller backend capability */
    uint32_t packet_bytes_limit; /* 1..16384; complete indication accepted or rejected */
    uint32_t output_bytes_limit; /* 4..4096, multiple of4 */
    uint32_t focus_policy;
    uint32_t focus_grant_mask; /* bits1..4 permit GAIN/TRANSIENT/NAVI/RELEASE */
};
struct aa_audio_pcm_view {
    const uint8_t *data; /* owned packed S16LE bytes, not native-endian int16 casts */
    size_t bytes,frames;
    uint32_t sample_rate,channels,bit_depth;
    uint8_t channel;
    int32_t media_session;
    uint32_t focus_type; /* snapshot when this output chunk was assembled */
    uint64_t timestamp; /* first sample-frame's first byte indication timestamp */
    uint64_t frame_offset; /* per START session, including previously accepted prefix */
};
/* Backend returns exact consumed prefix, aligned to2/4-byte sample frames.
 * OK or PAUSED may accept a prefix; only that prefix is advanced. PAUSED0
 * retries exactly the same owned view. Positive partial consumption retries
 * only the unaccepted suffix. No retained pointer after accepting its bytes.
 * Invalid consumed/status fails this channel; no guessed recovery. */
typedef int (*aa_audio_pcm_backend)(void *,const struct aa_audio_pcm_view *,size_t *consumed);
struct aa_audio_stats {
    uint64_t accepted_packets,accepted_bytes,assembled_bytes,backend_bytes,backend_frames;
    uint64_t discarded_bytes,last_timestamp;
    uint32_t queued_packets,queued_bytes,pending_bytes,carry_bytes,focus_type;
    int32_t media_session;
    int streaming,finished,error;
};
uint32_t aa_audio_context_bytes(void);
int aa_audio_init(void *,uint32_t transport_session,const struct aa_audio_config *,aa_audio_pcm_backend,void *);
/* Exact aa_control_provider signature. Complete MEDIA is copied before OK;
 * PAUSED queue-full means zero acceptance/side effects, so control may retry.
 * OPEN permits parsed caller metadata bytes but never retains them. All signed
 * int32 START sessions are supported; phase distinguishes inactive from -1.
 * Channels4/5/6 fixed formats: 48k stereo /16k mono /16k mono, S16LE. */
int aa_audio_control_provider(void *,uint8_t channel,uint32_t event,
                            int32_t media_session,uint32_t config,
                            uint64_t timestamp,const uint8_t *,size_t);
int aa_audio_step(void *,uint32_t transport_session);
int aa_audio_retry(void *,uint32_t transport_session); /* step alias */
int aa_audio_finish(void *,uint32_t transport_session,uint8_t channel);
int aa_audio_stats_get(void *,uint32_t transport_session,uint8_t,struct aa_audio_stats *);
int aa_audio_status(void *,uint32_t transport_session);
int aa_audio_stop(void *,uint32_t transport_session); /* global teardown; fresh init after stop */
/* Caller supplies fresh zero/aligned>=8 context. Serialized calls/backend;
 * reentry rejected. Two owned input slots per enabled channel; worker step
 * assembles PCM sample frames across arbitrary indication byte boundaries.
 * STOP event discards this channel and permits another START from SETUP;
 * partial sample at explicit EOF is terminal TRUNCATED, never zero-padded.
 * Focus gating: GAIN permits all; TRANSIENT/NAVI permit speech/system only;
 * RELEASE/initial0 permit none. Notify-only delivers all with focus metadata.
 * No mixing/duck/resampling/mute/hardware ownership or asynchronous reclaim.
 * ACK means owned complete bytes, not rendered/audio playback. */
#ifdef __cplusplus
}
#endif
#endif
