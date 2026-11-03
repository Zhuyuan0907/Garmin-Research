/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef AA_VIDEO_H
#define AA_VIDEO_H
#include <stdint.h>
#include <stddef.h>
#include "h264.h"
enum {
    AA_VIDEO_OK=0, AA_VIDEO_PAUSED=1, AA_VIDEO_FINISHED=2, AA_VIDEO_PROGRESS=3,
    AA_VIDEO_E_ARGUMENT=-600001, AA_VIDEO_E_SESSION=-600002,
    AA_VIDEO_E_STATE=-600003, AA_VIDEO_E_DECODER=-600004,
    AA_VIDEO_E_REENTRANT=-600005, AA_VIDEO_E_PROTOCOL=-600006
};
struct aa_video_stats {
    uint64_t accepted_packets, accepted_bytes, fed_bytes;
    uint64_t last_timestamp;
    int32_t media_session;
    uint32_t queued_packets;
};
/* Own software-video provider for aa_control, channel3 only. Caller provides
 * fresh zero/aligned>=8 context and initialized aa_h264 object, retained until
 * fully stopped. Two fixed262144-byte slots copy complete media indications.
 * Provider MEDIA only copies; worker step performs Annex-B parsing/decode.
 * ACK from control means compressed input was owned, not decoded/rendered.
 * All calls and decoder/frame callbacks must be serialized. No original
 * Garmin code, task/IRQ/USB or physical display. Focus is software-owner state.
 */
uint32_t aa_video_context_bytes(void);
int aa_video_init(void *,uint32_t session,aa_h264 *);
/* Exact aa_control_provider signature; events use control.h enum values. */
int aa_video_control_provider(void *,uint8_t channel,uint32_t event,
                              int32_t media_session,uint32_t config,
                              uint64_t timestamp,const uint8_t *,size_t);
int aa_video_step(void *,uint32_t session);
int aa_video_finish(void *,uint32_t session);
int aa_video_stats_get(void *,uint32_t session,struct aa_video_stats *);
int aa_video_status(void *,uint32_t session);
int aa_video_decoder_detail(void *,uint32_t session);
/* Discard queue, stop decoder, preserve allocation owner. No asynchronous
 * callback quiescence/hardware mute; fresh init required after this teardown. */
int aa_video_stop(void *,uint32_t session);
#endif
