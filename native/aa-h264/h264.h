/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef AA_H264_H
#define AA_H264_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct aa_h264 aa_h264;
enum { AA_H264_OK=0, AA_H264_PAUSED=1, AA_H264_FINISHED=2,
       AA_H264_ARGUMENT=-1, AA_H264_CAPACITY=-2, AA_H264_MALFORMED=-3,
       AA_H264_UNSUPPORTED=-4, AA_H264_CODEC=-5, AA_H264_STOPPED=-6,
       AA_H264_REENTRANT=-7, AA_H264_CALLBACK=-8, AA_H264_TRUNCATED=-9 };
typedef struct {
    const uint8_t *planes[3];
    size_t strides[3]; /* tightly packed owned copies: width,width/2,width/2 */
    uint32_t width,height;
    uint64_t timestamp; /* first VCL NAL's first chunk; not verified phone PTS */
    uint64_t index;
} aa_h264_frame;
typedef int (*aa_h264_frame_fn)(void *user,const aa_h264_frame *frame);
typedef struct {
    uint32_t max_width,max_height; /* even, <=800x480; coded dimensions also capped */
    size_t max_nal_bytes,max_au_bytes;
    aa_h264_frame_fn callback;
    void *user;
} aa_h264_config;
size_t aa_h264_context_size(void);
size_t aa_h264_context_align(void);
size_t aa_h264_workspace_size(const aa_h264_config *config); /* 0 if invalid */
int aa_h264_init(void *context,size_t context_bytes,void *workspace,size_t workspace_bytes,
                 const aa_h264_config *config,aa_h264 **out);
int aa_h264_start(aa_h264 *decoder); /* reset; destroys all prior decoder refs */
int aa_h264_reset(aa_h264 *decoder); /* alias of start */
int aa_h264_feed(aa_h264 *decoder,const uint8_t *data,size_t length,
                 uint64_t timestamp,size_t *consumed);
int aa_h264_retry(aa_h264 *decoder);
int aa_h264_finish(aa_h264 *decoder); /* EOF, drain reorder frames; retry if PAUSED */
int aa_h264_stop(aa_h264 *decoder); /* serialized discard/Uninitialize/Destroy */
int aa_h264_status(const aa_h264 *decoder);
void aa_h264_destroy(aa_h264 *decoder); /* stop then end object lifetime */
/* Caller owns aligned context and workspace for the whole object lifetime.
 * Every input byte counted in consumed was copied/accepted; do not resend it.
 * PAUSED retains one owned complete frame; retry invokes callback again without
 * redecoding. No feed bytes accepted while pending. callback OK consumes the view;
 * it may be overwritten immediately after return. PAUSED view remains stable.
 * Single-threaded serialized API; callback reentry rejected. Fatal errors sticky
 * until reset. No firmware/device/I/O; OpenH264 internal allocations are not capped
 * by workspace_size. Annex-B only: no AVCC, no per-AA-indication AU assumption. */
#ifdef __cplusplus
}
#endif
#endif
