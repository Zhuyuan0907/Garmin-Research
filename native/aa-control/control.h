/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef AA_CONTROL_H
#define AA_CONTROL_H
#include <stdint.h>
#include <stddef.h>
#include "message.h"
#include "proto.h"
enum {
    AA_CONTROL_OK=0, AA_CONTROL_PAUSED=1,
    AA_CONTROL_E_ARGUMENT=-500001, AA_CONTROL_E_SESSION=-500002,
    AA_CONTROL_E_STATE=-500003, AA_CONTROL_E_PROTOCOL=-500004,
    AA_CONTROL_E_PROTOBUF=-500005, AA_CONTROL_E_CAPACITY=-500006,
    AA_CONTROL_E_PROVIDER=-500007, AA_CONTROL_E_REENTRANT=-500008,
    AA_CONTROL_E_TRANSPORT=-500009
};
enum aa_control_channel_state {
    AA_CONTROL_OFFERED=0, AA_CONTROL_OPEN_PENDING=1, AA_CONTROL_OPEN=2,
    AA_CONTROL_SETUP_PENDING=3, AA_CONTROL_SETUP=4, AA_CONTROL_STREAMING=5,
    AA_CONTROL_BIND_PENDING=6, AA_CONTROL_BOUND=7
};
enum aa_control_event {
    AA_CONTROL_OPEN_EVENT=1, AA_CONTROL_SETUP_EVENT=2,
    AA_CONTROL_START_EVENT=3, AA_CONTROL_STOP_EVENT=4,
    AA_CONTROL_MEDIA_EVENT=5, AA_CONTROL_VIDEO_FOCUS_EVENT=6,
    AA_CONTROL_AUDIO_FOCUS_EVENT=7, AA_CONTROL_BIND_EVENT=8
};
/* Provider returns OK only after accepting/copying the complete request/data;
 * PAUSED means NOT accepted and no irreversible side effect. Anything else
 * rejects the operation. Views are callback-local; no pointer retention.
 * The provider must perform the actual platform open/init/start/stop/focus,
 * bounded media ownership and eventual decode/output. This layer supplies no
 * display/audio/touch backend. A media ACK means provider acceptance, NOT
 * decode, display, audible sound or physical transport verification.
 */
typedef int (*aa_control_provider)(void *,uint8_t channel,uint32_t event,
                                  int32_t media_session,uint32_t config,
                                  uint64_t timestamp,const uint8_t *,size_t);
/* Own Linux C legacy model, caller-owned fresh zero/aligned>=8 context.
 * All entry points, provider and TLS RX/TX must be serialized. No native OS,
 * phone, hardware or official Google authentication/compatibility claim.
 * Capabilities MUST describe caller-provided backends, not desired hardware.
 * Supported subset: input1, video3, media4, speech5, system6. No microphone,
 * sensor, BT or navigation-service descriptor is synthesized. Discovery's
 * encoded response <=8190 bytes, 4 queued replies <=8192 bytes each.
 * Unknown protobuf fields are skipped by pinned nanopb; malformed/overflow/
 * missing proto2 required fields fail. Unknown message IDs fail this strict
 * subset. Plaintext only permits ping request/response on channel0; this is
 * an explicit compatibility policy inferred from legacy plaintext pinger.
 */
uint32_t aa_control_context_bytes(void);
int aa_control_init(void *,uint32_t session,
                    const f1x_aasdk_proto_messages_ServiceDiscoveryResponse *,
                    aa_control_provider,void *arg);
int aa_control_receive(void *,uint32_t,const struct aa_message_view *);
/* Drive deferred video-focus publication AFTER setup output was successfully
 * committed. Provider PAUSED preserves the request for retry. Caller drives
 * this serially, alongside RX and sender; no autonomous OS worker exists. */
int aa_control_step(void *,uint32_t);
/* Direct aa_message_callback bridge. Context's bound session is used. */
int aa_control_message_callback(void *,const struct aa_message_view *);
/* Queue head view/token is stable until matching successful whole-message
 * transport completion. A sender must commit all its wire bytes FIRST, then
 * call this commit. Zero/uncommitted/failed I/O must never be called success.
 * OPEN/SETUP/BOUND only become usable at this completion gate. A PAUSED
 * receive accepts nothing; retry the same complete message after output drains.
 */
int aa_control_tx_peek(void *,uint32_t,struct aa_message_view *,uint32_t *token);
int aa_control_tx_commit(void *,uint32_t,uint32_t token,int transport_status);
int aa_control_channel_status(void *,uint32_t,uint8_t channel);
int aa_control_pending(void *,uint32_t);
int aa_control_status(void *,uint32_t);
/* Serialized discard, no provider STOP callbacks, async quiescence/mute or
 * reclaim guarantee. Owner must separately stop/quiesce platform backends. */
int aa_control_stop(void *,uint32_t);
#endif
