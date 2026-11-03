/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef AA_INPUT_H
#define AA_INPUT_H
#include "control.h"
enum {
 AA_INPUT_OK=0, AA_INPUT_PAUSED=1,
 AA_INPUT_E_ARGUMENT=-700001, AA_INPUT_E_SESSION=-700002,
 AA_INPUT_E_STATE=-700003, AA_INPUT_E_PROTOCOL=-700004,
 AA_INPUT_E_CAPACITY=-700005, AA_INPUT_E_TRANSPORT=-700006,
 AA_INPUT_E_REENTRANT=-700007
};
enum { AA_INPUT_PRESS=0, AA_INPUT_RELEASE=1, AA_INPUT_DRAG=2 };
struct aa_input_viewport {
 uint32_t surface_width,surface_height,x,y,width,height;
};
/* A single serialized pointer in explicitly advertised touch coordinates.
 * Owner passes exactly the profile used by control, retains that control, and
 * supplies an already calibrated local surface/viewport. No hardware driver,
 * clock acquisition, rotation, multi-pointer/CANCEL or current phone claim.
 * Caller-owned >=8-aligned zero context. Timestamp is caller-provided uint64
 * microseconds in one nondecreasing domain, not verified phone clock sync.
 */
uint32_t aa_input_context_bytes(void);
int aa_input_init(void *,uint32_t session,void *control,
 const f1x_aasdk_proto_messages_ServiceDiscoveryResponse *,const struct aa_input_viewport *);
int aa_input_control_provider(void *,uint8_t,uint32_t,int32_t,uint32_t,uint64_t,const uint8_t *,size_t);
int aa_input_touch(void *,uint32_t,uint64_t timestamp,uint32_t action,int32_t x,int32_t y);
/* Explicit release at last captured coordinate on local capture loss; this
 * is RELEASE, not a fabricated Android CANCEL. PAUSED means retry unchanged. */
int aa_input_release_touch(void *,uint32_t,uint64_t timestamp);
int aa_input_button(void *,uint32_t,uint64_t,uint32_t scan_code,int pressed,int long_press);
int aa_input_scroll(void *,uint32_t,uint64_t,int32_t delta);
int aa_input_tx_peek(void *,uint32_t,struct aa_message_view *,uint32_t *token);
/* Owner serializes one shared aa_sender/TLS, preserving queue-owner+token.
 * Commit only after sender's final successful wire byte. Transport failure
 * invalidates this context and the entire associated TLS session. */
int aa_input_tx_commit(void *,uint32_t,uint32_t token,int transport_status);
int aa_input_pending(void *,uint32_t);
int aa_input_status(void *,uint32_t);
/* Discards unsent input without emitting releases; owner must release held
 * input while bound before orderly shutdown. Not async quiescence. */
int aa_input_stop(void *,uint32_t);
#endif
