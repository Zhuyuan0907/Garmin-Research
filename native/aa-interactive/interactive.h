/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef AA_INTERACTIVE_H
#define AA_INTERACTIVE_H
#include "message.h"
enum {
 AA_INTERACTIVE_OK=0, AA_INTERACTIVE_PAUSED=1, AA_INTERACTIVE_PROGRESS=2,
 AA_INTERACTIVE_COMPLETED=3, AA_INTERACTIVE_CLOSED=4,
 AA_INTERACTIVE_E_ARGUMENT=-900001, AA_INTERACTIVE_E_SESSION=-900002,
 AA_INTERACTIVE_E_STATE=-900003, AA_INTERACTIVE_E_DEPENDENCY=-900004,
 AA_INTERACTIVE_E_REENTRANT=-900005
};
enum {AA_INTERACTIVE_CONTROL_OWNER=1,AA_INTERACTIVE_INPUT_OWNER=2};
/* Serialized Linux-host composition, not GarminOS or a hardware backend.
 * Caller initializes control/input/video/audio first, retains their contexts
 * and the verified TLS session, then supplies fresh aligned sender storage.
 * After init this bridge is the sole owner of sender and both source queues'
 * peek/commit operations. RX, control_step, video_step and audio_step remain
 * explicit caller work; they MUST NOT run concurrently with this bridge.
 */
uint32_t aa_interactive_context_bytes(void);
int aa_interactive_init(void *,uint32_t,void *tls,void *control,void *input,
 void *video,void *audio,void *sender,size_t sender_bytes);
int aa_interactive_control_provider(void *,uint8_t,uint32_t,int32_t,uint32_t,uint64_t,const uint8_t *,size_t);
int aa_interactive_step(void *,uint32_t);
int aa_interactive_tx_peek(void *,uint32_t,const uint8_t **,size_t *);
int aa_interactive_tx_commit(void *,uint32_t,size_t actual_successful_bytes,int transport_status);
int aa_interactive_owner(void *,uint32_t,uint32_t *,uint32_t *);
int aa_interactive_status(void *,uint32_t);
int aa_interactive_detail(void *,uint32_t);
/* Every stop abandons the entire TLS session, as required by aa_sender.
 * It does not stop/quiesce child backends, release held input, mute hardware
 * or revoke an OS owner. Caller separately stops children and discards TLS.
 * CLOSED after delivered shutdown reply likewise requires owner cleanup. */
int aa_interactive_stop(void *,uint32_t);
#endif
