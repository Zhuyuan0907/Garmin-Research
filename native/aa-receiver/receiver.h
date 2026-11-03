/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef AA_RECEIVER_H
#define AA_RECEIVER_H
#include <stddef.h>
#include <stdint.h>
#include "message.h"
enum {
    AA_RECEIVER_OK=0, AA_RECEIVER_PAUSED=1, AA_RECEIVER_PROGRESS=2,
    AA_RECEIVER_E_ARGUMENT=-200001, AA_RECEIVER_E_SESSION=-200002,
    AA_RECEIVER_E_STATE=-200003, AA_RECEIVER_E_WIRE=-200004,
    AA_RECEIVER_E_TLS=-200005, AA_RECEIVER_E_MESSAGE=-200006,
    AA_RECEIVER_E_RECORD=-200007, AA_RECEIVER_E_POLICY=-200008,
    AA_RECEIVER_E_CAPACITY=-200009, AA_RECEIVER_E_REENTRANT=-200010
};
/* Post-handshake receiver only. TLS context must already be active, verified,
 * and uniquely owned by this serialized receiver until stopped. Handshake
 * envelopes, version negotiation, channel dispatch, protobuf, ACKs, USB,
 * threads/IRQs, native Garmin APIs and installation are not implemented.
 *
 * Old aasdk Cryptor encrypts each frame then drains its entire output BIO.
 * This implementation therefore requires each nonempty encrypted frame to
 * contain whole TLS1.2 application records. It rejects records split across
 * AA frames, other TLS record kinds, or renegotiation. This policy and the
 * stricter message sequencing have NOT been verified against a current Pixel.
 * TLS authenticates record contents, not the outer channel/flags metadata.
 *
 * There are two owned 32768-byte queue slots. Wire capacity <=32768 and
 * plaintext capacity >=wire capacity. Message capacity/max_fragments follow
 * the assembler. All contexts/buffers/inputs/callback state must be distinct
 * valid accessible storage. Context is caller-owned, aligned >=8, initially
 * zeroed; caller must retain buffers, callback and TLS until quiescent stop.
 * Do not write owned buffers, retain accepted callback views or call init
 * from a callback. Message callback PAUSED means not accepted, then retry.
 */
uint32_t aa_receiver_context_bytes(void);
int aa_receiver_init(void *context, void *tls, uint32_t session,
                     uint8_t *wire_storage, size_t wire_capacity,
                     uint8_t *plaintext_storage, size_t plaintext_capacity,
                     uint8_t *message_storage, size_t message_capacity,
                     uint32_t max_fragments, aa_message_callback, void *arg,
                     int allow_plaintext);
/* Copies complete frames into the queue; does no TLS/decode work in callback.
 * Always initializes consumed to zero when provided. On PAUSED, only resend
 * the unconsumed transport tail. A complete frame may remain in wire storage;
 * feed(NULL,0) retries its enqueue after step has freed a slot.
 */
int aa_receiver_feed(void *,uint32_t,const uint8_t *,size_t,size_t *consumed);
/* Process at most one queued frame. A pending complete-message delivery is
 * retried first. Its ciphertext is never re-fed or re-decrypted on PAUSED.
 * WANT_WRITE from TLS returns PAUSED: caller must drain TLS output before
 * retrying. Callbacks must finish/copy their message before returning OK.
 */
int aa_receiver_step(void *,uint32_t);
/* Drain step/feed retries first. Queued/paused deliveries return PAUSED;
 * truncated wire or message ends fail terminally. Success closes receiver,
 * without closing/freeing the caller's TLS context. Stop is serialized,
 * discards queued/partial data and zeroes owned buffers; it is not a hardware
 * audio mute or asynchronous cancellation/quiescence guarantee.
 */
int aa_receiver_finish(void *,uint32_t);
int aa_receiver_stop(void *,uint32_t);
int aa_receiver_status(void *,uint32_t);
int aa_receiver_error_detail(void *,uint32_t);
int aa_receiver_queued(void *,uint32_t);
#endif
