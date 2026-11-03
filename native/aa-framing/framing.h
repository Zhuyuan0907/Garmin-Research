/* SPDX-License-Identifier: GPL-3.0-or-later
 * Wire behavior derived from aasdk, Copyright (C) 2018 f1x.studio
 * (Michal Szwaj), commit046b3b381595509d0939fa84b14a90978f46ff63.
 * New bounded C implementation. See COPYING and provenance.json.
 */
#ifndef GARMIN_AA_FRAMING_H
#define GARMIN_AA_FRAMING_H
#include <stdint.h>
enum aa_frame_flags { AA_MIDDLE=0, AA_FIRST=1, AA_LAST=2, AA_BULK=3,
                     AA_CONTROL=4, AA_ENCRYPTED=8 };
enum aa_result { AA_MORE=0, AA_READY=1, AA_BUSY=2, AA_E_ARGUMENT=-40,
    AA_E_STATE=-41, AA_E_BOUNDS=-42, AA_E_PROTOCOL=-43, AA_E_ENCRYPTED=-44,
    AA_E_STALE=-45, AA_E_SEQUENCE=-46, AA_E_FRAGMENTS=-48, AA_E_CANCELLED=-49 };
struct aa_frame_context {
    uint32_t state,session,sequence,capacity;
    uint8_t *buffer;
    uint32_t header_used,header_needed,payload_bytes,payload_used;
    int32_t failure;
    uint32_t cancelled;
    uint8_t header[8];
};
struct aa_frame_view {
    uint32_t session,sequence,channel,flags,bytes,total_plain_bytes;
    const uint8_t *data;
};
struct aa_message_context {
    uint32_t state,session,last_sequence,channel,flags,total,bytes,capacity,max_fragments,fragments;
    uint8_t *buffer;
    int32_t failure;
    uint32_t cancelled;
};
struct aa_message_view {
    uint32_t session,sequence,channel,flags,bytes;
    const uint8_t *data;
};
/* Single serialized actor, unique session and fresh/unborrowed storage. Caller
 * provides real writable pools of stated capacities; input/output/context/
 * view/consumed/pools must not overlap. All feeds copy input synchronously.
 * A READY view borrows its pool until release; cancel retains that borrow.
 * Never reinitialize/free held storage. No DMA, allocator, TLS or OS here.
 * Malformed streams lock the context; recovery requires a new transport/session.
 * Reserved header bits rejected for this older pinned model, not a claim about
 * current phones. Fragmented channels may not interleave, as in this snapshot.
 */
int aa_frame_init(struct aa_frame_context *,uint32_t session,uint8_t *,uint32_t capacity);
/* Consume at most one complete frame. Always sets *consumed, even on error;
 * caller must retain/re-feed trailing bytes after releasing the READY frame.
 * Wire payload may be opaque ciphertext. FIRST total is PLAINTEXT message size
 * and is deliberately not compared to ciphertext length by this parser. */
int aa_frame_feed(struct aa_frame_context *,const uint8_t *,uint32_t bytes,uint32_t *consumed);
int aa_frame_peek(const struct aa_frame_context *,struct aa_frame_view *);
int aa_frame_release(struct aa_frame_context *);
int aa_frame_cancel(struct aa_frame_context *);
/* Encodes one supplied wire frame, including opaque ciphertext if tagged.
 * It does not encrypt or automatically split outgoing messages. Returns encoded
 * byte count or negative error; output unchanged for rejected arguments. */
int aa_frame_encode(uint8_t *,uint32_t capacity,uint32_t channel,uint32_t flags,
                    const uint8_t *data,uint32_t bytes,uint32_t total_plain_bytes);
int aa_message_init(struct aa_message_context *,uint32_t session,uint8_t *,uint32_t capacity,uint32_t max_fragments);
/* Plaintext only. Encrypted view returns E_ENCRYPTED WITHOUT mutation; a real
 * TLS/authentication adapter must decode it first. No fake decrypt callback.
 * Frames must be from the same session in consecutive global sequence. */
int aa_message_push(struct aa_message_context *,const struct aa_frame_view *);
int aa_message_peek(const struct aa_message_context *,struct aa_message_view *);
int aa_message_release(struct aa_message_context *);
int aa_message_cancel(struct aa_message_context *);
uint32_t aa_frame_context_bytes(void);
uint32_t aa_frame_view_bytes(void);
uint32_t aa_message_context_bytes(void);
uint32_t aa_message_view_bytes(void);
#endif
