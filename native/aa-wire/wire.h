/* SPDX-License-Identifier: GPL-3.0-or-later
 * New host-tested C wire framer. Behavioral reference: aasdk commit
 * 046b3b381595509d0939fa84b14a90978f46ff63 (see provenance.json).
 * This is NOT a decrypted-message assembler or an official Google spec.
 */
#ifndef AA_WIRE_H
#define AA_WIRE_H
#include <stddef.h>
#include <stdint.h>

enum aa_wire_flags {
    AA_WIRE_MIDDLE = 0, AA_WIRE_FIRST = 1, AA_WIRE_LAST = 2,
    AA_WIRE_BULK = 3, AA_WIRE_CONTROL = 4, AA_WIRE_ENCRYPTED = 8
};
enum aa_wire_status {
    AA_WIRE_OK = 0, AA_WIRE_PAUSED = 1,
    AA_WIRE_E_ARGUMENT = -1, AA_WIRE_E_STATE = -2,
    AA_WIRE_E_FLAGS = -3, AA_WIRE_E_CAPACITY = -4,
    AA_WIRE_E_TRUNCATED = -5, AA_WIRE_E_CALLBACK = -6,
    AA_WIRE_E_REENTRANT = -7
};
struct aa_wire_frame {
    uint8_t channel;
    uint8_t flags;
    uint16_t payload_bytes;
    uint32_t total_plain_bytes;
    const uint8_t *payload;
};
/* Return OK only after accepting this frame, PAUSED only if NOT accepted.
 * Any other return is a terminal callback failure (saved in callback_status).
 * The frame structure itself is callback-local: NEVER retain its pointer.
 * payload is a copy in caller-owned storage, stable across PAUSED retries.
 * The caller must not write that storage while the parser owns a frame.
 * After OK it may be overwritten immediately by the SAME feed call; therefore
 * accepted views/pointers must not be retained beyond the callback return.
 * A paused callback may inspect/copy but must not enqueue or otherwise accept
 * the frame before returning PAUSED, since it is offered again on retry.
 */
typedef int (*aa_wire_callback)(void *, const struct aa_wire_frame *);
struct aa_wire_parser {
    uint8_t *storage;
    size_t capacity;
    aa_wire_callback callback;
    void *callback_arg;
    size_t header_used, header_needed, payload_used;
    uint16_t payload_bytes;
    uint8_t header[8];
    int state, error, callback_status, in_feed;
    uint32_t initialized;
};
/* Single serialized owner, no threads/IRQ/DMA or concurrent reset.
 * Parser, storage, input, consumed and callback state must not overlap.
 * Caller supplies valid accessible ranges; capacities are <=65535 bytes.
 * capacity=0 permits only zero-length frames and allows storage=NULL.
 * Init a fresh context only; discard/reset and quiesce old callbacks before
 * reinitializing or freeing storage. A callback must not modify the parser.
 */
int aa_wire_init(struct aa_wire_parser *, uint8_t *storage, size_t capacity,
                 aa_wire_callback, void *callback_arg);
/* Arbitrary transport chunks, potentially containing multiple frames.
 * ALWAYS initializes *consumed=0 when consumed!=NULL. Bytes reported consumed
 * have been copied/parsed even if PAUSED/error is returned. Re-feed only the
 * unconsumed tail. A pending frame is retried BEFORE new input is consumed.
 * Retry with (NULL,0) is supported. No callback before full frame arrival.
 * FIRST has 8-byte header; all other frame kinds have 4-byte header.
 * FIRST total_plain_bytes is plaintext message length and is deliberately NOT
 * compared with opaque wire payload length. Fragment sequencing, plaintext
 * assembly, TLS authentication/decryption and channels belong to later layers.
 * Reserved flag bits are rejected under this OLD pinned-model policy; current
 * Pixel/Android Auto wire compatibility is not established.
 */
int aa_wire_feed(struct aa_wire_parser *, const uint8_t *input, size_t bytes,
                 size_t *consumed);
/* Signal transport EOF. Partial headers/payloads are terminal TRUNCATED.
 * Pending callback remains PAUSED (no implicit retry). Success closes the
 * stream: additional nonempty input is rejected until explicit reset.
 */
int aa_wire_finish(struct aa_wire_parser *);
/* Intentionally drops all pending/partial bytes, preserving configuration.
 * Do not use reset as automatic resynchronization of a malformed transport.
 * It is for an explicitly ended/new transport after downstream quiescence.
 */
int aa_wire_reset(struct aa_wire_parser *);
#endif
