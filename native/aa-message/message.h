/* SPDX-License-Identifier: GPL-3.0-or-later
 * New host-tested plaintext assembler; pinned aasdk behavioral reference.
 * See provenance.json. No TLS operation or authentication is performed here.
 */
#ifndef AA_MESSAGE_H
#define AA_MESSAGE_H
#include <stddef.h>
#include <stdint.h>
enum aa_message_flags {
    AA_MESSAGE_MIDDLE=0, AA_MESSAGE_FIRST=1, AA_MESSAGE_LAST=2,
    AA_MESSAGE_BULK=3, AA_MESSAGE_CONTROL=4, AA_MESSAGE_ENCRYPTED=8
};
enum aa_message_status {
    AA_MESSAGE_OK=0, AA_MESSAGE_PAUSED=1,
    AA_MESSAGE_E_ARGUMENT=-1, AA_MESSAGE_E_STATE=-2,
    AA_MESSAGE_E_FLAGS=-3, AA_MESSAGE_E_CAPACITY=-4,
    AA_MESSAGE_E_SEQUENCE=-5, AA_MESSAGE_E_LENGTH=-6,
    AA_MESSAGE_E_FRAGMENTS=-7, AA_MESSAGE_E_CALLBACK=-8,
    AA_MESSAGE_E_REENTRANT=-9, AA_MESSAGE_E_TRUNCATED=-10
};
struct aa_message_fragment {
    uint8_t channel, flags;
    uint32_t total_plain_bytes; /* FIRST only; must be zero otherwise. */
    const uint8_t *payload;     /* Complete already-decrypted fragment. */
    size_t bytes;
};
struct aa_message_view {
    uint8_t channel;
    uint8_t flags; /* CONTROL/ENCRYPTED origin metadata, no frame-kind bits. */
    uint32_t fragments;
    size_t bytes;
    const uint8_t *payload;
};
/* Entire view is callback-local. Never retain the view pointer. Payload storage
 * is owned by this parser and stable while delivery is PAUSED. After OK it may
 * be reused by the next push, so copy/process before returning OK. PAUSED means
 * the callback has NOT accepted the complete message: do not queue it first.
 * Any other return is a terminal error; original value saved in callback_status.
 */
typedef int (*aa_message_callback)(void *,const struct aa_message_view *);
struct aa_message_parser {
    uint8_t *storage;
    size_t capacity, bytes;
    uint32_t total_plain_bytes, max_fragments, fragments, initialized;
    uint8_t channel, flags;
    aa_message_callback callback;
    void *callback_arg;
    int state, error, callback_status, in_callback;
};
/* Fresh/quiescent context, single serialized caller, no concurrent/IRQ access.
 * capacity <= UINT32_MAX; zero capacity allows storage=NULL and empty messages.
 * max_fragments > 0 bounds even zero-byte fragment sequences. Parser, storage,
 * input, accepted and callback state must not overlap. Caller provides valid
 * accessible ranges; caller must not write storage while parser owns a message.
 * No allocator, TLS, OS, message ID dispatch or Garmin API is used.
 */
int aa_message_init(struct aa_message_parser *,uint8_t *storage,size_t capacity,
                    uint32_t max_fragments,aa_message_callback,void *callback_arg);
/* Each push contains ONE COMPLETE decrypted fragment. Caller must authenticate
 * encrypted wire data before pushing it; ENCRYPTED flag is retained provenance,
 * not proof that TLS happened. FIRST total is compared only with plaintext.
 * Always sets *accepted=0 initially when accepted!=NULL. If accepted=1, the whole
 * fragment has been copied/accepted and MUST NOT be resent, even on PAUSED or
 * callback error. PAUSED after copying final fragment retains a complete owned
 * message; use retry. While pending, push returns PAUSED/accepted=0 and does NOT
 * inspect the supplied fragment. Resume via retry, then send the unaccepted one.
 * Strict policy: no intertwined channels; FIRST/BULK start; MIDDLE/LAST continue;
 * channel, ENCRYPTED and CONTROL must stay identical; no excess/short LAST or
 * FIRST restart; only FIRST carries total. Reserved bits rejected. Policy is
 * stricter than old aasdk and unverified with current Pixel/Android Auto.
 * Empty BULK and FIRST(total=0)+empty LAST are allowed; even 1-byte messages are
 * allowed. A downstream dispatcher, not this assembler, checks a 2-byte ID.
 */
int aa_message_push(struct aa_message_parser *,const struct aa_message_fragment *,
                    int *accepted);
/* Retries ONLY delivery of an owned complete message; no payload input. */
int aa_message_retry(struct aa_message_parser *);
/* Transport end: incomplete message -> terminal TRUNCATED; pending -> PAUSED.
 * Successful finish closes the stream until an explicit quiescent reset. */
int aa_message_finish(struct aa_message_parser *);
/* Explicitly discard pending/partial data after downstream quiescence. Never
 * guess stream resynchronization after a malformed fragment. Do not init from
 * callback; push/retry/finish/reset callback reentry is rejected. */
int aa_message_reset(struct aa_message_parser *);
#endif
