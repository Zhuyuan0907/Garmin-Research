/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef AA_SENDER_H
#define AA_SENDER_H
#include <stdint.h>
#include <stddef.h>
#include "message.h"
enum {
    AA_SENDER_OK=0, AA_SENDER_PAUSED=1, AA_SENDER_PROGRESS=2, AA_SENDER_DONE=3,
    AA_SENDER_E_ARGUMENT=-400001, AA_SENDER_E_SESSION=-400002,
    AA_SENDER_E_STATE=-400003, AA_SENDER_E_TLS=-400004,
    AA_SENDER_E_RECORD=-400005, AA_SENDER_E_CAPACITY=-400006,
    AA_SENDER_E_TRANSPORT=-400007, AA_SENDER_E_REENTRANT=-400008
};
/* Serialized post-handshake, small control-message sender. The caller owns a
 * fresh zeroed/aligned>=8 context and the already verified TLS session. Calls
 * into receiver and sender MUST be serialized; no concurrent TLS owner exists.
 * At submission TLS must have no pending write or undrained output. Each
 * complete message (2..8192 bytes including BE16 ID) is copied, then emitted
 * as ONE legacy BULK AA frame. Larger media / outgoing fragmentation are not
 * implemented. Current Pixel/Google compatibility is unverified.
 *
 * Peek is a borrowed stable lease until commit/error/stop. Commit only bytes
 * the transport has actually accepted successfully, not bytes just queued to
 * USB. DONE only follows the final successful byte commit. The owner then
 * commits the matching control token and releases this sender. A terminal
 * error invalidates the whole TLS session; discard/free TLS before restart.
 * Stop only zeros owned memory; not async cancellation or hardware mute.
 * EVERY stop abandons this entire TLS session. Owner MUST discard/free TLS
 * and establish a new verified session before constructing another sender.
 * This is a caller obligation, not enforced by the generic TLS adapter: an
 * already generated but unsent record advanced TLS's sequence number, and
 * discarding its bytes cannot safely cancel just one message.
 */
uint32_t aa_sender_context_bytes(void);
int aa_sender_init(void *,void *tls,uint32_t session);
int aa_sender_submit(void *,uint32_t,const struct aa_message_view *,uint32_t token);
int aa_sender_step(void *,uint32_t);
int aa_sender_tx_peek(void *,uint32_t,const uint8_t **,size_t *);
int aa_sender_tx_commit(void *,uint32_t,size_t bytes,int transport_status);
int aa_sender_token(void *,uint32_t,uint32_t *);
int aa_sender_release(void *,uint32_t,uint32_t token);
int aa_sender_status(void *,uint32_t);
int aa_sender_error_detail(void *,uint32_t);
int aa_sender_stop(void *,uint32_t);
#endif
