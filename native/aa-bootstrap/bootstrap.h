/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef AA_BOOTSTRAP_H
#define AA_BOOTSTRAP_H
#include <stdint.h>
#include <stddef.h>
enum {
    AA_BOOT_OK=0, AA_BOOT_PROGRESS=1, AA_BOOT_PAUSED=2, AA_BOOT_READY=3,
    AA_BOOT_E_ARGUMENT=-300001, AA_BOOT_E_SESSION=-300002,
    AA_BOOT_E_STATE=-300003, AA_BOOT_E_WIRE=-300004,
    AA_BOOT_E_MESSAGE=-300005, AA_BOOT_E_PROTOCOL=-300006,
    AA_BOOT_E_VERSION=-300007, AA_BOOT_E_TLS=-300008,
    AA_BOOT_E_TRANSPORT=-300009, AA_BOOT_E_TIMEOUT=-300010,
    AA_BOOT_E_RECORD=-300011, AA_BOOT_E_TRUNCATED=-300012
};
enum aa_boot_phase {
    AA_BOOT_VERSION_TX=1, AA_BOOT_WAIT_VERSION=2, AA_BOOT_TLS=3,
    AA_BOOT_AUTH_TX=4, AA_BOOT_AUTH_READY=5, AA_BOOT_STOPPED=6
};
/* Legacy aasdk 1.1 control envelope; configurable requested major/minor must
 * match the response exactly. Current Pixel/Google interoperability unknown.
 * TLS context is already initialized but MUST NOT have handshaken (state 0).
 * This serialized owner alone drives it until AUTH output is fully committed.
 * It then hands the SAME active TLS context to the post-handshake receiver.
 * No socket/USB/phone/native APIs or general protobuf/channel dispatch.
 *
 * Caller supplies distinct valid storage, zeroed/aligned>=8 context, wire
 * capacity 1..32768 and message capacity 8..32770, with lifetime through stop.
 * All calls and transport completions are serialized. TLS entropy/provider,
 * trusted time and monotonic deadline remain caller responsibilities.
 * Caller must periodically drive step(now_ms); no autonomous timer exists.
 */
uint32_t aa_bootstrap_context_bytes(void);
int aa_bootstrap_init(void *,void *tls,uint32_t session,uint16_t major,uint16_t minor,
                      uint32_t now_ms,uint32_t timeout_ms,
                      uint8_t *wire,size_t wire_capacity,
                      uint8_t *message,size_t message_capacity);
/* Stops consuming immediately after ONE complete incoming control message.
 * Does not consume any input while TX awaits confirmation or RX awaits step.
 * ALWAYS reports exact consumed, including on errors. After READY it returns
 * READY/consumed0; transfer the untouched tail to receiver after callback/feed
 * has returned. Never reset/reinitialize TLS or discard a USB completion tail.
 * This bytewise bootstrap feed favors a precise handoff boundary; realtime
 * performance/native suitability have not been measured.
 */
int aa_bootstrap_feed(void *,uint32_t,const uint8_t *,size_t,size_t *consumed);
int aa_bootstrap_step(void *,uint32_t,uint32_t now_ms);
/* Borrowed TX view stable until commit/stop/error; one serialized lease only.
 * peek does NOT advance. After actual successful transport completion commit
 * exactly bytes sent; zero-byte success is no progress. Failure is terminal.
 * AUTH_READY is reached only after the final AUTH byte is committed.
 * This gate is our stricter policy, not an upstream Google guarantee.
 */
int aa_bootstrap_tx_peek(void *,uint32_t,const uint8_t **view,size_t *bytes);
int aa_bootstrap_tx_commit(void *,uint32_t,size_t bytes,int transport_status);
int aa_bootstrap_status(void *,uint32_t);
int aa_bootstrap_error_detail(void *,uint32_t);
int aa_bootstrap_finish(void *,uint32_t);
/* Serialized discard only; does not free/close TLS or prove async quiescence. */
int aa_bootstrap_stop(void *,uint32_t);
#endif
