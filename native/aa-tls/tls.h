/* SPDX-License-Identifier: Apache-2.0 */
#ifndef AA_NATIVE_TLS_H
#define AA_NATIVE_TLS_H
#include <stdint.h>
#include <stddef.h>
/* Native caller must own real writable context/heap, serialize calls, provide
 * fresh high-quality entropy and trusted Unix time, retain storage until free,
 * bind a unique nonzero session and avoid overlapping input/output/context.
 * No filesystem/socket/OS entropy fallback, AA credentials or USB backend.
 * Handshake timeout uses caller monotonic32 time (interval < 2^31).
 * Every transport byte is copied: no borrowed cipher view/USB DMA pointer.
 * Pending plaintext writes are copied; retry without changing their bytes.
 * This is ABI version 2; it replaces the finite seed with a caller entropy
 * callback. The callback/opaque storage must outlive the TLS context and supply
 * fresh cryptographic entropy on every request, including future reseeds.
 * The caller must refresh trusted wall time separately from monotonic time.
 * No Garmin entropy/time provider or Android Auto handshake is implemented.
 */
#define AA_TLS_ABI_VERSION 2u
typedef int (*aa_tls_entropy_fn)(void *, unsigned char *, size_t);
enum { AA_TLS_BAD_ARGUMENT=-100001, AA_TLS_BAD_SESSION=-100002,
       AA_TLS_BUSY=-100003, AA_TLS_TIMED_OUT=-100004,
       AA_TLS_BAD_STATE=-100005, AA_TLS_CAPACITY=-100006 };
struct aa_tls_params {
    uint32_t session;
    const char *hostname;
    uint32_t hostname_bytes;
    const unsigned char *ca;
    uint32_t ca_bytes;
    const unsigned char *cert;
    uint32_t cert_bytes;
    const unsigned char *key;
    uint32_t key_bytes;
    aa_tls_entropy_fn entropy;
    void *entropy_context;
    uint32_t now_ms, timeout_ms;
};
uint32_t aa_tls_context_bytes(void);
uint32_t aa_tls_params_bytes(void);
int aa_tls_runtime_init(void *heap, uint32_t heap_bytes, uint32_t unix_time);
int aa_tls_runtime_set_time(uint32_t unix_time);
int aa_tls_init(void *context, const struct aa_tls_params *params);
int aa_tls_feed(void *, uint32_t session, const void *, uint32_t bytes);
int aa_tls_take_out(void *, uint32_t session, void *, uint32_t capacity);
int aa_tls_handshake(void *, uint32_t session, uint32_t now_ms);
int aa_tls_write(void *, uint32_t session, const void *, uint32_t bytes);
int aa_tls_retry_write(void *, uint32_t session);
/* Write/retry return bytes accepted by TLS on this call, or WANT/error. After
 * any partial result retry the owned remainder, not the original caller data.
 * Zero is no progress. Pending bytes must reach zero before the next write.
 */
int aa_tls_pending_bytes(void *, uint32_t session);
int aa_tls_read(void *, uint32_t session, void *, uint32_t capacity);
int aa_tls_close(void *, uint32_t session);
int aa_tls_status(void *, uint32_t session);
uint32_t aa_tls_verify_flags(void *, uint32_t session);
int aa_tls_free(void *, uint32_t session);
uint32_t aa_tls_heap_used(void);
uint32_t aa_tls_heap_max(void);
int aa_tls_heap_verify(void);
#endif
