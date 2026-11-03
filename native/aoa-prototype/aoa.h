#ifndef GARMIN_AOA_PROTOTYPE_H
#define GARMIN_AOA_PROTOTYPE_H
#include <stdint.h>

/* Single actor. The controller owns no copy of the context: it borrows setup
 * and data until ONE terminal completion/cancellation acknowledgement. A
 * timeout/cancel cannot revoke that borrow. Never reinitialize/free a borrowed
 * context, or reuse a session ID for delayed callbacks. No controller exists
 * in this prototype. ACCESSORY_IDENTIFIED does NOT mean bulk/TLS/AA ready. */
enum aoa_state { AOA_PROTOCOL=1, AOA_STRINGS, AOA_START,
    AOA_WAIT_REENUMERATION, AOA_ACCESSORY_IDENTIFIED, AOA_FAILED };
enum aoa_result { AOA_IDLE=0, AOA_REQUEST=1, AOA_BUSY=2,
    AOA_E_ARGUMENT=-1, AOA_E_STALE=-2, AOA_E_TIMEOUT=-3,
    AOA_E_TRANSFER=-4, AOA_E_PROTOCOL=-5, AOA_E_STATE=-6,
    AOA_E_SEQUENCE=-7, AOA_E_CANCELLED=-8 };

struct aoa_options {
    uint32_t session, device_generation, transfer_timeout_ms, reenumeration_timeout_ms;
    uint16_t initial_vid, initial_pid;
    const uint8_t *strings[6];
    uint32_t string_bytes[6]; /* includes NUL, 1..256; explicit bounded reads */
};
struct aoa_request {
    uint32_t session, sequence, device_generation;
    const uint8_t *setup;
    uint8_t *data;
    uint32_t data_bytes, direction_in;
};
struct aoa_context {
    uint32_t session, device_generation, sequence, state, string_index;
    uint32_t transfer_timeout_ms, reenumeration_timeout_ms, deadline;
    uint32_t borrowed;
    int32_t failure;
    uint32_t protocol_version;
    uint16_t string_bytes[6];
    uint8_t setup[8], rx[2], strings[6][256];
};
int aoa_init(struct aoa_context *, const struct aoa_options *, uint32_t now);
int aoa_next(struct aoa_context *, uint32_t now, struct aoa_request *);
/* actual_bytes excludes the 8-byte setup; success is 0, all errors nonzero.
 * A terminal callback means controller/DMA will never touch its borrow again.
 * Complete only after IN bytes have been written to request.data. */
int aoa_complete(struct aoa_context *, uint32_t session, uint32_t sequence,
                 int status, uint32_t actual_bytes, uint32_t now);
int aoa_cancel(struct aoa_context *);
/* Called only after the controller has acknowledged cancellation. */
int aoa_cancel_ack(struct aoa_context *, uint32_t session, uint32_t sequence);
/* Caller verifies SAME physical port/device lineage; VID/PID alone are not
 * identity. Generations strictly increase without wrapping within a session.
 * Host enumeration, config/interface/bulk selection remain external. */
int aoa_reenumerated(struct aoa_context *, uint32_t session, uint32_t generation,
                    uint32_t vid, uint32_t pid, uint32_t now);
uint32_t aoa_context_bytes(void);
uint32_t aoa_options_bytes(void);
uint32_t aoa_request_bytes(void);
#endif
