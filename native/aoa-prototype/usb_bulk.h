#ifndef GARMIN_AOA_USB_BULK_H
#define GARMIN_AOA_USB_BULK_H
#include "usb_config.h"
#define AOA_BULK_BUFFER_BYTES 4096u
enum aoa_bulk_state { AOA_BULK_ACTIVE=1, AOA_BULK_STOPPED, AOA_BULK_FAILED };
enum aoa_bulk_direction { AOA_BULK_OUT=0, AOA_BULK_IN=1 };
enum aoa_bulk_error { AOA_BULK_E_DISCONNECTED=-30, AOA_BULK_E_PENDING=-31 };
struct aoa_bulk_lane {
    uint32_t borrowed, sequence, request_bytes, deadline, actual_bytes, offset, total_bytes;
};
struct aoa_bulk_context {
    uint32_t session, device_generation, sequence, timeout_ms, state;
    int32_t failure;
    uint32_t in_endpoint, out_endpoint, in_packet_bytes;
    struct aoa_bulk_lane rx,tx;
    uint8_t rx_data[AOA_BULK_BUFFER_BYTES],tx_data[AOA_BULK_BUFFER_BYTES];
};
struct aoa_bulk_request {
    uint32_t session, sequence, device_generation, direction, endpoint;
    uint8_t *data;
    uint32_t bytes;
};
/* Single serialized actor, one child per configured parent. Init only fresh or
 * quiescent storage. HAL binds SAME port/generation/session and must implement
 * terminal callbacks: after completion it will NEVER touch that borrow again.
 * RX/TX may both be in flight. HAL may write RX only, never TX. No controller,
 * DMA cache maintenance, USB framing/ZLP policy, TLS or native install here. */
int aoa_bulk_init(struct aoa_bulk_context *,const struct aoa_usb_context *);
int aoa_bulk_queue_tx(struct aoa_bulk_context *,const uint8_t *,uint32_t bytes);
int aoa_bulk_next_tx(struct aoa_bulk_context *,uint32_t now,struct aoa_bulk_request *);
/* Request a packet-size multiple, <=4096, to avoid arbitrary short IN buffers.
 * A short/zero successful IN is valid. Copy data with read_rx before reusing RX.
 * Input/output/request/context storage must not overlap. */
int aoa_bulk_next_rx(struct aoa_bulk_context *,uint32_t bytes,uint32_t now,struct aoa_bulk_request *);
/* Returns copied byte count (including 0 or 2), or a negative error. Pending
 * controller ownership is E_PENDING, not positive AOA_BUSY, to avoid ambiguity. */
int aoa_bulk_read_rx(struct aoa_bulk_context *,uint8_t *,uint32_t capacity);
/* Terminal completion. Errors/timeout lock the stream; partial error data is
 * recorded but not retried/delivered. Successful short OUT advances by actual
 * bytes and next_tx emits only remaining bytes. Successful OUT zero is error. */
int aoa_bulk_complete(struct aoa_bulk_context *,uint32_t session,uint32_t sequence,
                      uint32_t direction,int status,uint32_t actual,uint32_t now);
int aoa_bulk_poll(struct aoa_bulk_context *,uint32_t now);
/* Cancel/disconnect retains BOTH borrows until matching terminal completions.
 * Quiescent refers only to these controller borrows, not OS/module unload. */
int aoa_bulk_stop(struct aoa_bulk_context *,uint32_t disconnected);
int aoa_bulk_quiescent(const struct aoa_bulk_context *);
uint32_t aoa_bulk_context_bytes(void);
uint32_t aoa_bulk_request_bytes(void);
#endif
