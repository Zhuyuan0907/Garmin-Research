#ifndef GARMIN_AOA_USB_CONFIG_H
#define GARMIN_AOA_USB_CONFIG_H
#include "aoa.h"
#define AOA_USB_MAX_CONFIGURATION 1024u
enum aoa_usb_speed { AOA_USB_FULL=1, AOA_USB_HIGH=2 };
enum aoa_usb_state { AOA_USB_NEEDS_CONFIGURATION=1, AOA_USB_CONFIGURED, AOA_USB_FAILED };
enum aoa_usb_error { AOA_USB_E_DESCRIPTOR=-20, AOA_USB_E_NOT_FOUND=-21,
                     AOA_USB_E_AMBIGUOUS=-22 };
struct aoa_usb_plan {
    uint32_t configuration, interface_number, in_endpoint, out_endpoint;
    uint32_t in_packet_bytes, out_packet_bytes;
};
struct aoa_usb_context {
    uint32_t session, device_generation, sequence, state, timeout_ms, deadline, borrowed;
    int32_t failure;
    struct aoa_usb_plan plan;
    uint8_t setup[8];
};
/* USB2 FS/HS only. Bounded to1024 bytes,64 interface/alt pairs. Output unchanged
 * on failure. Input/output/context/request storage must not overlap. Interface
 * identity FF/FF/00 comes from the pinned AOSP accessory function. Skip other
 * classes/protocols, including ADB; select default alt0 only. */
int aoa_usb_parse(const uint8_t *, uint32_t bytes, uint32_t speed, struct aoa_usb_plan *);
/* Parent must have identified the same re-enumerated accessory and hold no
 * controller borrow. Use exactly one child per parent/session. HAL provides the
 * complete config descriptor for the same physical port and generation. */
int aoa_usb_init(struct aoa_usb_context *, const struct aoa_context *,
                 const uint8_t *, uint32_t bytes, uint32_t speed);
int aoa_usb_next(struct aoa_usb_context *, uint32_t now, struct aoa_request *);
int aoa_usb_complete(struct aoa_usb_context *, uint32_t session, uint32_t sequence,
                     int status, uint32_t actual_bytes, uint32_t now);
int aoa_usb_cancel(struct aoa_usb_context *);
int aoa_usb_cancel_ack(struct aoa_usb_context *, uint32_t session, uint32_t sequence);
uint32_t aoa_usb_context_bytes(void);
uint32_t aoa_usb_plan_bytes(void);
/* CONFIGURED here means a successful fixture/controller callback, not bulk
 * traffic, interface ownership, TLS, Android Auto or a working Garmin host. */
#endif
