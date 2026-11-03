#ifndef GARMIN_MUSIC_ENDPOINT_H
#define GARMIN_MUSIC_ENDPOINT_H
#include <stdint.h>
/* Exact HWID1352/8.00 private ABI, candidate only. Stock AVDTP/SDP boot init
 * must already have completed. Caller serializes prepare/publish, keeps code,
 * callback and capabilities pinned until reboot, and installs the preaccept
 * dispatcher before publishing. No unload/unregister path is supplied.
 * SDP record ownership must be exclusive; lock ordering/concurrency on the
 * device is not proven by the offline single-actor prototype.
 */
/* Returns local SEID1..3, negative error. Unlock failure -38 retains ownership
 * and endpoint; it does not roll back or imply code can be unloaded.
 */
int music_endpoint_prepare(uint32_t callback,uint32_t local_receive_mtu);
/* Native SDP errors are preserved. In particular 0x2504 means the record was
 * enabled but DB unlock failed; publication is uncertain, never rolled back.
 */
int music_endpoint_publish(uint32_t local_seid,uint32_t callback);
/* Signaling dispatcher entry, caller holds original AVDTP lock. Registered
 * owned GetCapabilities excludes stock's fixed HeaderCompression claim;
 * actual dispatch installation remains a caller obligation.
 */
int music_endpoint_capabilities(uint32_t context,uint32_t signal,uint32_t transaction,
    const uint8_t *payload,uint32_t payload_length);
uint32_t music_endpoint_publication_state(void);
#endif
