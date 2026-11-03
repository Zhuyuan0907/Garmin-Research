#ifndef GARMIN_AVDTP_GATE_H
#define GARMIN_AVDTP_GATE_H
#include <stdint.h>
/* Exact HWID1352 MAIN ABI. Caller holds the original AVDTP mutex. Registered
 * descriptors/capabilities/callbacks must remain valid and module code pinned.
 * Claiming does NOT register SDP or a SEP. Zero BSS once before first claim;
 * never reinitialize while callbacks/code can be in flight.
 */
int music_gate_claim(uint32_t local_seid,uint32_t callback);
int music_gate_release(uint32_t local_seid,uint32_t callback);
int music_configuration_gate(uint32_t context,uint32_t signal,uint32_t transaction,
    const uint8_t *payload,uint32_t payload_length);
uint32_t music_gate_binding_bytes(void);
#endif
