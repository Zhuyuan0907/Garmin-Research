#ifndef GARMIN_MEMORY_OUTPUT_H
#define GARMIN_MEMORY_OUTPUT_H
#include <stdint.h>
/* Private prototype metadata, NOT a public Garmin ABI. One serialized actor
 * owns the channel list; pool inspection is not cross-actor reservation.
 */
struct owned_slot {
    uint32_t ticket, state, bytes, instance, reads, in_flight;
};
struct output_control {
    uint32_t initialized, channel, generation, active_ticket, installed;
    uint32_t native_calls, reader_in_flight, reads, bytes_read, releases, full;
    int32_t last_native_result;
};
extern volatile struct output_control memory_output_control;
extern volatile struct owned_slot memory_output_slots[4];
int memory_output_configure(uint32_t);
int memory_output_submit(const void *, uint32_t);
int memory_output_discard(uint32_t);
int memory_output_register(uint32_t);
int memory_output_selection_guard(uint32_t);
int memory_output_after_selection(uint32_t);
uint32_t memory_output_read(uint32_t, uint8_t *, uint32_t);
int memory_output_release(uint32_t);
#endif
