/* Offline command handoff ABI, one controller and one outstanding command. */
#ifndef RESIDENT_MUSIC_V1_H
#define RESIDENT_MUSIC_V1_H
#include <stdint.h>
#include "../sbc-prototype/decoder.h"
enum resident_operation_v1 { RESIDENT_START=1, RESIDENT_DECODE=2, RESIDENT_STOP=3 };
struct resident_music_v1 {
    uint32_t magic, controller_tcb, adapter, observed_argument, worker_entries;
    uint32_t request_seq, completed_seq, operation;
    const uint8_t *input;
    uint32_t input_bytes;
    uint8_t *output;
    uint32_t output_capacity;
    struct decoder_result *result;
    int32_t status;
    uint32_t active, generation, wait_returns, notifications, notify_returns;
    uint32_t decode_successes, stopped_rejections, stops, resets, event_count;
    uint32_t controller_failure, controller_finished;
    uint32_t idle_pulse_request, idle_pulse_delivered, idle_post_returns;
    uint32_t worker_tcb_observed, active_start_rejections;
    uint32_t controller_tcb_observed, idle_tcb_observed;
    uint32_t events[16];
};
_Static_assert(sizeof(struct resident_music_v1)==196, "ARM32 command ABI");
#endif
