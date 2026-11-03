/* Offline ARM32 worker. No live Bluetooth, DAC or device installation. */
#include <stdint.h>
#include "../sbc-prototype/decoder.h"

struct scheduled_decode_job_v1 {
    uint32_t magic;
    const uint8_t *input;
    uint32_t input_bytes;
    uint8_t *output;
    uint32_t output_capacity;
    struct decoder_result *result;
    uint32_t observed_argument;
    uint32_t entered;
    int32_t decode_status;
    uint32_t controller_tcb;
    uint32_t notify_returned;
};

typedef void (*reset_fn)(void);
typedef int (*decode_fn)(const uint8_t *, uint32_t, uint8_t *, uint32_t,
                         struct decoder_result *);
typedef void (*post_fn)(uint32_t, uint32_t);

/* Exact immutable decoder-armv6.elf addresses, checked by the build script. */
#define DECODER_RESET_ADDRESS 0x0800223cu
#define DECODER_FRAME_ADDRESS 0x08002284u

void scheduled_decode_entry_v1(void *argument) {
    volatile struct scheduled_decode_job_v1 *job = argument;
    if (job->magic != 0x53424331u) return;
    job->observed_argument = (uint32_t)argument;
    job->entered++;
    ((reset_fn)DECODER_RESET_ADDRESS)();
    job->decode_status = ((decode_fn)DECODER_FRAME_ADDRESS)(
        job->input, job->input_bytes, job->output, job->output_capacity, job->result);
    ((post_fn)0x002fcf44u)(job->controller_tcb, 0x400u);
    job->notify_returned++;
}

void scheduled_idle_v1(void) {
    for (;;) __asm__ volatile("" ::: "memory");
}
