#ifndef GARMIN_MEDIA_WORKER_H
#define GARMIN_MEDIA_WORKER_H
#include <stdint.h>

struct worker_state {
    uint32_t tcb, entered, wake_returns, handled_packets, capacity_deferrals;
    uint32_t quit_requested, finished_on_stack;
    int32_t last_step;
};
extern volatile struct worker_state media_worker_state;
int media_worker_init(void);
uint32_t media_worker_boot(uint32_t kernel_priority);
int media_worker_callback(uint32_t, uint32_t, const void *, const uint8_t *, uint32_t);
int media_worker_notify_capacity(void);
int media_worker_shutdown(void);
void media_worker_entry(void);
#endif
