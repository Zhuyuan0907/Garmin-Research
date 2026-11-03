#ifndef GARMIN_MEDIA_QUEUE_H
#define GARMIN_MEDIA_QUEUE_H
#include <stdint.h>

typedef int (*media_fn)(uint32_t, uint32_t, const void *, const uint8_t *, uint32_t);
typedef int (*reset_fn)(void);
struct queue_control {
    uint32_t read, write, count, epoch, running, producer_busy, worker_busy;
    media_fn consume;
    reset_fn reset;
};
struct queue_stats {
    uint32_t callbacks, enqueued, full, rejected, processed, failed, discarded;
    int32_t last_error;
    uint32_t in_flight_cancelled;
};
extern volatile struct queue_control media_queue_control;
extern volatile struct queue_stats media_queue_stats;
int media_queue_init(media_fn consume, reset_fn reset);
int media_queue_begin(void);
int media_queue_stop(void);
int media_queue_callback(uint32_t, uint32_t, const void *, const uint8_t *, uint32_t);
int media_queue_step(void);
#endif
