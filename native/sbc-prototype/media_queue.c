/* Offline, single-core queue experiment for exact HWID1352 firmware8.00.
 * No SEP registration, OS event loop, module installation or ownership of
 * the real TTS output ring is provided. Queue storage is preallocated.
 */
#include <stdint.h>
#include <string.h>
#include "media_queue.h"

#define SLOTS 4u
#define PACKET_BYTES 4096u
#define RING_BYTES 0xa000u
/* At most15 SBC frames, each producing at most256 mono16k PCM bytes.
 * Stock reserve requires strictly more than5120 bytes free before EACH
 * submission. The extra3840 is a conservative whole-packet allowance.
 * This is valid only for one producer and an already initialized ring.
 */
#define REQUIRED_FREE (5121u+15u*256u)
#define INVALID (-20)
#define NOT_RUNNING (-22)
#define FULL (-23)
#define CANCELLED (-24)
#define BUSY (-25)
#define DEFERRED 1
#define EMPTY 2

volatile struct queue_control media_queue_control;
volatile struct queue_stats media_queue_stats;
static uint32_t lengths[SLOTS];
static uint8_t slots[SLOTS][PACKET_BYTES]
    __attribute__((aligned(4096), section(".queue_payload")));

static uint32_t lock(void)
{
    uint32_t result = ((uint32_t (*)(void))0x21b6cc)();
    __asm__ volatile ("" ::: "memory");
    return result;
}
static void unlock(uint32_t saved)
{
    __asm__ volatile ("" ::: "memory");
    ((void (*)(uint32_t))0x21b6dc)(saved);
}
static void discard_pending(void)
{
    media_queue_stats.discarded += media_queue_control.count;
    media_queue_control.read = media_queue_control.write = media_queue_control.count = 0;
}

/* First initialization only, with no running caller or worker. A later stream
 * uses begin/stop; reinitializing while executing this module is unsupported.
 * Payload is not cleared: count/length publication prevents reading old bytes.
 */
int media_queue_init(media_fn consume, reset_fn reset)
{
    if (consume == 0 || reset == 0) return INVALID;
    uint32_t saved = lock();
    memset((void *)&media_queue_control, 0, sizeof(media_queue_control));
    memset((void *)&media_queue_stats, 0, sizeof(media_queue_stats));
    media_queue_control.consume = consume;
    media_queue_control.reset = reset;
    unlock(saved);
    return 0;
}

int media_queue_begin(void)
{
    uint32_t saved = lock();
    if (media_queue_control.running || media_queue_control.producer_busy ||
        media_queue_control.worker_busy) {
        unlock(saved);
        return BUSY;
    }
    if (media_queue_control.consume == 0 || media_queue_control.reset == 0) {
        unlock(saved);
        return INVALID;
    }
    discard_pending();
    uint32_t epoch = ++media_queue_control.epoch;
    media_queue_control.worker_busy = 1;
    unlock(saved);
    int result = media_queue_control.reset();
    saved = lock();
    media_queue_control.worker_busy = 0;
    if (media_queue_control.epoch != epoch) result = CANCELLED;
    media_queue_control.running = result == 0;
    unlock(saved);
    return result;
}

int media_queue_stop(void)
{
    uint32_t saved = lock();
    media_queue_control.running = 0;
    ++media_queue_control.epoch;
    /* A consumer can still be reading its slot outside the critical section.
     * Keep that storage reserved until it finishes. Never free module/stack.
     */
    if (!media_queue_control.worker_busy) discard_pending();
    unlock(saved);
    return 0;
}

/* Stock0x50BBC0 callback ABI. The temporary handle is deliberately not stored.
 * Copying/decoding happen with IRQs restored; only metadata is protected.
 */
int media_queue_callback(uint32_t event, uint32_t status, const void *handle,
                         const uint8_t *packet, uint32_t length)
{
    (void)handle;
    uint32_t saved = lock();
    media_queue_stats.callbacks++;
    int error = 0;
    if (event != 0xf1 || status != 0 || packet == 0 || length < 13 || length > PACKET_BYTES)
        error = INVALID;
    else if (!media_queue_control.running) error = NOT_RUNNING;
    else if (media_queue_control.producer_busy) error = BUSY;
    else if (media_queue_control.count == SLOTS) error = FULL;
    if (error) {
        media_queue_stats.rejected++;
        if (error == FULL) media_queue_stats.full++;
        media_queue_stats.last_error = error;
        unlock(saved);
        return error;
    }
    uint32_t slot = media_queue_control.write;
    uint32_t epoch = media_queue_control.epoch;
    media_queue_control.producer_busy = 1;
    unlock(saved);
    memcpy(slots[slot], packet, length);
    saved = lock();
    media_queue_control.producer_busy = 0;
    if (!media_queue_control.running || media_queue_control.epoch != epoch) {
        media_queue_stats.rejected++;
        media_queue_stats.last_error = CANCELLED;
        unlock(saved);
        return CANCELLED;
    }
    lengths[slot] = length;
    media_queue_control.write = (slot+1u)%SLOTS;
    media_queue_control.count++;
    media_queue_stats.enqueued++;
    media_queue_stats.last_error = 0;
    unlock(saved);
    return 0;
}

static int output_ready(void)
{
    const volatile uint8_t *context = (const volatile uint8_t *)0xf09294;
    if (!context[7]) return 0; /* Cold initialization remains unverified. */
    uint32_t write = *(const volatile uint32_t *)(context+12);
    uint32_t read = *(const volatile uint32_t *)(context+16);
    if (write >= RING_BYTES || read >= RING_BYTES) return 0;
    uint32_t free = read >= write ? read-write : RING_BYTES-(write-read);
    if (!free) free = RING_BYTES;
    return free >= REQUIRED_FREE;
}

/* One serialized, cooperatively cancellable work item. No OS wait is used.
 * An event loop must eventually call this function; that OS integration is
 * not implemented here. Real navigation output needs an ownership policy.
 */
int media_queue_step(void)
{
    uint32_t saved = lock();
    if (media_queue_control.worker_busy) { unlock(saved); return BUSY; }
    if (!media_queue_control.running) { unlock(saved); return NOT_RUNNING; }
    if (!media_queue_control.count) { unlock(saved); return EMPTY; }
    uint32_t slot = media_queue_control.read;
    uint32_t epoch = media_queue_control.epoch;
    media_queue_control.worker_busy = 1;
    unlock(saved);
    int ready = output_ready();
    saved = lock();
    if (!media_queue_control.running || media_queue_control.epoch != epoch) {
        media_queue_control.worker_busy = 0;
        discard_pending();
        unlock(saved);
        return CANCELLED;
    }
    if (!ready) {
        media_queue_control.worker_busy = 0;
        unlock(saved);
        return DEFERRED;
    }
    unlock(saved);
    int result = media_queue_control.consume(0xf1, 0, 0, slots[slot], lengths[slot]);
    saved = lock();
    media_queue_control.worker_busy = 0;
    media_queue_control.count--;
    media_queue_control.read = (slot+1u)%SLOTS;
    media_queue_stats.processed++;
    if (result) media_queue_stats.failed++;
    if (!media_queue_control.running || media_queue_control.epoch != epoch) {
        media_queue_stats.in_flight_cancelled++;
        discard_pending();
        result = CANCELLED;
    }
    media_queue_stats.last_error = result;
    unlock(saved);
    return result;
}

const void *const media_queue_api[] __attribute__((used, section(".queue_api"))) = {
    (const void *)media_queue_init, (const void *)media_queue_begin,
    (const void *)media_queue_stop, (const void *)media_queue_callback,
    (const void *)media_queue_step
};
