/* Experimental raw notice journal, no device hook or PCM recycling.
 * Caller must supply the original report task's valid 20-byte notice frame.
 * Preserve the original dispatcher and copy notices before it translates
 * per-channel fields. Queue/configuration epochs are not stream generations.
 */
#include <stdint.h>
#include <string.h>

#define NOTICE_BYTES 20u
#define NOTICE_SLOTS 4u
#define SOURCE_CHANNELS 18u
#define STOCK_NOTICE_DISPATCH 0x455b65u

struct observer_control {
    uint32_t channel, event_mask, epoch, armed, in_flight, read, write, count;
    uint32_t calls, captured, filtered, full, canceled, last_original_result, initialized;
};
volatile struct observer_control memory_notice_control;
static uint8_t notice_slots[NOTICE_SLOTS][NOTICE_BYTES];

static uint32_t lock(void)
{
    uint32_t saved = ((uint32_t (*)(void))0x21b6cc)();
    __asm__ volatile ("" ::: "memory");
    return saved;
}
static void unlock(uint32_t saved)
{
    __asm__ volatile ("" ::: "memory");
    ((void (*)(uint32_t))0x21b6dc)(saved);
}

/* Initial BSS must be cleared by the loader. Configuration is permitted only
 * with no observer call in flight; it resets this journal, never source PCM.
 */
int memory_notice_configure(uint32_t channel, uint32_t event_mask)
{
    if (channel >= SOURCE_CHANNELS || (event_mask & ~0x1fffu)) return -20;
    uint32_t saved = lock();
    if (memory_notice_control.in_flight) { unlock(saved); return -25; }
    uint32_t epoch = memory_notice_control.epoch+1u;
    if (!epoch) { unlock(saved); return -30; }
    memset((void *)&memory_notice_control, 0, sizeof(memory_notice_control));
    memory_notice_control.channel = channel;
    memory_notice_control.event_mask = event_mask;
    memory_notice_control.epoch = epoch;
    memory_notice_control.armed = 1;
    memory_notice_control.initialized = 1;
    unlock(saved);
    return 0;
}

int memory_notice_disarm(void)
{
    uint32_t saved = lock();
    memory_notice_control.armed = 0;
    memory_notice_control.read = memory_notice_control.write = memory_notice_control.count = 0;
    /* No code/unload or source-callback quiescence is implied. In-flight
     * snapshots are rejected by armed/epoch even if dispatch later returns.
     */
    if (memory_notice_control.epoch != UINT32_MAX) memory_notice_control.epoch++;
    unlock(saved);
    return 0;
}

uint32_t memory_notice_dispatch(const uint8_t *notice, void *original_control)
{
    uint8_t snapshot[NOTICE_BYTES];
    uint32_t saved = lock();
    memory_notice_control.in_flight++;
    uint32_t epoch = memory_notice_control.epoch;
    int selected = 0;
    if (memory_notice_control.initialized && memory_notice_control.armed && notice) {
        uint32_t event = notice[1];
        if (event >= 21u && event <= 33u && notice[0] == memory_notice_control.channel)
            selected = (memory_notice_control.event_mask & (1u << (event-21u))) != 0;
    }
    unlock(saved);
    if (selected) memcpy(snapshot, notice, NOTICE_BYTES);
    /* Never call a custom App handler instead of the original translator. */
    uint32_t result = ((uint32_t (*)(const uint8_t *, void *))STOCK_NOTICE_DISPATCH)
                      (notice, original_control);
    saved = lock();
    memory_notice_control.calls++;
    memory_notice_control.last_original_result = result;
    if (!selected) memory_notice_control.filtered++;
    else if (!memory_notice_control.armed || memory_notice_control.epoch != epoch)
        memory_notice_control.canceled++;
    else if (memory_notice_control.count == NOTICE_SLOTS) memory_notice_control.full++;
    else {
        uint32_t slot = memory_notice_control.write;
        memcpy(notice_slots[slot], snapshot, NOTICE_BYTES);
        memory_notice_control.write = (slot+1u)%NOTICE_SLOTS;
        memory_notice_control.count++;
        memory_notice_control.captured++;
    }
    memory_notice_control.in_flight--;
    unlock(saved);
    return result;
}

/* The output is a copied raw notice, not a borrowed stack pointer. Caller
 * supplies writable non-overlapping memory. Dropped notices require source
 * state reconciliation; no caller may infer PCM safety from this journal.
 */
int memory_notice_pop(void *output, uint32_t output_bytes)
{
    if (!output || output_bytes < NOTICE_BYTES) return -20;
    uint32_t saved = lock();
    if (!memory_notice_control.count) { unlock(saved); return -26; }
    uint32_t slot = memory_notice_control.read;
    memcpy(output, notice_slots[slot], NOTICE_BYTES);
    memory_notice_control.read = (slot+1u)%NOTICE_SLOTS;
    memory_notice_control.count--;
    unlock(saved);
    return 0;
}

const void *const memory_notice_api[] __attribute__((used, section(".notice_api"))) = {
    (const void *)memory_notice_configure, (const void *)memory_notice_disarm,
    (const void *)memory_notice_dispatch, (const void *)memory_notice_pop
};
