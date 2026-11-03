/* Offline exact-version prototype. Serialized exclusive channel/list owner
 * and pinned module/PCM are required; state checks are not a cross-task barrier.
 * Links to the unchanged owned-media artifact's PRIVATE ABI, not Garmin APIs.
 */
#include <stdint.h>
#include <stddef.h>
#include "memory_output.h"
#include "playback_imports.h"

_Static_assert(sizeof(struct owned_slot) == 24, "owned slot ABI differs");
_Static_assert(sizeof(struct output_control) == 48, "owned control ABI differs");
_Static_assert(offsetof(struct output_control, reader_in_flight) == 24, "reader ABI differs");
enum { FREE, COPYING, READY, QUEUED, ACTIVE };
struct playback_state {
    uint32_t callback_entries, bypassed, attached, attach_rejected;
    uint32_t rearm_attempts, rearmed, rearm_refused;
    int32_t last_result;
};
volatile struct playback_state playback_state;

static uint32_t lock(void)
{
    uint32_t flags = ((uint32_t (*)(void))0x21b6cc)();
    __asm__ volatile ("" ::: "memory");
    return flags;
}
static void unlock(uint32_t flags)
{
    __asm__ volatile ("" ::: "memory");
    ((void (*)(uint32_t))0x21b6dc)(flags);
}

/* Assembly hook invokes this before the ORIGINAL allocation callback posts
 * START14. Unrelated channels/no owned ticket pass to the original callback.
 * Failed owned attachment does not start reads; native allocations stay held
 * for explicit reconciliation. This does not implement failure cancellation.
 */
int playback_before_start(const uint8_t *descriptor)
{
    playback_state.callback_entries++;
    if (!descriptor) {
        playback_state.attach_rejected++;
        return playback_state.last_result = -20;
    }
    if (!memory_output_control.initialized || !memory_output_control.active_ticket ||
        descriptor[0] != memory_output_control.channel) {
        playback_state.bypassed++;
        return playback_state.last_result = 0;
    }
    int result = memory_output_after_selection(memory_output_control.active_ticket);
    if (result) playback_state.attach_rejected++;
    else playback_state.attached++;
    return playback_state.last_result = result;
}

/* Retained queue source may replay after ORIGINAL stop/cleanup completion.
 * Never unpin PCM, rewrite native state, delete a source or allocate providers.
 * Caller must serialize against all native callers and future callbacks; IRQ
 * exclusion only protects this private transition, not global reservation.
 */
int playback_rearm(uint32_t ticket)
{
    uint32_t flags = lock();
    volatile struct owned_slot *s = &memory_output_slots[ticket & 3u];
    playback_state.rearm_attempts++;
    int result = -28;
    if (ticket && s->ticket == ticket && s->state == ACTIVE &&
        memory_output_control.active_ticket == ticket && memory_output_control.initialized &&
        memory_output_control.channel < 18u) {
        result = -25;
        uint32_t channel = memory_output_control.channel;
        volatile uint8_t *r = (volatile uint8_t *)(0x034e6f08u+channel*520u);
        volatile uint8_t *m = (volatile uint8_t *)(0x034e5378u+channel*304u);
        volatile uint8_t *d = (volatile uint8_t *)(0x034e32bcu+channel*84u);
        int clear = 1;
        for (uint32_t i=0; i<68u; i++) if (r[0xf4u+i]) clear=0;
        for (uint32_t i=0; i<5u; i++) {
            volatile uint8_t *p = (volatile uint8_t *)(0x034e3cf4u+i*576u);
            if (*(volatile uint32_t *)(p+16u) == playback_pcm_pages[ticket & 3u] &&
                (p[12] || p[28])) clear=0;
        }
        if (channel < 18u && !memory_output_control.native_calls &&
            !memory_output_control.reader_in_flight && !s->in_flight &&
            *(volatile uint16_t *)(r+0x1c0u) == 1u && !r[2] && !m[0x84u] &&
            !*(volatile uint16_t *)d && *(volatile uint8_t *)(0x034e9398u+channel) == 1u &&
            clear) {
            s->state = QUEUED; s->instance = UINT32_MAX;
            memory_output_control.installed = 0;
            result = 0;
        }
    }
    if (result) playback_state.rearm_refused++;
    else playback_state.rearmed++;
    playback_state.last_result = result;
    unlock(flags);
    return result;
}

const void *const playback_api[] __attribute__((used, section(".playback_api"))) = {
    (const void *)playback_before_start, (const void *)playback_rearm
};
