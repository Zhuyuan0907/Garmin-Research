/* Owned finite PCM for the exact HWID1352 kind10/flags12 interface.
 * Offline prototype: one serialized source actor/channel and exclusive
 * control of that channel's source list are REQUIRED caller contracts.
 * Pool inspection is admission, not reservation against other actors.
 * No hooks, task scheduling, decoder redirection or module unload installed.
 */
#include <stdint.h>
#include <string.h>
#include "memory_output.h"

#define SLOTS 4u
#define CAPACITY 4096u
#define CHANNELS 0x034e6f08u
#define STRIDE 0x208u
#define POOL 0x034e3cf4u
#define POOL_STRIDE 0x240u
#define MIXERS 0x034e5378u
#define STOCK_READ 0x48edf9u
#define STOCK_FORMAT 0x48ee31u
enum { FREE, COPYING, READY, QUEUED, ACTIVE };
volatile struct output_control memory_output_control;
volatile struct owned_slot memory_output_slots[SLOTS];
static uint8_t pcm0[CAPACITY] __attribute__((section(".pcm0"), aligned(4)));
static uint8_t pcm1[CAPACITY] __attribute__((section(".pcm1"), aligned(4)));
static uint8_t pcm2[CAPACITY] __attribute__((section(".pcm2"), aligned(4)));
static uint8_t pcm3[CAPACITY] __attribute__((section(".pcm3"), aligned(4)));
static uint8_t *const buffers[SLOTS] = {pcm0, pcm1, pcm2, pcm3};

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
static volatile uint8_t *record(void)
{
    return (volatile uint8_t *)(CHANNELS+memory_output_control.channel*STRIDE);
}
static uint32_t word(volatile uint8_t *p, uint32_t offset)
{
    return *(volatile uint32_t *)(p+offset);
}
static uint32_t node_count(void)
{
    return *(volatile uint16_t *)(record()+0x1c0);
}
static uint32_t mixer_active(void)
{
    return *(volatile uint8_t *)(MIXERS+memory_output_control.channel*0x130u+0x84u);
}
static volatile struct owned_slot *find(uint32_t ticket)
{
    volatile struct owned_slot *s = &memory_output_slots[ticket & 3u];
    return ticket && s->ticket == ticket && s->state != FREE ? s : 0;
}
static int methods_clear(void)
{
    volatile uint8_t *r = record();
    for (uint32_t i=0; i<68u; i++) if (r[0xf4u+i]) return 0;
    return 1;
}

/* BSS loader zeroing, configured channel/profile and valid caller memory are
 * external contracts. Reconfiguration cannot discard live/private buffers.
 */
int memory_output_configure(uint32_t channel)
{
    if (channel >= 18u) return -20;
    uint32_t saved = lock();
    if (memory_output_control.native_calls || memory_output_control.reader_in_flight ||
        memory_output_control.installed) { unlock(saved); return -25; }
    for (uint32_t i=0; i<SLOTS; i++)
        if (memory_output_slots[i].state != FREE) { unlock(saved); return -25; }
    memory_output_control.channel = channel;
    memory_output_control.initialized = 1;
    /* Preserve monotonic tickets across reconfiguration: stale tokens fail. */
    unlock(saved);
    return 0;
}

/* Copy before publishing to native code. Returns a positive private ticket,
 * never a native client ID. Existing READY/QUEUED/ACTIVE data stays immutable.
 */
int memory_output_submit(const void *pcm, uint32_t bytes)
{
    if (!pcm || !bytes || bytes > CAPACITY || (bytes & 1u)) return -20;
    uintptr_t start = (uintptr_t)pcm;
    if (start+bytes < start) return -20;
    for (uint32_t i=0; i<SLOTS; i++) {
        uintptr_t b = (uintptr_t)buffers[i];
        if (start < b+CAPACITY && start+bytes > b) return -20;
    }
    uint32_t saved = lock();
    if (!memory_output_control.initialized) { unlock(saved); return -28; }
    if (memory_output_control.generation == 0x1fffffffu) { unlock(saved); return -30; }
    uint32_t index;
    for (index=0; index<SLOTS; index++) if (memory_output_slots[index].state == FREE) break;
    if (index == SLOTS) { memory_output_control.full++; unlock(saved); return -24; }
    volatile struct owned_slot *s = &memory_output_slots[index];
    uint32_t ticket = (++memory_output_control.generation << 2) | index;
    s->ticket = ticket; s->state = COPYING; s->bytes = bytes;
    s->instance = UINT32_MAX; s->reads = s->in_flight = 0;
    unlock(saved);
    memcpy(buffers[index], pcm, bytes);
    saved = lock();
    s->state = READY;
    unlock(saved);
    return (int)ticket;
}

/* Cancel only a private, never-published buffer. */
int memory_output_discard(uint32_t ticket)
{
    uint32_t saved = lock();
    volatile struct owned_slot *s = find(ticket);
    int result = !s ? -28 : s->state != READY ? -25 : 0;
    if (!result) s->state = FREE;
    unlock(saved);
    return result;
}

int memory_output_register(uint32_t ticket)
{
    uint32_t params[0x20cu/4u];
    uint32_t saved = lock();
    volatile struct owned_slot *s = find(ticket);
    if (!s || s->state != READY) { unlock(saved); return -28; }
    if (memory_output_control.active_ticket || memory_output_control.native_calls ||
        node_count() || record()[2] || !methods_clear()) { unlock(saved); return -25; }
    s->state = QUEUED;
    memory_output_control.active_ticket = ticket;
    memory_output_control.native_calls++;
    uint32_t channel = memory_output_control.channel, bytes = s->bytes;
    unlock(saved);
    memset(params, 0, sizeof(params));
    params[0]=1; params[1]=16000; params[2]=16;
    params[3]=(uint32_t)buffers[ticket & 3u]; params[4]=bytes;
    /* Metadata=NULL: no arbitrary test ID is passed as a native App owner. */
    int result = ((int (*)(uint32_t,uint32_t,uint32_t,const void *,uint32_t,
                           const void *,uint32_t))0x270459)
                 (channel,10,12,params,sizeof(params),0,1);
    saved = lock();
    memory_output_control.native_calls--;
    memory_output_control.last_native_result = result;
    if (result && !node_count() && !record()[2]) {
        s->state = READY;
        memory_output_control.active_ticket = 0;
    } else if (result || node_count() != 1u) {
        /* Uncertain publication remains pinned for explicit reconciliation. */
        result = -31;
    }
    unlock(saved);
    return result;
}

/* Call immediately before the ORIGINAL serialized actor selects the source.
 * No other allocator may interleave under the stated actor contract. This
 * check does not reserve a native slot against independent channel actors.
 */
int memory_output_selection_guard(uint32_t ticket)
{
    uint32_t saved = lock();
    volatile struct owned_slot *s = find(ticket);
    int result = -28;
    if (s && s->state == QUEUED && memory_output_control.active_ticket == ticket &&
        !memory_output_control.native_calls && node_count() == 1u) {
        result = -33;
        for (uint32_t i=0; i<5u; i++)
            if (!*(volatile uint8_t *)(POOL+i*POOL_STRIDE+12u)) { result=0; break; }
    }
    unlock(saved);
    return result;
}

uint32_t memory_output_read(uint32_t instance, uint8_t *output, uint32_t capacity)
{
    uint32_t saved = lock();
    volatile struct owned_slot *s = find(memory_output_control.active_ticket);
    int owned = s && s->state == ACTIVE && s->instance == instance;
    memory_output_control.reader_in_flight++;
    if (owned) s->in_flight++;
    unlock(saved);
    uint32_t count = ((uint32_t (*)(uint32_t,uint8_t *,uint32_t))STOCK_READ)
                     (instance,output,capacity);
    saved = lock();
    memory_output_control.reader_in_flight--;
    memory_output_control.reads++; memory_output_control.bytes_read+=count;
    if (owned) { s->in_flight--; s->reads++; }
    unlock(saved);
    return count;
}

/* Explicit post-selector hook prototype. Only wrap the characterized native
 * kind10 instance borrowing this exact owned buffer; keep other methods.
 */
int memory_output_after_selection(uint32_t ticket)
{
    uint32_t saved = lock();
    volatile struct owned_slot *s = find(ticket);
    volatile uint8_t *r = record();
    uint32_t instance = word(r,0xf0u);
    int result = -27;
    if (!s || memory_output_control.active_ticket != ticket) result = -28;
    else if (memory_output_control.native_calls || memory_output_control.reader_in_flight)
        result = -25;
    else if (r[2] && instance < 5u && word(r,0x10cu) == STOCK_FORMAT) {
        volatile uint8_t *p = (volatile uint8_t *)(POOL+instance*POOL_STRIDE);
        if (p[12] && p[28] && word(p,16) == (uint32_t)buffers[ticket & 3u] &&
            word(p,20) == s->bytes) {
            if (s->state == ACTIVE && memory_output_control.installed &&
                instance == s->instance && word(r,0x108u) == (uint32_t)memory_output_read)
                result = 0;
            else if (s->state == QUEUED && word(r,0x108u) == STOCK_READ) {
                *(volatile uint32_t *)(r+0x108u) = (uint32_t)memory_output_read;
                s->instance = instance; s->state = ACTIVE;
                memory_output_control.installed = 1;
                result = 0;
            }
        }
    }
    unlock(saved);
    return result;
}

/* Caller MUST reach a serialized actor boundary AFTER stop15/cleanup19 and
 * complete original list-remove return, excluding not-yet-entered callbacks.
 * Native state checks and in-flight counters supplement that contract; they
 * cannot establish it across real actors/IRQs or prove safe module unload.
 */
int memory_output_release(uint32_t ticket)
{
    uint32_t saved = lock();
    volatile struct owned_slot *s = find(ticket);
    int result = -28;
    if (s && (s->state == QUEUED || s->state == ACTIVE) &&
        memory_output_control.active_ticket == ticket) {
        result = -25;
        if (!memory_output_control.native_calls && !memory_output_control.reader_in_flight &&
            !s->in_flight && !node_count() && !record()[2] && !mixer_active() && methods_clear()) {
            result = 0;
            for (uint32_t i=0; i<5u; i++) {
                volatile uint8_t *p=(volatile uint8_t *)(POOL+i*POOL_STRIDE);
                if (word(p,16) == (uint32_t)buffers[ticket & 3u] && (p[12] || p[28]))
                    result = -25;
            }
        }
        if (!result) {
            s->state = FREE;
            memory_output_control.active_ticket = memory_output_control.installed = 0;
            memory_output_control.releases++;
        }
    }
    unlock(saved);
    return result;
}

const void *const memory_output_api[] __attribute__((used, section(".output_api"))) = {
    (const void *)memory_output_configure, (const void *)memory_output_submit,
    (const void *)memory_output_discard, (const void *)memory_output_register,
    (const void *)memory_output_selection_guard, (const void *)memory_output_after_selection,
    (const void *)memory_output_read, (const void *)memory_output_release
};
