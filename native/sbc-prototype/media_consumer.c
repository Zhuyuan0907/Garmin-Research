/* Offline capacity feedback for one original type17 audio-method instance.
 * The original reader still supplies all PCM. No global factory/firmware
 * patch, hardware interrupt entry, cold initialization or ownership policy.
 */
#include <stdint.h>
#include <string.h>
#include "media_queue.h"
#include "media_worker.h"

typedef uint32_t (*reader_fn)(uint32_t, uint8_t *, uint32_t);
#define STOCK_READER 0x484c05u
#define STOCK_FORMAT 0x484c49u
#define RING_BYTES 0xa000u
#define REQUIRED_FREE 8961u

struct consumer_state {
    uint32_t methods, installed, reads, notifications, original_reader, last_read_count;
    int32_t last_attach_error;
};
volatile struct consumer_state media_consumer_state;

static uint32_t consumer_lock(void)
{
    uint32_t result = ((uint32_t (*)(void))0x21b6cc)();
    __asm__ volatile ("" ::: "memory");
    return result;
}
static void consumer_unlock(uint32_t saved)
{
    __asm__ volatile ("" ::: "memory");
    ((void (*)(uint32_t))0x21b6dc)(saved);
}

uint32_t media_consumer_read(uint32_t source, uint8_t *destination, uint32_t requested)
{
    uint32_t count = ((reader_fn)STOCK_READER)(source, destination, requested);
    uint32_t saved = consumer_lock();
    media_consumer_state.reads++;
    media_consumer_state.last_read_count = count;
    const volatile uint8_t *context = (const volatile uint8_t *)0xf09294;
    uint32_t write = *(const volatile uint32_t *)(context+12);
    uint32_t read = *(const volatile uint32_t *)(context+16);
    uint32_t free = 0;
    if (write < RING_BYTES && read < RING_BYTES) {
        free = read >= write ? read-write : RING_BYTES-(write-read);
        if (!free) free = RING_BYTES;
    }
    int wake = count && media_consumer_state.installed && context[7] &&
        media_queue_control.running && media_queue_control.count &&
        media_worker_state.tcb && !media_worker_state.quit_requested && free >= REQUIRED_FREE;
    consumer_unlock(saved);
    /* Original post selects its normal/interrupt-marker path. In particular,
     * no custom context switch or fabricated event is made here.
     */
    if (wake && media_worker_notify_capacity() == 0) media_consumer_state.notifications++;
    return count;
}

/* First initialization only, with no active callback or attached instance. */
int media_consumer_init(void)
{
    memset((void *)&media_consumer_state, 0, sizeof(media_consumer_state));
    return 0;
}

int media_consumer_attach(uint32_t *methods, uint32_t bytes)
{
    if (methods == 0 || ((uintptr_t)methods & 3u) || bytes < 0x44u) return -20;
    uint32_t saved = consumer_lock();
    int result = 0;
    if (media_consumer_state.installed) result = -25;
    else if (methods[5] != STOCK_READER || methods[6] != STOCK_FORMAT) result = -27;
    if (result == 0) {
        media_consumer_state.methods = (uint32_t)methods;
        media_consumer_state.original_reader = methods[5];
        media_consumer_state.installed = 1;
        methods[5] = (uint32_t)media_consumer_read;
    }
    media_consumer_state.last_attach_error = result;
    consumer_unlock(saved);
    return result;
}

int media_consumer_detach(void)
{
    uint32_t saved = consumer_lock();
    int result = 0;
    if (!media_consumer_state.installed) result = -28;
    else {
        uint32_t *methods = (uint32_t *)media_consumer_state.methods;
        if (methods[5] != (uint32_t)media_consumer_read) result = -29;
        else {
            methods[5] = media_consumer_state.original_reader;
            media_consumer_state.installed = 0;
        }
    }
    consumer_unlock(saved);
    /* Detach prevents new calls through this instance, but does not prove
     * previously entered callbacks have returned or the module can unload.
     */
    return result;
}

/* Called after source selection has returned on the serialized mixer actor.
 * This does not install that call-site hook or establish actor quiescence.
 * An unrelated provider change must not be silently overwritten.
 */
int media_consumer_refresh_after_selection(void)
{
    uint32_t saved = consumer_lock();
    int result = 0;
    if (!media_consumer_state.installed) result = -28;
    else {
        uint32_t *methods = (uint32_t *)media_consumer_state.methods;
        if (methods[6] != STOCK_FORMAT ||
            (methods[5] != STOCK_READER && methods[5] != (uint32_t)media_consumer_read))
            result = -27;
        else methods[5] = (uint32_t)media_consumer_read;
    }
    media_consumer_state.last_attach_error = result;
    consumer_unlock(saved);
    return result;
}

const void *const media_consumer_api[] __attribute__((used, section(".consumer_api"))) = {
    (const void *)media_consumer_init, (const void *)media_consumer_attach,
    (const void *)media_consumer_detach, (const void *)media_consumer_read,
    (const void *)media_consumer_refresh_after_selection
};
