/* Offline OS task/event integration for exact Taiwan HWID1352/8.00.
 * Caller must initialize/begin the queue and arrange output-ring ownership.
 * This is not a loaded Garmin App; stacks/data remain allocated after exit.
 */
#include <stdint.h>
#include <string.h>
#include "media_queue.h"
#include "media_worker.h"
volatile struct worker_state media_worker_state;
static uint32_t descriptor[5];
static uint8_t worker_stack[16384]
    __attribute__((aligned(4096), section(".worker_stack")));

static void post(uint32_t events)
{
    ((void (*)(uint32_t, uint32_t))0x2fcf44)(media_worker_state.tcb, events);
}

void media_worker_entry(void)
{
    media_worker_state.entered++;
    for (;;) {
        /* Original wait blocks and switches context when mailbox is empty. */
        (void)((uint32_t (*)(void))0x2fd035)();
        media_worker_state.wake_returns++;
        if (media_worker_state.quit_requested) break;
        while (!media_worker_state.quit_requested) {
            int result = media_queue_step();
            media_worker_state.last_step = result;
            if (result == 1) {
                media_worker_state.capacity_deferrals++;
                break;
            }
            if (result == 2 || result == -22 || result == -24 || result == -25) break;
            media_worker_state.handled_packets++;
        }
        if (media_worker_state.quit_requested) break;
    }
    /* This flag is written while executing on the stack. It is NOT proof
     * that the kernel has unlinked this task or that the module can be freed.
     */
    media_worker_state.finished_on_stack = 1;
    /* Return through the original context builder's kernel exit shim. */
}

/* First initialization only, before any active caller. */
int media_worker_init(void)
{
    memset((void *)&media_worker_state, 0, sizeof(media_worker_state));
    memset(descriptor, 0, sizeof(descriptor));
    return 0;
}

uint32_t media_worker_boot(uint32_t kernel_priority)
{
    if (media_worker_state.tcb || kernel_priority > 255u) return 0;
    descriptor[0] = (uint32_t)media_worker_entry;
    /* Word1 affects mailbox acknowledgement; this is not an entry argument. */
    descriptor[1] = 0;
    descriptor[2] = (uint32_t)(worker_stack+sizeof(worker_stack));
    descriptor[3] = kernel_priority << 16;
    descriptor[4] = 0;
    media_worker_state.tcb = ((uint32_t (*)(uint32_t *))0x358bf9)(descriptor);
    ((void (*)(uint32_t *))0x2fbbbf)(descriptor);
    /* Bit8 makes an initial task runnable without leaving a mailbox event. */
    post(8);
    return media_worker_state.tcb;
}

int media_worker_callback(uint32_t event, uint32_t status, const void *handle,
                          const uint8_t *packet, uint32_t length)
{
    if (!media_worker_state.tcb || media_worker_state.quit_requested) return -22;
    int result = media_queue_callback(event, status, handle, packet, length);
    if (result == 0) post(1);
    return result;
}

/* Required after consumer capacity increases without a new accepted packet.
 * Wiring this to the actual audio consumer remains unimplemented.
 */
int media_worker_notify_capacity(void)
{
    if (!media_worker_state.tcb || media_worker_state.quit_requested) return -22;
    post(1);
    return 0;
}

int media_worker_shutdown(void)
{
    if (!media_worker_state.tcb) return -22;
    media_worker_state.quit_requested = 1;
    media_queue_stop();
    post(4);
    return 0;
}

const void *const media_worker_api[] __attribute__((used, section(".worker_api"))) = {
    (const void *)media_worker_init, (const void *)media_worker_boot,
    (const void *)media_worker_callback, (const void *)media_worker_notify_capacity,
    (const void *)media_worker_shutdown, (const void *)media_worker_entry
};
