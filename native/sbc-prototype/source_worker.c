/* Offline native coordinator task, exact HWID1352/8.00/private import ABI.
 * Hooks run after complete packet publication/source completion returns.
 * Normal task context only; module, PCM and stack remain pinned after exit.
 */
#include <stdint.h>
#include "memory_output.h"
extern int media_coordinator_init(void);
extern int media_coordinator_pump(void);
extern int media_coordinator_cancel(void);
struct coordinator_state {
    uint32_t initialized,owner_tcb,busy,ticket,cancel_pending,stop_sent;
    uint32_t starts,completed,cancelled,discarded,remove_calls,pump_calls,cancel_calls,failures;
    int32_t last_result;
};
extern volatile struct coordinator_state coordinator_state;
struct owned_media_control {
    uint32_t initialized,busy,read,write,count,gather_bytes,rate,channels;
    uint32_t committed,failed,canceled,released,last_ticket;
};
extern volatile struct owned_media_control owned_media_control;
struct source_worker_state {
    uint32_t tcb,entered,wake_returns,pending,publications,completions;
    uint32_t requests,pump_calls,cancel_requested,quit_requested,finished_on_stack;
    int32_t init_result,last_result;
};
volatile struct source_worker_state source_worker_state;
static uint32_t descriptor[5];
static uint8_t source_stack[16384]
    __attribute__((aligned(4096),section(".source_stack")));
_Static_assert(sizeof(struct coordinator_state)==60,"coordinator ABI differs");
_Static_assert(sizeof(struct owned_media_control)==52,"owned ABI differs");
static uint32_t lock(void) { return ((uint32_t (*)(void))0x21b6cc)(); }
static void unlock(uint32_t f) { ((void (*)(uint32_t))0x21b6dc)(f); }
static void post(uint32_t event)
{
    uint32_t f=lock();source_worker_state.pending|=event;unlock(f);
    ((void (*)(uint32_t,uint32_t))0x2fcf44)(source_worker_state.tcb,event);
}
static uint32_t take(void)
{
    uint32_t f=lock(),p=source_worker_state.pending;
    source_worker_state.pending=0;unlock(f);return p;
}
void source_worker_entry(void)
{
    source_worker_state.entered++;
    source_worker_state.init_result=media_coordinator_init();
    if (!source_worker_state.init_result) for (;;) {
        /* The mailbox is sticky across a post before wait. Durable pending
         * bits also survive notifications during a native synchronous call.
         */
        if (!take()) {
            (void)((uint32_t (*)(void))0x2fd035)();
            source_worker_state.wake_returns++;
            if (!take()) continue;
        }
        int result=source_worker_state.cancel_requested ?
            media_coordinator_cancel() : media_coordinator_pump();
        source_worker_state.pump_calls++;
        source_worker_state.last_result=result;
        /* Frozen cancel visits at most four slots. Confirm an empty result
         * once without waiting for a publication that will never arrive.
         */
        if (result==1 && coordinator_state.cancel_pending &&
            !coordinator_state.ticket && !owned_media_control.busy &&
            !owned_media_control.count) {
            result=media_coordinator_pump();
            source_worker_state.pump_calls++;
            source_worker_state.last_result=result;
        }
        if (!result && !coordinator_state.cancel_pending)
            source_worker_state.cancel_requested=0;
        if (source_worker_state.quit_requested && !coordinator_state.cancel_pending &&
            !coordinator_state.ticket && !owned_media_control.busy &&
            !owned_media_control.count) break;
    }
    source_worker_state.finished_on_stack=1;
    /* Return through original context-builder exit shim. Flag is not
     * independent proof of task unlinking or permission to unload.
     */
}
uint32_t source_worker_boot(uint32_t priority)
{
    if (source_worker_state.tcb || priority>255u) return 0;
    descriptor[0]=(uint32_t)source_worker_entry;
    descriptor[1]=0;descriptor[2]=(uint32_t)(source_stack+sizeof(source_stack));
    descriptor[3]=priority<<16;descriptor[4]=0;
    source_worker_state.tcb=((uint32_t (*)(uint32_t *))0x358bf9)(descriptor);
    ((void (*)(uint32_t *))0x2fbbbf)(descriptor);
    ((void (*)(uint32_t,uint32_t))0x2fcf44)(source_worker_state.tcb,8);
    return source_worker_state.tcb;
}
void source_worker_published(int result)
{
    if (!source_worker_state.tcb || source_worker_state.finished_on_stack) return;
    if (!result && owned_media_control.count) source_worker_state.publications++;
    if ((!result && owned_media_control.count) || source_worker_state.cancel_requested)
        post(0x10000u);
}
void source_worker_completed(const volatile void *record)
{
    if (!source_worker_state.tcb || source_worker_state.finished_on_stack ||
        (uint32_t)record!=0x034e6f08u+memory_output_control.channel*520u) return;
    source_worker_state.completions++;post(0x20000u);
}
int source_worker_cancel(void)
{
    if (!source_worker_state.tcb || source_worker_state.finished_on_stack) return -22;
    uint32_t f=lock();source_worker_state.cancel_requested=1;
    source_worker_state.requests++;unlock(f);post(0x40000u);return 0;
}
int source_worker_shutdown(void)
{
    if (!source_worker_state.tcb || source_worker_state.finished_on_stack) return -22;
    uint32_t f=lock();source_worker_state.quit_requested=1;unlock(f);
    return source_worker_cancel();
}
extern void source_publication_hook(void),source_completion_hook(void);
const void *const source_worker_api[] __attribute__((used,section(".source_worker_api")))={
    (const void *)source_worker_boot,(const void *)source_worker_cancel,
    (const void *)source_worker_shutdown,(const void *)source_publication_hook,
    (const void *)source_completion_hook
};
