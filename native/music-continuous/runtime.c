/* Exact HWID1352/8.00 OFFLINE runtime integration. Real driver inventory,
 * exclusive channel ownership, code pinning/MMU/cache and install unresolved.
 * Kernel tasks/events/source lifecycle run only in the declared VM fixture.
 */
#include "runtime.h"
#include "stream.h"
#include "music_patch_imports.h"
#include "../sbc-prototype/media_worker.h"
#include "../sbc-prototype/media_queue.h"
#include "../sbc-prototype/memory_output.h"
struct source_state {
    uint32_t tcb,entered,wake_returns,pending,publications,completions;
    uint32_t requests,pump_calls,cancel_requested,quit_requested,finished_on_stack;
    int32_t init_result,last_result;
};
extern volatile struct source_state source_worker_state;
struct coordinator_state { uint32_t initialized,owner_tcb,busy,ticket,cancel_pending; };
extern volatile struct coordinator_state coordinator_state;
struct owned_control {uint32_t initialized,busy,read,write,count;};
extern volatile struct owned_control owned_media_control;
struct runtime_state {
    uint32_t initialized,channel,decoder_tcb,source_tcb;
    int32_t last_error;
    uint32_t source_init_done;
    int32_t source_init_result;
    uint32_t source_init_owner,last_status,snapshots;
};
volatile struct runtime_state music_runtime_state;
extern uint32_t source_worker_boot(uint32_t);
extern int source_worker_cancel(void),source_worker_shutdown(void);
extern int native_music_callback(uint32_t,uint32_t,const void *,const uint8_t *,uint32_t);

static uint32_t irq_lock(void)
{
    uint32_t f=((uint32_t (*)(void))0x21b6cc)();
    __asm__ volatile ("" ::: "memory");return f;
}
static void irq_unlock(uint32_t f)
{
    __asm__ volatile ("" ::: "memory");((void (*)(uint32_t))0x21b6dc)(f);
}
extern int __real_media_coordinator_init(void);
/* Linker wraps only cross-object coordinator initialization, leaving the exact
 * original initializer intact. Publish completion AFTER its complete return;
 * source.entry++ and a zeroed init_result alone are not readiness evidence.
 */
int __wrap_media_coordinator_init(void)
{
    int result=__real_media_coordinator_init();
    uint32_t f=irq_lock();
    music_runtime_state.source_init_owner=((uint32_t (*)(void))0x358d25)();
    music_runtime_state.source_init_result=result;
    music_runtime_state.source_init_done=1;
    irq_unlock(f);return result;
}
/* One IRQ-protected snapshot for gates. No event posts, blocking functions or
 * output transitions under exclusion. Real clock/IRQ/channel reservation is
 * still a device contract, not inferred from this VM's boundary controls.
 */
uint32_t music_runtime_status(void)
{
    uint32_t f=irq_lock(),status=0,tcb=source_worker_state.tcb;
    if(tcb)status|=MUSIC_RUNTIME_ACTOR;
    if(music_runtime_state.initialized && tcb && music_runtime_state.source_init_done &&
        !music_runtime_state.source_init_result && music_runtime_state.source_init_owner==tcb &&
        coordinator_state.initialized && coordinator_state.owner_tcb==tcb &&
        source_worker_state.entered && !source_worker_state.init_result &&
        !source_worker_state.finished_on_stack && !source_worker_state.quit_requested &&
        media_worker_state.tcb && media_worker_state.entered &&
        !media_worker_state.quit_requested && !media_worker_state.finished_on_stack)
        status|=MUSIC_RUNTIME_READY;
    if(source_worker_state.cancel_requested || source_worker_state.quit_requested ||
        coordinator_state.cancel_pending || coordinator_state.busy || coordinator_state.ticket ||
        memory_output_control.active_ticket || memory_output_control.native_calls ||
        memory_output_control.reader_in_flight || media_queue_control.producer_busy ||
        media_queue_control.worker_busy || owned_media_control.busy || owned_media_control.count)
        status|=MUSIC_RUNTIME_BUSY;
    music_runtime_state.last_status=status;music_runtime_state.snapshots++;
    irq_unlock(f);return status;
}
int music_runtime_actor_present(void) { return !!(music_runtime_status()&MUSIC_RUNTIME_ACTOR); }
int music_runtime_source_busy(void) { return !!(music_runtime_status()&MUSIC_RUNTIME_BUSY); }
int music_runtime_ready(void) { return !!(music_runtime_status()&MUSIC_RUNTIME_READY); }
int music_runtime_boot(uint32_t channel,uint32_t decoder_priority,uint32_t source_priority)
{
    if(music_runtime_state.initialized || music_runtime_actor_present() || media_worker_state.tcb ||
        channel>=18u || decoder_priority>255u || source_priority>255u)return -25;
    int result=music_stream_output_prepare(channel);
    if(!result)result=media_worker_init();
    if(result){music_runtime_state.last_error=result;return result;}
    music_runtime_state.channel=channel;
    music_runtime_state.decoder_tcb=media_worker_boot(decoder_priority);
    music_runtime_state.source_tcb=source_worker_boot(source_priority);
    if(!music_runtime_state.decoder_tcb || !music_runtime_state.source_tcb)result=-26;
    /* TCBs/stacks retained on failure; this is not rollback/unload. */
    music_runtime_state.initialized=!result;music_runtime_state.last_error=result;return result;
}
int music_runtime_cancel(void)
{
    (void)media_queue_stop();
    return source_worker_cancel();
}
int music_runtime_shutdown(void)
{
    int result=media_worker_shutdown();
    int source=source_worker_shutdown();
    return result?result:source;
}

/* Original dispatcher holds AV mutex. Reject START while an old source's
 * asynchronous cancellation remains, before original state becomes streaming.
 * All other syntax/state checks run in the exact original START handler.
 */
int music_runtime_start_gate(uint32_t context,uint32_t signal,uint32_t tx,
                              const uint8_t *p,uint32_t n)
{
    /* Stock START's loop index truncates to8 bits. A body above255 would
     * wrap forever for repeated valid SEIDs; reject before entering it.
     */
    if(context<2u && signal==7u && tx<16u && n>255u){
        uint32_t ch=((volatile uint8_t *)(0x3a88eb8u+context*28u))[0x13];
        uint32_t failed=(p && (uintptr_t)p<=UINT32_MAX-n)?p[0]:0;
        if(ch<12u)return ((int (*)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t))0x5756adu)(ch,tx,signal,failed,0x11);
    }
    if(context<2u && signal==7u && tx<16u && p && n && n<=255u && (uintptr_t)p<=UINT32_MAX-n){
        uint32_t status=music_runtime_status();
        for(uint32_t i=0;i<n;i++){
            uint32_t seid=p[i]>>2;
            if(seid<1u || seid>3u || (p[i]&3u))continue;
            volatile uint8_t *s=(volatile uint8_t *)(0x3a88ef0u+(seid-1u)*32u);
            if(*(volatile uint32_t *)s!=(uint32_t)native_music_callback)continue;
            if((status&(MUSIC_RUNTIME_READY|MUSIC_RUNTIME_BUSY))!=MUSIC_RUNTIME_READY){
                uint32_t ch=((volatile uint8_t *)(0x3a88eb8u+context*28u))[0x13];
                if(ch<12u)return ((int (*)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t))0x5756adu)(ch,tx,signal,p[i],0x31);
            }
        }
    }
    return ((int (*)(uint32_t,uint32_t,uint32_t,const uint8_t *,uint32_t))STOCK_START_HANDLER)(context,signal,tx,p,n);
}
const void *const music_runtime_api[] __attribute__((used,section(".music_runtime_api")))={
    (const void *)music_runtime_boot,(const void *)music_runtime_cancel,(const void *)music_runtime_shutdown,
    (const void *)music_runtime_start_gate,(const void *)music_runtime_status
};
