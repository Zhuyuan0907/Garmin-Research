/* Resident, bounded one-node Stop/retirement prototype for the declared
 * Source/Mixer kernel fixture. This is NOT native ownership or STOP_DONE.
 * No callback target/module/task is unregistered or unloaded. */
#include "music_session_guard_v4.h"
#include "memory_output.h"
#include "media_queue.h"
#define NS_RECORD ((volatile uint8_t *)0x034e7f48u)
#define NS_MIXER ((volatile uint8_t *)(0x034e5378u+8u*0x130u))
#define NS_HEAD ((volatile uint32_t *)(0x034e68d8u+8u*4u))
extern struct mcs_guard aas_guard;
extern int continuous_media_cancel_ready(void);
enum ns_stage { NS_EMPTY,NS_NODE_CAPTURED,NS_BOUND,NS_BARRIER,
                NS_RETIRED,NS_PINNED_ERROR,NS_NO_INPUT_STOP };
volatile uint32_t ns_stage,ns_head,ns_epoch,ns_generation,ns_instance;
volatile uint32_t ns_attempts,ns_deferred,ns_barrier_returns,ns_remove_returns;
volatile uint32_t ns_anchor_returns,ns_fifo_canceled,ns_rejections,ns_hold;
volatile int32_t ns_last_result;
static uint32_t word(volatile uint8_t *p,uint32_t offset)
{return *(volatile uint32_t *)(p+offset);}
static uint32_t lock(void){return ((uint32_t (*)(void))0x21b6ccu)();}
static void unlock(uint32_t saved){((void (*)(uint32_t))0x21b6dcu)(saved);}
static int source_actor(struct mcs_guard *g)
{
    return g->magic==MCS_MAGIC && g->control && g->held &&
        g->control->adapters.current_actor(g->control->adapters.context)==g->owner &&
        g->normal_context(g->normal_context_arg);
}
static uint32_t count(void){return *(volatile uint16_t *)(NS_RECORD+0x1c0u);}
static int same_publication(struct mcs_guard *g)
{
    return g->epoch==ns_epoch && g->generation==ns_generation &&
        g->control->status.generation==ns_generation && ns_head &&
        *NS_HEAD==ns_head && count()==1u && g->registration_ticket &&
        memory_output_control.active_ticket==g->registration_ticket &&
        word(NS_RECORD,0x160u)==(uint32_t)(uintptr_t)mcs_queue_bridge;
}
static int methods_clear(void)
{
    for(uint32_t i=0;i<68u;i++)if(NS_RECORD[0xf4u+i])return 0;
    return 1;
}
static int same_mixer(struct mcs_guard *g)
{
    return g->mixer_tcb && word(NS_MIXER,0x78u)==g->mixer_tcb &&
        word(NS_MIXER,0x64u)==0x2fa0ddu &&
        word(NS_MIXER,0x68u)==g->mixer_queue &&
        word(NS_MIXER,0x6cu)==g->mixer_stack_end &&
        word(NS_MIXER,0x2cu)==g->mixer_stack_base &&
        word(NS_MIXER,0x30u)==g->mixer_queue &&
        *(volatile uint32_t *)(uintptr_t)(g->mixer_tcb+8u)==g->mixer_queue;
}
static int idle_provider(struct mcs_guard *g)
{
    volatile uint8_t *p=g->pool+ns_instance*576u;
    return !NS_RECORD[2] && !NS_MIXER[0x84u] && methods_clear() &&
        !p[12] && !p[28] && word(p,16u)==g->anchor && word(p,20u)==2u;
}
int ns_capture_registration(void)
{
    struct mcs_guard *g=&aas_guard;uint32_t saved=lock();int r=MCS_REJECTED;
    /* Called immediately AFTER the full original one-node registration.
     * The new compiled Source captures actual native head, never a host input.
     * This snapshot is bounded provenance, not durable channel exclusivity. */
    if(source_actor(g) && ns_stage==NS_EMPTY && g->registration_ticket &&
       count()==1u && *NS_HEAD && !g->borrow && !g->native_mutation &&
       !memory_output_control.native_calls && !memory_output_control.reader_in_flight &&
       !g->control->status.media_references && !g->control->status.callback_references &&
       !g->selected_session && g->control->status.armed &&
       memory_output_control.active_ticket==g->registration_ticket){
        ns_head=*NS_HEAD;ns_epoch=g->epoch;ns_generation=g->generation;
        ns_instance=UINT32_MAX;ns_stage=NS_NODE_CAPTURED;r=0;
    }
    unlock(saved);return r;
}
int ns_bind_selected(void)
{
    struct mcs_guard *g=&aas_guard;uint32_t saved=lock();int r=MCS_REJECTED;
    if(source_actor(g) && ns_stage==NS_NODE_CAPTURED && same_publication(g) &&
       same_mixer(g) && g->selected_session==ns_epoch && g->selected_instance<5u &&
       word(NS_RECORD,0xf0u)==g->selected_instance && NS_RECORD[2] &&
       word(NS_RECORD,0x108u)==(uint32_t)(uintptr_t)memory_output_read &&
       !g->borrow && !g->native_mutation && !memory_output_control.native_calls &&
       !memory_output_control.reader_in_flight){
        volatile uint8_t *p=g->pool+g->selected_instance*576u;
        if(p[12] && p[28] && word(p,16u)==g->anchor && word(p,20u)==2u){
            ns_instance=g->selected_instance;ns_stage=NS_BOUND;r=0;
        }
    }
    unlock(saved);return r;
}
static int send(uint32_t command,struct mcs_guard *g)
{
    uint32_t message[3]={command|(8u<<8),0,0};
    if(!same_mixer(g))return MCS_REJECTED;
    ((void (*)(uint32_t,const void *))0x37bce5u)(g->mixer_tcb,message);
    return 0; /* original copied transport is void, not a zero-success ABI */
}
static int pinned_error(struct mcs_guard *g,int error)
{
    uint32_t saved=lock();
    if(ns_hold){memory_output_control.native_calls--;ns_hold=0;}
    ns_stage=NS_PINNED_ERROR;ns_last_result=error;ns_rejections++;
    unlock(saved);mcs_mutation_end(g);return error;
}
int ns_retire_step(void)
{
    struct mcs_guard *g=&aas_guard;uint32_t saved=lock();int r;
    ns_attempts++;
    if(!source_actor(g)){ns_rejections++;unlock(saved);return UMC_WRONG_OWNER;}
    if(ns_stage==NS_RETIRED || ns_stage==NS_NO_INPUT_STOP){unlock(saved);return UMC_ALREADY;}
    if(g->control->status.state!=UMC_STOPPING || g->control->status.armed ||
       g->control->status.stop_requested_generation!=g->generation ||
       media_queue_control.running){ns_rejections++;unlock(saved);return MCS_REJECTED;}
    if(ns_stage==NS_EMPTY && !g->registration_ticket && !count() && !*NS_HEAD &&
       !g->selected_session && !memory_output_control.active_ticket){
        ns_stage=NS_NO_INPUT_STOP;unlock(saved);return 0;
    }
    if(ns_stage!=NS_BOUND || !same_publication(g) || !same_mixer(g) ||
       g->selected_session!=ns_epoch || g->selected_instance!=ns_instance ||
       ns_instance>=5u || word(NS_RECORD,0xf0u)!=ns_instance || !NS_RECORD[2] ||
       word(NS_RECORD,0x108u)!=(uint32_t)(uintptr_t)memory_output_read){
        ns_rejections++;unlock(saved);return MCS_REJECTED;
    }
    if(g->borrow || g->native_mutation || memory_output_control.native_calls ||
       memory_output_control.reader_in_flight || g->control->status.media_references ||
       g->control->status.callback_references){
        ns_deferred++;unlock(saved);return UMC_PENDING;
    }
    unlock(saved);
    r=mcs_mutation_begin(g);if(r)return r;
    /* Source is sole cleanup actor under this bounded fixture. Hold stays
     * across copied15/19, actual wait/ACK, provider release and full removal.
     * Unentered foreign callbacks remain a reason to keep the module resident. */
    saved=lock();memory_output_control.native_calls++;ns_hold=1;
    ns_stage=NS_BARRIER;unlock(saved);
    r=send(15,g);if(r)return pinned_error(g,r);
    r=send(19,g);if(r)return pinned_error(g,r);
    r=((int (*)(volatile void *,uint32_t,uint32_t))0x46cc7bu)(NS_RECORD,1,0);
    if(r)return pinned_error(g,r);
    ns_barrier_returns++;
    if(!same_publication(g) || !same_mixer(g) || !idle_provider(g) || g->borrow ||
       memory_output_control.reader_in_flight || g->control->status.media_references ||
       g->control->status.callback_references)return pinned_error(g,MCS_REJECTED);
    r=((int (*)(volatile void *,uint32_t))0x277675u)(NS_RECORD+0x1a8u,0);
    if(r)return pinned_error(g,r);
    ns_remove_returns++;
    if(*NS_HEAD || count() || !idle_provider(g) || g->borrow ||
       memory_output_control.reader_in_flight)return pinned_error(g,MCS_REJECTED);
    saved=lock();memory_output_control.native_calls--;ns_hold=0;unlock(saved);
    r=memory_output_release_session(ns_epoch);if(r)return pinned_error(g,r);
    ns_anchor_returns++;
    r=continuous_media_cancel_ready();if(r<0)return pinned_error(g,r);
    ns_fifo_canceled=(uint32_t)r;
    ns_stage=NS_RETIRED;ns_last_result=0;mcs_mutation_end(g);
    /* Keep control STOPPING, guard held, module/TCBs/storage pinned. No
     * native STOP_DONE, safe-unload or hardware/DMA drain is invented. */
    return 0;
}
void ns_status(uint32_t *p)
{
    p[0]=ns_stage;p[1]=ns_head;p[2]=ns_epoch;p[3]=ns_generation;
    p[4]=ns_instance;p[5]=ns_attempts;p[6]=ns_deferred;
    p[7]=ns_barrier_returns;p[8]=ns_remove_returns;p[9]=ns_anchor_returns;
    p[10]=ns_fifo_canceled;p[11]=ns_rejections;p[12]=ns_hold;
    p[13]=(uint32_t)ns_last_result;
}
