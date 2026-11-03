/* Offline prototype: grant CONFIG capability before the complete original
 * synchronous initializer. PLAY remains closed until that call returns.
 * This does not certify channel exclusivity, cancellation or hardware. */
#include "music_session_guard_v4.h"

extern struct mcs_guard aas_guard;
volatile uint32_t ms_sync_entries, ms_sync_grants, ms_sync_reuses;
volatile uint32_t ms_sync_rejections, ms_original_sync_completed;
volatile int32_t ms_before_result;

static uint32_t word(volatile uint8_t *p, uint32_t offset)
{ return *(volatile uint32_t *)(p + offset); }

static int existing_capability(struct mcs_guard *g)
{
    volatile uint8_t *m=(volatile uint8_t *)0x034e5cf8u;
    return g->mixer_tcb && g->mixer_session==g->epoch &&
        g->mixer_generation==g->generation &&
        g->mixer_admission_epoch==g->control->status.admission_epoch &&
        word(m,0x78)==g->mixer_tcb && word(m,0x64)==0x2fa0ddu &&
        word(m,0x68)==g->mixer_queue &&
        word(m,0x6c)==g->mixer_stack_end && word(m,0x70)==0x0117140cu &&
        word(m,0x74)==(uint32_t)(uintptr_t)(m+0x3cu) &&
        word(m,0x2c)==g->mixer_stack_base && word(m,0x30)==g->mixer_queue &&
        g->mixer_stack_end-g->mixer_stack_base==8192u &&
        g->mixer_tcb==((g->mixer_stack_end-108u)&~7u) &&
        word((volatile uint8_t *)(uintptr_t)g->mixer_tcb,8)==g->mixer_queue;
}

int ms_before_original_sync(uint32_t record, uint32_t wait,
                            uint32_t seek, uint32_t original_lr)
{
    struct mcs_guard *g=&aas_guard;
    /* Other native channels retain original behavior and do not change the
     * private channel8 completion gate. The assembly always tail-calls stock. */
    if(record!=0x034e7f48u)return UMC_OK;
    uint32_t irq=((uint32_t (*)(void))0x21b6ccu)();
    int allowed=record==0x034e7f48u && wait==1u && !seek &&
        original_lr==0x3b9c59u && g->magic==MCS_MAGIC && g->control &&
        g->control->magic==UMC_MAGIC && g->held && g->registration_ticket &&
        g->generation==g->control->status.generation &&
        g->control->status.armed && !g->borrow && !g->native_mutation &&
        !g->permit_entered && !g->output->native_calls &&
        !g->control->status.media_references &&
        !g->control->status.callback_references &&
        g->control->adapters.current_actor(g->control->adapters.context)==g->owner &&
        g->normal_context(g->normal_context_arg) &&
        word(g->source_record,0x160)==(uint32_t)(uintptr_t)mcs_queue_bridge &&
        umc_admission(g->control,g->generation,UMC_GATE_CONFIG);
    ms_sync_entries++;
    ms_original_sync_completed=0;
    ((void (*)(uint32_t))0x21b6dcu)(irq);
    if(!allowed){ms_sync_rejections++;ms_before_result=MCS_REJECTED;return MCS_REJECTED;}
    if(g->mixer_tcb){
        ms_before_result=existing_capability(g)?UMC_OK:MCS_REJECTED;
        if(!ms_before_result)ms_sync_reuses++;else ms_sync_rejections++;
    }else{
        ms_before_result=mcs_handoff_source_to_mixer(g);
        if(!ms_before_result)ms_sync_grants++;else ms_sync_rejections++;
    }
    return ms_before_result;
}

/* Called by the real source actor only after original3B9B66 returns. */
int ms_validate_completed_sync(void)
{
    struct mcs_guard *g=&aas_guard;
    if(ms_before_result || !ms_sync_entries || !g->held ||
       g->control->adapters.current_actor(g->control->adapters.context)!=g->owner ||
       !g->normal_context(g->normal_context_arg) || !existing_capability(g))
        return MCS_REJECTED;
    ms_original_sync_completed=1;
    return UMC_OK;
}
