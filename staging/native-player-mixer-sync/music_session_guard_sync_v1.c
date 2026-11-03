/* NEW v3 source; frozen v2 source is unchanged. The immutable control core
 * retains typed leases, Stop admission and fail-closed cancellation proof.
 * Original source/mixer TCB provenance must be established by the ROOT guest,
 * not by HOST actor or provider matches. */
#include "music_session_guard_v4.h"
#include "memory_output.h"
struct mcs_guard *mcs_bridge_context;
extern volatile uint32_t ms_original_sync_completed;
static uint32_t enter(struct mcs_guard *g)
{ return g->control->adapters.metadata_enter(g->control->adapters.context); }
static void leave(struct mcs_guard *g,uint32_t f)
{ g->control->adapters.metadata_leave(g->control->adapters.context,f); }
static uint32_t actor(struct mcs_guard *g)
{ return g->control->adapters.current_actor(g->control->adapters.context); }
static uint32_t word(volatile uint8_t *p,uint32_t off)
{ return *(volatile uint32_t *)(p+off); }
static int ready(struct mcs_guard *g)
{ return g && g->magic==MCS_MAGIC && g->control && g->control->magic==UMC_MAGIC; }
static int normal(struct mcs_guard *g)
{ return g->normal_context(g->normal_context_arg); }
int mcs_init(struct mcs_guard *g,struct umc_controller *c,
    volatile struct umcn_output_view *o,volatile struct umcn_slot_view *s,
    volatile uint8_t *r,volatile uint8_t *pool,uint32_t anchor,
    int (*is_normal)(void *),void *arg)
{
    if(!g || g->magic || !c || c->magic!=UMC_MAGIC || c->config.route!=8u ||
       !c->config.resident_storage_confirmed || !o || !s || !r || !pool ||
       !anchor || !is_normal || o->channel!=8u) return UMC_BAD_ARGUMENT;
    g->control=c;g->output=o;g->slots=s;g->source_record=r;g->pool=pool;
    g->anchor=anchor;g->owner=c->config.source_tcb;
    g->normal_context=is_normal;g->normal_context_arg=arg;
    g->selected_instance=UINT32_MAX;g->magic=MCS_MAGIC;
    return UMC_OK;
}
int mcs_reserve_scoped(struct mcs_guard *g,uint32_t generation)
{
    uint32_t f;int result=UMC_OK;
    if(!ready(g) || !generation)return UMC_BAD_ARGUMENT;
    f=enter(g);
    if(actor(g)!=g->owner || !normal(g))result=UMC_WRONG_OWNER;
    else if(g->held || g->borrow || g->permit_entered)result=UMC_BUSY;
    else if(g->epoch==UINT32_MAX)result=UMC_OVERFLOW;
    else if(g->control->status.generation!=generation ||
            (g->control->status.state!=UMC_ARMING &&
             g->control->status.state!=UMC_ARMED &&
             g->control->status.state!=UMC_ACTIVE))result=UMC_STALE;
    else {g->held=1;g->generation=generation;g->epoch++;}
    leave(g,f);return result;
}
int mcs_release_scoped(struct mcs_guard *g)
{
    uint32_t f;int result=UMC_OK;
    if(!ready(g))return UMC_BAD_ARGUMENT;
    f=enter(g);
    if(actor(g)!=g->owner || !normal(g))result=UMC_WRONG_OWNER;
    else if(!g->held)result=UMC_ALREADY;
    else if(g->borrow || g->native_mutation || g->permit_entered ||
            g->output->active_ticket || g->output->installed ||
            g->output->native_calls || g->output->reader_in_flight ||
            g->control->status.media_references ||
            g->control->status.callback_references ||
            g->control->status.state!=UMC_STOPPED)result=UMC_BUSY;
    else {g->held=0;g->selected_session=0;g->selected_instance=UINT32_MAX;
          g->registration_ticket=0;}
    leave(g,f);return result;
}
int mcs_install_queue_callback(struct mcs_guard *g)
{
    uint32_t f,old;int result=UMC_OK;
    if(!ready(g))return UMC_BAD_ARGUMENT;
    f=enter(g);old=word(g->source_record,0x160u);
    if(actor(g)!=g->owner || !normal(g))result=UMC_WRONG_OWNER;
    else if(g->original_queue || old!=(0x277c6au|1u))result=MCS_ALREADY_BOUND;
    else {
        g->original_queue=(mcs_queue_fn)(uintptr_t)old;
        *(volatile uint32_t *)(g->source_record+0x160u)=
            (uint32_t)(uintptr_t)mcs_queue_bridge;
        /* Only this native callback slot was changed; no authority inferred. */
    }
    leave(g,f);return result;
}
int mcs_register_begin(struct mcs_guard *g,uint32_t ticket)
{
    uint32_t f;int result=UMC_OK;
    if(!ready(g) || !ticket)return UMC_BAD_ARGUMENT;
    f=enter(g);
    if(actor(g)!=g->owner || !normal(g))result=UMC_WRONG_OWNER;
    else if(!g->held || g->permit_entered || g->registration_ticket ||
       g->selected_session || g->output->active_ticket || g->output->installed ||
       g->output->native_calls || g->native_mutation || g->borrow ||
       word(g->source_record,0x160u)!=(uint32_t)(uintptr_t)mcs_queue_bridge ||
       g->generation!=g->control->status.generation || !g->control->status.armed ||
       g->slots[ticket&3u].ticket!=ticket || g->slots[ticket&3u].state!=2u)
        result=MCS_REJECTED;
    else {g->permit_ticket=ticket;g->permit_actor=actor(g);
          g->permit_consumed=0;g->permit_entered=1;}
    leave(g,f);return result;
}
int mcs_register_end(struct mcs_guard *g,int original_result)
{
    uint32_t f;int result=original_result;
    if(!ready(g))return UMC_BAD_ARGUMENT;
    f=enter(g);
    if(!g->permit_entered || g->permit_actor!=actor(g))result=UMC_WRONG_OWNER;
    else {
        if(!original_result){
            if(!g->permit_consumed || g->output->native_calls ||
               g->output->active_ticket!=g->permit_ticket)result=MCS_REJECTED;
            else g->registration_ticket=g->permit_ticket;
        }
        g->permit_entered=0;g->permit_actor=0;g->permit_ticket=0;
    }
    leave(g,f);return result;
}
int mcs_queue_dispatch(struct mcs_guard *g,volatile void *list,uint32_t key,
    uint32_t kind,uint32_t flags,const void *params,uint32_t len,const void *metadata)
{
    uint32_t f;int allow;const uint32_t *p=params;mcs_queue_fn original;
    if(!ready(g) || !g->original_queue)return MCS_NATIVE_UNAVAILABLE;
    /* This callback is installed only in channel8's slot. A foreign list
     * cannot masquerade as that slot; other channel slots stay original. */
    f=enter(g);original=g->original_queue;
    allow=list==(volatile void *)(g->source_record+0x1a8u) && g->held &&
       g->permit_entered && !g->permit_consumed && normal(g) &&
       actor(g)==g->owner && actor(g)==g->permit_actor &&
       g->generation==g->control->status.generation && g->control->status.armed &&
       g->output->active_ticket==g->permit_ticket &&
       g->slots[g->permit_ticket&3u].ticket==g->permit_ticket && key==0xffffu &&
       kind==10u && flags==12u && params && len==0x20cu && !metadata;
    if(allow)allow=p[0]==1u && p[1]==16000u && p[2]==16u &&
                   p[3]==g->anchor && p[4]==2u;
    if(allow){g->permit_consumed=1;g->queue_calls++;}
    else g->foreign_rejections++;
    leave(g,f);
    /* Queue/list locks may wait. Never run native code under IRQ exclusion.
     * Complete original result is preserved, including alloc failure5. */
    return allow?original(list,key,kind,flags,params,len,metadata):MCS_NATIVE_UNAVAILABLE;
}
int mcs_queue_bridge(volatile void *list,uint32_t key,uint32_t kind,uint32_t flags,
    const void *p,uint32_t n,const void *metadata)
{ return mcs_queue_dispatch(mcs_bridge_context,list,key,kind,flags,p,n,metadata); }
/* Actual native state is rechecked at every scoped pull/admission. This
 * detects replacement visible in this record; it cannot exclude unredirected
 * independent native writers or a future callback not yet in this scope. */
static int native_binding_matches(struct mcs_guard *g,uint32_t instance)
{
    volatile uint8_t *r=g->source_record,*p;
    if(instance>=5u || word(r,0xf0u)!=instance || !r[2] ||
       word(r,0x10cu)!=0x48ee31u)return 0;
    p=g->pool+instance*576u;
    return p[12] && p[28] && word(p,16)==g->anchor && word(p,20)==2u;
}
static volatile uint8_t *native_mixer(void)
{ return (volatile uint8_t *)(uintptr_t)(0x034e5378u+8u*0x130u); }
static int mixer_descriptor_matches(struct mcs_guard *g)
{
    volatile uint8_t *m=native_mixer();
    if(!g->mixer_tcb || word(m,0x78u)!=g->mixer_tcb ||
       word(m,0x64u)!=0x2fa0ddu || word(m,0x68u)!=g->mixer_queue ||
       word(m,0x6cu)!=g->mixer_stack_end || word(m,0x70u)!=0x0117140cu ||
       word(m,0x74u)!=(uint32_t)(uintptr_t)(m+0x3cu) ||
       word(m,0x2cu)!=g->mixer_stack_base || word(m,0x30u)!=g->mixer_queue)
        return 0;
    return word((volatile uint8_t *)(uintptr_t)g->mixer_tcb,8u)==g->mixer_queue;
}
/* Called under metadata exclusion. A revoked capability cannot be recovered
 * from a matching snapshot: anchor/task/storage remain pinned for cleanup. */
static int mixer_capability_current(struct mcs_guard *g)
{
    if(!g->mixer_session)return 0;
    if(g->mixer_session!=g->epoch || g->mixer_generation!=g->generation ||
       g->generation!=g->control->status.generation ||
       g->mixer_admission_epoch!=g->control->status.admission_epoch ||
       word(g->source_record,0x160u)!=(uint32_t)(uintptr_t)mcs_queue_bridge ||
       !mixer_descriptor_matches(g)){
        g->mixer_session=0;g->mixer_revocations++;return 0;
    }
    return 1;
}
static int actual_mixer_actor(struct mcs_guard *g)
{ return mixer_capability_current(g) && actor(g)==g->mixer_tcb && normal(g); }
int mcs_handoff_source_to_mixer(struct mcs_guard *g)
{
    uint32_t f,tcb,base,top,queue;volatile uint8_t *m;int result=MCS_REJECTED;
    if(!ready(g))return UMC_BAD_ARGUMENT;
    f=enter(g);m=native_mixer();tcb=word(m,0x78u);base=word(m,0x2cu);
    top=word(m,0x6cu);queue=word(m,0x30u);
    if(g->held && actor(g)==g->owner && normal(g) && !g->mixer_tcb &&
       !g->borrow && !g->native_mutation && g->registration_ticket &&
       !g->selected_session && g->generation==g->control->status.generation &&
       umc_admission(g->control,g->generation,UMC_GATE_CONFIG) &&
       tcb && tcb!=g->owner && base && queue && top>base && top-base==8192u &&
       tcb==((top-108u)&~7u) &&
       word(m,0x64u)==0x2fa0ddu && word(m,0x68u)==queue &&
       word(m,0x70u)==0x0117140cu && word(m,0x74u)==(uint32_t)(uintptr_t)(m+0x3cu) &&
       word((volatile uint8_t *)(uintptr_t)tcb,8u)==queue){
        g->mixer_tcb=tcb;g->mixer_stack_base=base;g->mixer_stack_end=top;
        g->mixer_queue=queue;g->mixer_generation=g->generation;
        g->mixer_admission_epoch=g->control->status.admission_epoch;
        g->mixer_session=g->epoch;g->mixer_handoffs++;result=UMC_OK;
    }
    leave(g,f);return result;
}
int mcs_mixer_selector_begin(uint32_t channel,uint32_t entry_lr,struct mcs_event_frame *b)
{
    struct mcs_guard *g=mcs_bridge_context;uint32_t f;int result;
    if(!b)return MCS_REJECTED;
    if(channel!=8u)return UMC_OK;
    if(!ready(g))return MCS_REJECTED;
    f=enter(g);
    if(entry_lr!=0x2fa299u || !actual_mixer_actor(g) || g->borrow ||
       g->native_mutation || g->output->native_calls){leave(g,f);return MCS_REJECTED;}
    result=mcs_event_begin(g,g->generation,UMC_GATE_CONFIG,b);
    if(!result){g->native_mutation=1;g->selector_entries++;}
    leave(g,f);return result;
}
int mcs_mixer_selector_after_original(uint32_t channel,struct mcs_event_frame *b,int original_result)
{
    struct mcs_guard *g=mcs_bridge_context;uint32_t f;int result=MCS_REJECTED;
    (void)original_result;
    if(channel!=8u)return UMC_OK;
    if(!ready(g) || !b || !b->media.held || !b->callback.held)return MCS_REJECTED;
    f=enter(g);
    if(actor(g)==g->mixer_tcb && g->native_mutation){
        g->native_mutation=0;g->selector_returns++;result=UMC_OK;
    }
    leave(g,f);
    if(!result)result=memory_output_bind_selected_session(g->epoch);
    g->last_selector_bind_result=result;
    mcs_event_end(g,b);return result;
}
int mcs_capture_selected(struct mcs_guard *g,uint32_t session)
{
    uint32_t f,index;int result=MCS_REJECTED;
    if(!ready(g) || !session)return UMC_BAD_ARGUMENT;
    f=enter(g);index=word(g->source_record,0xf0u);
    if(g->held && !g->borrow && !g->native_mutation && actual_mixer_actor(g) &&
       session==g->epoch && g->registration_ticket &&
       (!g->selected_session || g->selected_session==session) &&
       g->generation==g->control->status.generation && g->control->status.armed &&
       g->output->active_ticket==g->registration_ticket &&
       !g->output->native_calls && !g->output->reader_in_flight &&
       native_binding_matches(g,index)){
        /* Native session identity is epoch, not the first FIFO ticket. A
         * subsequent producer may recycle that ticket's slot immediately
         * after its unlocked copy has finished, without re-registering. */
        g->selected_session=session;g->selected_instance=index;result=UMC_OK;
    }
    leave(g,f);return result;
}
int mcs_pull_begin(uint32_t channel,struct mcs_borrow_frame *b,uint32_t entry_lr)
{
    struct mcs_guard *g=mcs_bridge_context;uint32_t f;int result;
    if(!b)return MCS_REJECTED;
    /* Assembly supplies new, zero-initialized stack frame. */
    b->channel=channel;
    if(channel!=8u)return UMC_OK; /* untouched native navigation channels */
    if(!ready(g))return MCS_REJECTED;
    f=enter(g);
    if(actual_mixer_actor(g) && g->selected_session &&
       (!native_binding_matches(g,g->selected_instance) ||
        word(g->source_record,0x108u)!=(uint32_t)(uintptr_t)memory_output_read)){
        g->mixer_session=0;g->mixer_revocations++;
    }
    if(!ms_original_sync_completed || !g->held || g->borrow || g->native_mutation || !actual_mixer_actor(g) ||
       (entry_lr!=0x2fa577u && entry_lr!=0x2fa53bu) ||
       !g->selected_session || g->selected_session!=g->epoch ||
       !g->registration_ticket || !g->output->installed ||
       g->output->active_ticket!=g->registration_ticket || g->output->native_calls ||
       !native_binding_matches(g,g->selected_instance) ||
       word(g->source_record,0x108u)!=(uint32_t)(uintptr_t)memory_output_read){
        g->pull_rejections++;leave(g,f);return MCS_REJECTED;
    }
    g->pull_entry_lr=entry_lr;
    b->actor=actor(g);b->generation=g->generation;b->epoch=g->epoch;
    b->session=g->selected_session;b->instance=g->selected_instance;
    /* Publish frame while IRQ excluded, before native descriptor/index load.
     * Core exclusion uses the same reentrant original IRQ save/restore. */
    result=umc_media_acquire(g->control,b->generation,&b->media);
    if(!result)result=umc_callback_acquire(g->control,&b->callback);
    if(result){if(b->media.held)(void)umc_media_release(g->control,&b->media);
        g->pull_rejections++;leave(g,f);return result;}
    g->borrow=b;b->entered=1;g->pulls++;leave(g,f);return UMC_OK;
}
void mcs_pull_end(struct mcs_borrow_frame *b,int original_result)
{
    struct mcs_guard *g=mcs_bridge_context;uint32_t f;
    (void)original_result;
    if(!b || b->channel!=8u || !ready(g))return;
    f=enter(g);
    if(g->borrow!=b || !b->entered || actor(g)!=b->actor){leave(g,f);return;}
    /* Full-return caller alone records this. No cancellation/STOP_DONE flag. */
    b->original_returned=1;g->borrow=0;g->pull_entry_lr=0;g->full_returns++;leave(g,f);
    (void)umc_media_release(g->control,&b->media);
    (void)umc_callback_release(g->control,&b->callback);
}
int mcs_reader_admit(struct mcs_guard *g,uint32_t instance)
{
    uint32_t f;struct mcs_borrow_frame *b;int allow;
    if(!ready(g))return 0;
    f=enter(g);b=g->borrow;
    if(actual_mixer_actor(g) && g->selected_session &&
       (!native_binding_matches(g,g->selected_instance) ||
        word(g->source_record,0x108u)!=(uint32_t)(uintptr_t)memory_output_read)){
        g->mixer_session=0;g->mixer_revocations++;
    }
    allow=b && b->entered && !b->original_returned && b->actor==actor(g) &&
       actual_mixer_actor(g) &&
       (g->pull_entry_lr==0x2fa577u || g->pull_entry_lr==0x2fa53bu) &&
       b->epoch==g->epoch && b->generation==g->generation &&
       b->session==g->selected_session && b->session==g->epoch &&
       g->registration_ticket && g->output->installed &&
       g->output->active_ticket==g->registration_ticket &&
       b->instance==instance && instance==g->selected_instance &&
       native_binding_matches(g,instance) &&
       word(g->source_record,0x108u)==(uint32_t)(uintptr_t)memory_output_read &&
       umc_media_current(g->control,&b->media);
    leave(g,f);return allow;
}
int mcs_mutation_begin(struct mcs_guard *g)
{
    uint32_t f;int result=UMC_OK;
    if(!ready(g))return UMC_BAD_ARGUMENT;
    f=enter(g);
    if(actor(g)!=g->owner || !normal(g))result=UMC_WRONG_OWNER;
    else if(!g->held)result=MCS_REJECTED;
    else if(g->borrow || g->native_mutation)result=UMC_PENDING;
    else g->native_mutation=1;
    leave(g,f);return result;
}
void mcs_mutation_end(struct mcs_guard *g)
{
    uint32_t f;
    if(!ready(g))return;
    f=enter(g);if(actor(g)==g->owner)g->native_mutation=0;leave(g,f);
}
int mcs_event_begin(struct mcs_guard *g,uint32_t generation,uint32_t gate,
                     struct mcs_event_frame *b)
{
    uint32_t f;int result;
    if(!ready(g) || !b)return UMC_BAD_ARGUMENT;
    f=enter(g);
    if(!g->held || g->generation!=generation || !normal(g) ||
       !umc_admission(g->control,generation,gate)){leave(g,f);return MCS_REJECTED;}
    result=umc_media_acquire(g->control,generation,&b->media);
    if(!result)result=umc_callback_acquire(g->control,&b->callback);
    if(result && b->media.held)(void)umc_media_release(g->control,&b->media);
    if(!result){b->generation=generation;b->gate=gate;}
    leave(g,f);return result;
}
void mcs_event_end(struct mcs_guard *g,struct mcs_event_frame *b)
{
    if(!ready(g) || !b)return;
    if(b->media.held)(void)umc_media_release(g->control,&b->media);
    if(b->callback.held)(void)umc_callback_release(g->control,&b->callback);
}
int mcs_native_ownership_snapshot(void *p,uint32_t generation,uint32_t token,
                                 struct umcn_ownership_witness *w)
{
    (void)p;(void)generation;(void)token;(void)w;
    /* 277C6A direct/indirect bypass, provider allocation48EE68 and outer pull
     * caller redirection have not been closed. Leave witness UNTOUCHED. */
    return MCS_UNCERTIFIED;
}
