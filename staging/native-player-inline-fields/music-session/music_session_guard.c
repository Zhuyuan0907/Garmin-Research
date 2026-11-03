#include "music_session_guard.h"
struct mcs_guard *mcs_bridge_context;
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
    else if(g->borrow || g->native_mutation || g->permit_entered || g->control->status.media_references ||
            g->control->status.callback_references ||
            g->control->status.state!=UMC_STOPPED)result=UMC_BUSY;
    else {g->held=0;g->selected_ticket=0;g->selected_instance=UINT32_MAX;}
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
    else if(!g->held || g->permit_entered ||
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
    else {g->permit_entered=0;g->permit_actor=0;g->permit_ticket=0;}
    leave(g,f);return result;
}
int mcs_queue_dispatch(struct mcs_guard *g,volatile void *list,uint32_t kind,
    uint32_t flags,const void *params,uint32_t len,const void *metadata,uint32_t last)
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
       g->slots[g->permit_ticket&3u].ticket==g->permit_ticket && kind==10u &&
       flags==12u && params && len==0x20cu && !metadata && last==1u;
    if(allow)allow=p[0]==1u && p[1]==16000u && p[2]==16u &&
                   p[3]==g->anchor && p[4]==2u;
    if(allow){g->permit_consumed=1;g->queue_calls++;}
    else g->foreign_rejections++;
    leave(g,f);
    /* Queue/list locks may wait. Never run native code under IRQ exclusion.
     * Complete original result is preserved, including alloc failure5. */
    return allow?original(list,kind,flags,params,len,metadata,last):MCS_NATIVE_UNAVAILABLE;
}
int mcs_queue_bridge(volatile void *list,uint32_t kind,uint32_t flags,
    const void *p,uint32_t n,const void *metadata,uint32_t last)
{ return mcs_queue_dispatch(mcs_bridge_context,list,kind,flags,p,n,metadata,last); }
int mcs_capture_selected(struct mcs_guard *g,uint32_t ticket)
{
    uint32_t f,index;volatile uint8_t *p;int result=MCS_REJECTED;
    if(!ready(g) || !ticket)return UMC_BAD_ARGUMENT;
    f=enter(g);index=word(g->source_record,0xf0u);
    if(g->held && !g->borrow && actor(g)==g->owner && normal(g) &&
       g->generation==g->control->status.generation && g->control->status.armed &&
       ticket==g->output->active_ticket &&
       g->slots[ticket&3u].ticket==ticket && !g->output->native_calls &&
       g->source_record[2] && index<5u && word(g->source_record,0x10cu)==0x48ee31u){
        p=g->pool+index*576u;
        if(p[12] && p[28] && word(p,16)==g->anchor && word(p,20)==2u){
            g->selected_ticket=ticket;g->selected_instance=index;result=UMC_OK;
        }
    }
    leave(g,f);return result;
}
int mcs_pull_begin(uint32_t channel,struct mcs_borrow_frame *b)
{
    struct mcs_guard *g=mcs_bridge_context;uint32_t f;int result;
    if(!b)return MCS_REJECTED;
    /* Assembly supplies new, zero-initialized stack frame. */
    b->channel=channel;
    if(channel!=8u)return UMC_OK; /* untouched native navigation channels */
    if(!ready(g))return MCS_REJECTED;
    f=enter(g);
    if(!g->held || g->borrow || g->native_mutation || !normal(g) || !actor(g) ||
       !g->selected_ticket || g->output->active_ticket!=g->selected_ticket ||
       g->slots[g->selected_ticket&3u].ticket!=g->selected_ticket){
        g->pull_rejections++;leave(g,f);return MCS_REJECTED;
    }
    b->actor=actor(g);b->generation=g->generation;b->epoch=g->epoch;
    b->ticket=g->selected_ticket;b->instance=g->selected_instance;
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
    b->original_returned=1;g->borrow=0;g->full_returns++;leave(g,f);
    (void)umc_media_release(g->control,&b->media);
    (void)umc_callback_release(g->control,&b->callback);
}
int mcs_reader_admit(struct mcs_guard *g,uint32_t instance)
{
    uint32_t f;struct mcs_borrow_frame *b;int allow;
    if(!ready(g))return 0;
    f=enter(g);b=g->borrow;
    allow=b && b->entered && !b->original_returned && b->actor==actor(g) &&
       normal(g) && b->epoch==g->epoch && b->generation==g->generation &&
       b->ticket==g->selected_ticket && b->ticket==g->output->active_ticket &&
       b->instance==instance && instance==g->selected_instance &&
       g->slots[b->ticket&3u].ticket==b->ticket &&
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
