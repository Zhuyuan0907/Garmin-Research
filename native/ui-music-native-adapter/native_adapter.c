#include "native_adapter.h"

struct umcn_context *umcn_cleanup_bridge_context;
static int valid(const struct umcn_context *a)
{ return a && a->magic==UMCN_MAGIC; }
static void zero_bytes(void *p,uint32_t n)
{ volatile uint8_t *b=p; while(n--) *b++=0; }
static void copy_bytes(void *to,const void *from,uint32_t n)
{ volatile uint8_t *d=to; const uint8_t *s=from; while(n--) *d++=*s++; }
static uint16_t half(const volatile uint8_t *p,uint32_t offset)
{ return (uint16_t)((uint16_t)p[offset]|(uint16_t)p[offset+1]<<8); }
static uint32_t word(const volatile uint8_t *p,uint32_t offset)
{ return (uint32_t)p[offset]|(uint32_t)p[offset+1]<<8|(uint32_t)p[offset+2]<<16|(uint32_t)p[offset+3]<<24; }
static uint32_t lock(struct umcn_context *a)
{ return a->native.irq_save(a->native.integration_context); }
static void unlock(struct umcn_context *a,uint32_t key)
{ a->native.irq_restore(a->native.integration_context,key); }
static uint32_t current(struct umcn_context *a)
{ return a->native.current_task(a->native.integration_context); }
static int runtime_ready(struct umcn_context *a)
{
    volatile struct umcn_runtime_view *r=a->native.runtime;
    volatile struct umcn_source_view *s=a->native.source;
    volatile struct umcn_worker_view *d=a->native.decoder;
    return r->initialized && r->channel==8u && r->source_tcb==s->tcb &&
        r->decoder_tcb==d->tcb && r->source_init_done && !r->source_init_result &&
        r->source_init_owner==s->tcb && s->tcb && s->entered && !s->init_result &&
        !s->quit_requested && !s->finished_on_stack && d->tcb && d->entered &&
        !d->quit_requested && !d->finished_on_stack && a->native.coordinator->initialized &&
        a->native.coordinator->owner_tcb==s->tcb && a->native.output->initialized &&
        a->native.output->channel==8u;
}
static int witnessed(struct umcn_context *a,uint32_t generation,uint32_t token,
                       struct umcn_ownership_witness *out)
{
    zero_bytes(out,sizeof(*out));
    if(!a->native.ownership_snapshot) return UMCN_BINDING_MISSING;
    if(a->native.ownership_snapshot(a->native.integration_context,generation,token,out))
        return UMCN_OWNER_MISMATCH;
    if(out->generation!=generation || out->cookie!=a->cookie || out->channel!=8u ||
        out->owner_tcb!=a->native.source->tcb || out->source_token!=token || !out->epoch ||
        !out->native_writers_excluded || !out->future_borrowing_callbacks_excluded)
        return UMCN_OWNER_MISMATCH;
    return UMCN_OK;
}
static uint32_t adapter_enter(void *opaque) { return lock(opaque); }
static void adapter_leave(void *opaque,uint32_t key) { unlock(opaque,key); }
static uint32_t adapter_current(void *opaque) { return current(opaque); }
static int adapter_wake(void *opaque,uint32_t tcb,uint32_t event)
{
    struct umcn_context *a=opaque; uint32_t key;
    if(tcb!=a->native.source->tcb || !tcb || a->native.source->finished_on_stack)
        return UMCN_OWNER_MISMATCH;
    key=lock(a); a->native.source->pending|=event; unlock(a,key);
    a->native.native_post(a->native.integration_context,tcb,event);
    /* Original post has no status return;0 means routine returned only. */
    return UMCN_OK;
}
static int adapter_prepare(void *opaque,uint32_t route,uint32_t generation,uint32_t cookie)
{
    struct umcn_context *a=opaque;
    struct umcn_ownership_witness first,last;
    uint32_t key; int ready,result;
    if(route!=8u || cookie!=a->cookie || current(a)!=a->native.source->tcb)
        return UMCN_OWNER_MISMATCH;
    if(!a->native.prepare_session) return UMCN_BINDING_MISSING;
    result=witnessed(a,generation,0,&first); if(result) return result;
    key=lock(a); ready=runtime_ready(a) && !a->native.coordinator->busy &&
        !a->native.coordinator->ticket && !a->native.coordinator->cancel_pending &&
        !a->native.output->active_ticket && !a->native.output->native_calls &&
        !a->native.output->reader_in_flight && !a->native.owned->busy &&
        !a->native.owned->count && !a->native.queue->producer_busy &&
        !a->native.queue->worker_busy && !a->native.queue->count;
    unlock(a,key); if(!ready) return UMCN_NATIVE_BUSY;
    result=a->native.prepare_session(a->native.integration_context,generation,first.epoch);
    if(result) return result;
    result=witnessed(a,generation,0,&last); if(result) return result;
    if(first.epoch!=last.epoch) return UMCN_OWNER_MISMATCH;
    key=lock(a);
    a->trace.generation=generation; a->trace.source_token=0;
    a->trace.ownership_epoch=last.epoch; a->trace.original_cleanup_returned=0;
    a->trace.cancel_generation=a->trace.owner_cancel_iteration_returned=0;
    unlock(a,key);
    return UMCN_OK;
}
static int adapter_cancel(void *opaque,uint32_t route,uint32_t generation,uint32_t cookie)
{
    struct umcn_context *a=opaque; struct umcn_ownership_witness w;
    uint32_t key,token; int result;
    if(route!=8u || cookie!=a->cookie || current(a)!=a->native.source->tcb)
        return UMCN_OWNER_MISMATCH;
    key=lock(a); token=a->trace.source_token; unlock(a,key);
    result=witnessed(a,generation,token,&w); if(result) return result;
    key=lock(a);
    a->trace.cancel_generation=generation;
    a->trace.cancel_count_baseline=a->native.coordinator->cancelled;
    a->trace.pump_baseline=a->native.source->pump_calls;
    a->trace.owner_cancel_iteration_returned=0;
    if(!a->trace.ownership_epoch) a->trace.ownership_epoch=w.epoch;
    unlock(a,key);
    return a->native.runtime_cancel(a->native.integration_context);
}
static int adapter_observe(void *opaque,uint32_t route,uint32_t generation,uint32_t cookie,
                             struct umc_stop_evidence *e)
{
    struct umcn_context *a=opaque; struct umcn_ownership_witness first,last;
    uint32_t key,token,i,pool_busy=0,slot_busy=0,cancel_returned,remove_returned,release_returned;
    int result;
    zero_bytes(e,sizeof(*e));
    if(route!=8u || cookie!=a->cookie || current(a)!=a->native.source->tcb)
        return UMCN_OWNER_MISMATCH;
    key=lock(a); token=a->trace.source_token; unlock(a,key);
    result=witnessed(a,generation,token,&first); if(result) return result;
    key=lock(a);
    e->generation=generation; e->ownership_cookie=cookie; e->route=8;
    e->source_was_published=token!=0; e->source_token=token;
    e->node_count=half(a->native.source_record,0x1c0u);
    for(i=0;i<68u;i++) if(a->native.source_record[0xf4u+i]) e->methods_live=1;
    for(i=0;i<5u;i++) {
        volatile uint8_t *p=a->native.provider_pool+i*576u;
        if(word(p,16)==a->native.anchor_address && (p[12] || p[28])) pool_busy=1;
    }
    for(i=0;i<4u;i++) if(a->native.slots[i].state || a->native.slots[i].in_flight) slot_busy=1;
    e->provider_active=pool_busy;
    e->mixer_active=a->native.mixer_record[0x84u];
    e->driver_active=half(a->native.driver_record,0);
    e->native_calls=a->native.output->native_calls;
    e->reader_in_flight=a->native.output->reader_in_flight;
    e->native_idle=!a->native.source_record[2] && !e->methods_live && !pool_busy &&
        !e->mixer_active && !e->driver_active && *a->native.source_state==1u;
    e->coordinator_busy=a->native.coordinator->busy;
    e->coordinator_ticket=a->native.coordinator->ticket;
    e->coordinator_cancel_pending=a->native.coordinator->cancel_pending;
    e->anchor_live=a->native.output->active_ticket || a->native.output->installed;
    e->owned_busy=a->native.owned->busy || slot_busy;
    e->owned_count=a->native.owned->count;
    e->queue_producer_busy=a->native.queue->producer_busy;
    e->queue_consumer_busy=a->native.queue->worker_busy;
    e->queue_pending=a->native.queue->count || a->native.queue->running;
    cancel_returned=a->trace.cancel_generation==generation &&
        a->trace.owner_cancel_iteration_returned==generation &&
        a->native.coordinator->cancelled>a->trace.cancel_count_baseline &&
        a->native.source->pump_calls>a->trace.pump_baseline &&
        !a->native.source->cancel_requested && !a->native.coordinator->busy;
    remove_returned=token && a->trace.original_cleanup_returned &&
        a->native.coordinator->remove_calls>a->trace.source_remove_baseline;
    release_returned=token && a->trace.original_cleanup_returned &&
        a->native.output->releases>a->trace.source_release_baseline;
    e->cancel_pipeline_returned=cancel_returned;
    e->node_removal_returned=remove_returned && !e->node_count;
    e->anchor_release_returned=release_returned && !e->anchor_live && !pool_busy;
    /* Exact cancel_step increments cancelled only AFTER FIFO function returns.
     * after_native_iteration additionally observes the source owner's full
     * return/cleared flag. Empty FIFO count alone does not grant this witness. */
    e->fifo_discard_returned=cancel_returned && !e->owned_busy && !e->owned_count;
    e->never_published_barrier=!token && cancel_returned;
    unlock(a,key);
    result=witnessed(a,generation,token,&last); if(result) return result;
    if(first.epoch!=last.epoch || last.epoch!=a->trace.ownership_epoch)
        return UMCN_OWNER_MISMATCH;
    e->ownership_confirmed=1;
    return UMCN_OK;
}

int umcn_init(struct umcn_context *a,struct umc_controller *control,const struct umcn_bindings *b,
              const struct umcn_control_functions *core,uint32_t cookie)
{
    struct umc_config cfg; struct umc_adapters ops;
    if(!a || !control || !b || !core || !cookie) return UMCN_BINDING_MISSING;
    if(a->magic) return UMCN_PINNED;
    if(b->channel!=8u) return UMCN_UNSUPPORTED_ROUTE;
    if(!b->resident_storage_confirmed || !b->irq_save || !b->irq_restore || !b->current_task ||
        !b->native_post || !b->runtime_cancel || !b->original_source_completed ||
        !b->ownership_snapshot || !b->prepare_session || !b->runtime || !b->source ||
        !b->coordinator || !b->output || !b->owned || !b->queue || !b->decoder || !b->slots ||
        !b->source_record || !b->mixer_record || !b->driver_record || !b->source_state ||
        !b->provider_pool || !b->anchor_address || !core->init || !core->ready || !core->service ||
        !core->status || !core->gate || !core->started || !core->cleaned ||
        !core->callback_acquire || !core->callback_release || !core->kick)
        return UMCN_BINDING_MISSING;
    zero_bytes(a,sizeof(*a)); copy_bytes(&a->native,b,sizeof(*b));
    copy_bytes(&a->core,core,sizeof(*core)); a->control=control; a->cookie=cookie;
    cfg.source_tcb=b->source->tcb; cfg.route=8; cfg.ownership_cookie=cookie;
    cfg.resident_storage_confirmed=1;
    ops.context=a; ops.metadata_enter=adapter_enter; ops.metadata_leave=adapter_leave;
    ops.current_actor=adapter_current; ops.wake_source=adapter_wake;
    ops.prepare_start=adapter_prepare; ops.request_cancel=adapter_cancel; ops.observe_stop=adapter_observe;
    if(a->core.init(control,&cfg,&ops)) return UMCN_BINDING_MISSING;
    a->magic=UMCN_MAGIC; return UMCN_OK;
}
int umcn_owner_ready(struct umcn_context *a)
{
    uint32_t key; int ready;
    if(!valid(a)) return UMCN_BINDING_MISSING;
    if(current(a)!=a->native.source->tcb) return UMCN_OWNER_MISMATCH;
    key=lock(a); ready=runtime_ready(a); unlock(a,key);
    return ready?a->core.ready(a->control):UMCN_NATIVE_BUSY;
}
int umcn_service_owner(struct umcn_context *a)
{ return valid(a)?a->core.service(a->control):UMCN_BINDING_MISSING; }
int umcn_admission(struct umcn_context *a,uint32_t generation,uint32_t gate)
{ return valid(a)?a->core.gate(a->control,generation,gate):0; }

int umcn_note_owned_publication(struct umcn_context *a)
{
    struct umc_status status; struct umcn_ownership_witness w;
    uint32_t key,token; int result;
    if(!valid(a)) return UMCN_BINDING_MISSING;
    if(current(a)!=a->native.source->tcb) return UMCN_OWNER_MISMATCH;
    if(a->core.status(a->control,&status)) return UMCN_STALE;
    key=lock(a); token=a->native.coordinator->ticket;
    if(!token || token!=a->native.output->active_ticket ||
        a->native.slots[token&3u].ticket!=token || !a->native.slots[token&3u].state ||
        a->native.output->native_calls || half(a->native.source_record,0x1c0u)!=1u) {
        unlock(a,key); return UMCN_STALE;
    }
    unlock(a,key);
    if(!status.generation || (status.source_seen && status.source_token!=token && !status.cleanup_seen))
        return UMCN_NATIVE_BUSY;
    result=witnessed(a,status.generation,token,&w); if(result) return result;
    key=lock(a);
    if(a->trace.source_token==token) { unlock(a,key); return UMC_ALREADY; }
    a->trace.generation=status.generation; a->trace.source_token=token;
    a->trace.ownership_epoch=w.epoch; a->trace.original_cleanup_returned=0;
    a->trace.source_remove_baseline=a->native.coordinator->remove_calls;
    a->trace.source_release_baseline=a->native.output->releases;
    unlock(a,key);
    return a->core.started(a->control,8,status.generation,a->cookie,token);
}
int umcn_after_native_iteration(struct umcn_context *a,int result)
{
    uint32_t key,returned;
    if(!valid(a)) return UMCN_BINDING_MISSING;
    if(current(a)!=a->native.source->tcb) return UMCN_OWNER_MISMATCH;
    key=lock(a);
    returned=!result && !a->native.source->last_result && !a->native.source->cancel_requested &&
        !a->native.coordinator->cancel_pending && !a->native.coordinator->busy &&
        !a->native.coordinator->ticket && !a->native.coordinator->last_result &&
        a->native.source->pump_calls>a->trace.pump_baseline &&
        a->native.coordinator->cancelled>a->trace.cancel_count_baseline && a->trace.cancel_generation;
    if(returned) a->trace.owner_cancel_iteration_returned=a->trace.cancel_generation;
    unlock(a,key);
    if(returned) return a->core.kick(a->control);
    return UMCN_NATIVE_BUSY;
}
int umcn_cleanup_begin(struct umcn_context *a,const volatile void *record,
                        struct umcn_cleanup_frame *frame,uint32_t entry_lr)
{
    uint32_t key; int result;
    if(!frame) return UMCN_BINDING_MISSING;
    zero_bytes(frame,sizeof(*frame)); frame->capture_result=UMCN_STALE;
    frame->entry_address=0x3b9dfcu; frame->entry_lr=entry_lr;
    if(!valid(a) || record!=(const volatile void *)a->native.source_record) return UMCN_STALE;
    result=a->core.callback_acquire(a->control,&frame->callback); if(result) return result;
    key=lock(a); frame->generation=a->trace.generation; frame->cookie=a->cookie;
    frame->source_token=a->trace.source_token; frame->route=8;
    frame->record_address=(uint32_t)(uintptr_t)record;
    result=frame->generation && frame->source_token?UMCN_OK:UMCN_STALE;
    frame->capture_result=result; unlock(a,key);
    return result;
}
int umcn_cleanup_after_original(struct umcn_context *a,struct umcn_cleanup_frame *frame,
                                 const volatile void *record,int original_result)
{
    uint32_t key; int result=UMCN_STALE;
    (void)original_result; /* Preserved by assembly, not a completion predicate. */
    if(!valid(a) || !frame) return UMCN_BINDING_MISSING;
    if(frame->original_returned) return UMCN_STALE;
    frame->original_returned=1;
    if(frame->capture_result==UMCN_OK && record==(const volatile void *)a->native.source_record &&
        frame->record_address==(uint32_t)(uintptr_t)record) {
        key=lock(a);
        if(frame->generation==a->trace.generation && frame->source_token==a->trace.source_token &&
            frame->cookie==a->cookie) a->trace.original_cleanup_returned=1;
        unlock(a,key);
        result=a->core.cleaned(a->control,frame->route,frame->generation,frame->cookie,frame->source_token);
    }
    /* Preserve the old completion/filter/post for every record, even foreign.
     * A high priority source may run here; frame reference is still held. */
    a->native.original_source_completed(a->native.integration_context,record);
    if(frame->callback.held) (void)a->core.callback_release(a->control,&frame->callback);
    return result;
}
int umcn_set_cleanup_bridge(struct umcn_context *a)
{
    if(!valid(a)) return UMCN_BINDING_MISSING;
    if(umcn_cleanup_bridge_context) return UMCN_PINNED;
    umcn_cleanup_bridge_context=a; return UMCN_OK;
}
