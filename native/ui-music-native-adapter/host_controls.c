/* Host execution of the REAL adapter's byte/ABI observations against supplied
 * RAM fixtures. Original-address imports and ARM cleanup bridge are not run.
 */
#include "native_adapter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"FAIL:%d:%s\n",__LINE__,#x);exit(1); } } while(0)
#define TCB 0x8801000u
#define COOKIE 0x13528011u
#define TOKEN 0x1411u
#define ANCHOR 0x02f91124u
struct fixture {
    struct umcn_context adapter; struct umc_controller controller;
    struct umcn_runtime_view runtime; struct umcn_source_view source;
    struct umcn_coordinator_view coordinator; struct umcn_output_view output;
    struct umcn_owned_view owned; struct umcn_queue_view queue; struct umcn_worker_view decoder;
    struct umcn_slot_view slots[4];
    uint8_t record[520],mixer[304],driver[84],pool[5*576],state;
    uint32_t current,depth,key,epoch,witness_calls,posts,cancel_calls,forwarded;
    int witness_bad,witness_epoch_changes,forward_preempts,prepare_missing_runtime;
};
static uint32_t save(void *p)
{ struct fixture *f=p;CHECK(!f->depth);f->depth=1;return ++f->key; }
static void restore(void *p,uint32_t key)
{ struct fixture *f=p;CHECK(f->depth==1 && key==f->key);f->depth=0; }
static uint32_t current(void *p)
{ struct fixture *f=p;CHECK(!f->depth);return f->current; }
static void post(void *p,uint32_t tcb,uint32_t event)
{ struct fixture *f=p;CHECK(!f->depth && tcb==TCB && (f->source.pending & event)==event);f->posts++; }
static int witness(void *p,uint32_t generation,uint32_t token,struct umcn_ownership_witness *out)
{
    struct fixture *f=p;CHECK(!f->depth);f->witness_calls++;
    memset(out,0,sizeof(*out));out->generation=generation;out->cookie=COOKIE;
    out->channel=8;out->owner_tcb=TCB;out->source_token=token;out->epoch=f->epoch;
    out->native_writers_excluded=1;out->future_borrowing_callbacks_excluded=(uint32_t)!f->witness_bad;
    if(f->witness_epoch_changes && !(f->witness_calls&1u)) out->epoch++;
    return 0;
}
static int session(void *p,uint32_t generation,uint32_t epoch)
{
    struct fixture *f=p;CHECK(!f->depth && generation && epoch==f->epoch);
    return f->prepare_missing_runtime?UMCN_NATIVE_BUSY:0;
}
static int cancel(void *p)
{
    struct fixture *f=p;CHECK(!f->depth && f->current==TCB);
    f->cancel_calls++; f->source.cancel_requested=1;f->coordinator.cancel_pending=1;
    f->queue.running=0; return 0;
}
static void completed(void *p,const volatile void *record)
{
    struct fixture *f=p;uint32_t old=f->current;
    CHECK(!f->depth && record);f->forwarded++;
    if(record==(const volatile void *)f->record) {
        f->source.completions++;f->source.pending|=0x20000u;
        post(f,TCB,0x20000u);
    }
    if(f->forward_preempts) {
        f->current=TCB;
        CHECK(umcn_service_owner(&f->adapter)==UMC_PENDING);
        CHECK(f->controller.status.callback_references==1);
        f->current=old;
    }
}
static const struct umcn_control_functions core={
    umc_init,umc_runtime_ready,umc_service,umc_status_read,umc_admission,
    umc_source_started,umc_cleanup_returned,umc_callback_acquire,umc_callback_release,umc_kick
};
static struct umcn_bindings bindings(struct fixture *f)
{
    struct umcn_bindings b;
    memset(&b,0,sizeof(b));b.integration_context=f;b.irq_save=save;b.irq_restore=restore;
    b.current_task=current;b.native_post=post;b.runtime_cancel=cancel;b.original_source_completed=completed;
    b.ownership_snapshot=witness;b.prepare_session=session;b.runtime=&f->runtime;b.source=&f->source;
    b.coordinator=&f->coordinator;b.output=&f->output;b.owned=&f->owned;b.queue=&f->queue;
    b.decoder=&f->decoder;b.slots=f->slots;b.source_record=f->record;b.mixer_record=f->mixer;
    b.driver_record=f->driver;b.source_state=&f->state;b.provider_pool=f->pool;
    b.anchor_address=ANCHOR;b.channel=8;b.resident_storage_confirmed=1;return b;
}
static void raw_init(struct fixture *f)
{
    memset(f,0,sizeof(*f));f->current=TCB;f->epoch=7;f->state=1;
    f->runtime.initialized=1;f->runtime.channel=8;f->runtime.decoder_tcb=TCB+0x1000;
    f->runtime.source_tcb=TCB;f->runtime.source_init_done=1;f->runtime.source_init_owner=TCB;
    f->source.tcb=TCB;f->source.entered=1;f->decoder.tcb=TCB+0x1000;f->decoder.entered=1;
    f->coordinator.initialized=1;f->coordinator.owner_tcb=TCB;
    f->output.initialized=1;f->output.channel=8;f->owned.initialized=1;
}
static void init(struct fixture *f)
{
    struct umcn_bindings b;raw_init(f);b=bindings(f);
    CHECK(umcn_init(&f->adapter,&f->controller,&b,&core,COOKIE)==0);
    CHECK(umcn_owner_ready(&f->adapter)==0);
}
static uint32_t start(struct fixture *f)
{
    uint32_t generation;
    CHECK(umc_request_start(&f->controller,&generation)==UMC_PENDING);
    CHECK(umcn_service_owner(&f->adapter)==UMC_OK);return generation;
}
static void put_half(uint8_t *p,uint32_t offset,uint16_t value)
{ p[offset]=(uint8_t)value;p[offset+1]=(uint8_t)(value>>8); }
static void put_word(uint8_t *p,uint32_t offset,uint32_t value)
{ unsigned i;for(i=0;i<4;i++) p[offset+i]=(uint8_t)(value>>(8*i)); }
static void published(struct fixture *f,uint32_t token)
{
    f->coordinator.ticket=f->output.active_ticket=token;
    f->slots[token&3u].ticket=token;f->slots[token&3u].state=2;
    put_half(f->record,0x1c0,1);
    CHECK(umcn_note_owned_publication(&f->adapter)==0);
    f->output.installed=1;f->record[2]=1;f->record[0xf4]=1;
    f->mixer[0x84]=1;put_half(f->driver,0,1);f->state=3;
}
static void stop(struct fixture *f)
{
    uint32_t generation;
    CHECK(umc_request_stop(&f->controller,&generation)==UMC_PENDING);
    CHECK(umcn_service_owner(&f->adapter)==UMC_PENDING);
}
/* Fixtures advance actual bound ABI counters/bytes; no evidence struct is
 * handed directly to control core. These are mocked original native returns,
 * not a claim that firmware was executed on this host. */
static void native_cancel_return(struct fixture *f,int published_source)
{
    f->source.pump_calls++;f->source.last_result=0;f->source.cancel_requested=0;
    f->coordinator.cancelled++;f->coordinator.last_result=0;
    f->coordinator.busy=f->coordinator.ticket=f->coordinator.cancel_pending=0;
    f->output.active_ticket=f->output.installed=0;
    if(published_source) {f->coordinator.remove_calls++;f->output.releases++;}
    memset(f->record,0,sizeof(f->record));memset(f->mixer,0,sizeof(f->mixer));
    memset(f->driver,0,sizeof(f->driver));memset(f->slots,0,sizeof(f->slots));f->state=1;
    f->owned.busy=f->owned.count=f->queue.running=f->queue.count=0;
}
static void cleanup(struct fixture *f)
{
    struct umcn_cleanup_frame frame;uint32_t old=f->current;
    f->current=TCB+0x3000;
    CHECK(umcn_cleanup_begin(&f->adapter,f->record,&frame,0x3b9981u)==0);
    CHECK(frame.entry_address==0x3b9dfc && frame.entry_lr==0x3b9981u && !frame.original_returned);
    CHECK(umcn_cleanup_after_original(&f->adapter,&frame,f->record,0x42)==0);
    CHECK(frame.original_returned && !frame.callback.held);f->current=old;
}
static void finish(struct fixture *f)
{
    CHECK(umcn_after_native_iteration(&f->adapter,0)==0);
    CHECK(umcn_service_owner(&f->adapter)==UMC_OK);
    CHECK(f->controller.status.stop_completed_generation==f->controller.status.generation);
}
static void missing_and_unsupported_bindings_fail_closed(void)
{
    struct fixture f;struct umcn_bindings b;
    raw_init(&f);b=bindings(&f);b.ownership_snapshot=0;
    CHECK(umcn_init(&f.adapter,&f.controller,&b,&core,COOKIE)==UMCN_BINDING_MISSING && !f.adapter.magic && !f.controller.magic);
    b=bindings(&f);b.prepare_session=0;CHECK(umcn_init(&f.adapter,&f.controller,&b,&core,COOKIE)==UMCN_BINDING_MISSING);
    b=bindings(&f);b.channel=9;CHECK(umcn_init(&f.adapter,&f.controller,&b,&core,COOKIE)==UMCN_UNSUPPORTED_ROUTE);
}
static void full_initializer_owner_is_required(void)
{
    struct fixture f;struct umcn_bindings b;
    raw_init(&f);b=bindings(&f);CHECK(umcn_init(&f.adapter,&f.controller,&b,&core,COOKIE)==0);
    f.runtime.source_init_done=0;CHECK(umcn_owner_ready(&f.adapter)==UMCN_NATIVE_BUSY);
    f.runtime.source_init_done=1;f.runtime.source_init_owner=TCB+4;CHECK(umcn_owner_ready(&f.adapter)==UMCN_NATIVE_BUSY);
    f.runtime.source_init_owner=TCB;f.current=TCB+4;CHECK(umcn_owner_ready(&f.adapter)==UMCN_OWNER_MISMATCH);
    f.current=TCB;CHECK(umcn_owner_ready(&f.adapter)==0);
}
static void native_ownership_and_epoch_race_reject_arm(void)
{
    struct fixture f;uint32_t g;
    init(&f);f.witness_bad=1;CHECK(umc_request_start(&f.controller,&g)==UMC_PENDING);
    CHECK(umcn_service_owner(&f.adapter)==UMC_ADAPTER_FAILED && !f.controller.status.armed);
    init(&f);f.witness_epoch_changes=1;CHECK(umc_request_start(&f.controller,&g)==UMC_PENDING);
    CHECK(umcn_service_owner(&f.adapter)==UMC_ADAPTER_FAILED && !f.controller.status.armed);
}
static void actual_native_token_not_supplied_sample_handle(void)
{
    struct fixture f;
    init(&f);start(&f);f.coordinator.ticket=TOKEN;f.output.active_ticket=TOKEN+1;
    f.slots[TOKEN&3].ticket=TOKEN;f.slots[TOKEN&3].state=2;put_half(f.record,0x1c0,1);
    CHECK(umcn_note_owned_publication(&f.adapter)==UMCN_STALE && !f.adapter.trace.source_token);
    f.output.active_ticket=TOKEN;CHECK(umcn_note_owned_publication(&f.adapter)==0);
    CHECK(f.controller.status.source_token==TOKEN && f.adapter.trace.source_token==TOKEN);
}
static void zero_cancel_and_idle_counts_do_not_fake_completion(void)
{
    struct fixture f;
    init(&f);start(&f);published(&f,TOKEN);stop(&f);CHECK(f.cancel_calls==1);
    cleanup(&f);native_cancel_return(&f,1);
    CHECK(umcn_service_owner(&f.adapter)==UMC_PENDING && !f.controller.status.stop_completed_generation);
    CHECK(umcn_after_native_iteration(&f.adapter,1)==UMCN_NATIVE_BUSY);
    CHECK(umcn_after_native_iteration(&f.adapter,0)==0);
    /* An unchanged old source worker can run a later empty pump and record1.
     * Preserve the captured real cancellation return, while still checking
     * all current idle/native/private ownership fields at observation. */
    f.source.pump_calls++;f.source.last_result=f.coordinator.last_result=1;
    CHECK(umcn_service_owner(&f.adapter)==0);
}
static void remove_release_and_cancel_counters_are_not_substitutes(void)
{
    struct fixture f;uint32_t remove,release;
    init(&f);start(&f);published(&f,TOKEN);stop(&f);cleanup(&f);
    native_cancel_return(&f,1);remove=f.coordinator.remove_calls;release=f.output.releases;
    CHECK(umcn_after_native_iteration(&f.adapter,0)==0);
    f.coordinator.remove_calls=0;CHECK(umcn_service_owner(&f.adapter)==UMC_PENDING);
    f.coordinator.remove_calls=remove;f.output.releases=0;CHECK(umcn_service_owner(&f.adapter)==UMC_PENDING);
    f.output.releases=release;f.coordinator.cancelled=0;CHECK(umcn_service_owner(&f.adapter)==UMC_PENDING);
    f.coordinator.cancelled=1;CHECK(umcn_service_owner(&f.adapter)==0);
}
static void exact_native_driver_methods_and_provider_pool_block_done(void)
{
    struct fixture f;
    init(&f);start(&f);published(&f,TOKEN);stop(&f);cleanup(&f);native_cancel_return(&f,1);
    CHECK(umcn_after_native_iteration(&f.adapter,0)==0);
    put_half(f.driver,0,7);CHECK(umcn_service_owner(&f.adapter)==UMC_PENDING);put_half(f.driver,0,0);
    f.record[0xf4+67]=1;CHECK(umcn_service_owner(&f.adapter)==UMC_PENDING);f.record[0xf4+67]=0;
    put_word(f.pool,16,ANCHOR);f.pool[28]=1;CHECK(umcn_service_owner(&f.adapter)==UMC_PENDING);f.pool[28]=0;
    f.mixer[0x84]=1;CHECK(umcn_service_owner(&f.adapter)==UMC_PENDING);f.mixer[0x84]=0;
    f.slots[2].in_flight=1;CHECK(umcn_service_owner(&f.adapter)==UMC_PENDING);f.slots[2].in_flight=0;
    CHECK(umcn_service_owner(&f.adapter)==0);
}
static void full_cleanup_reference_survives_original_notification_preemption(void)
{
    struct fixture f;struct umcn_cleanup_frame frame;uint32_t old;
    init(&f);start(&f);published(&f,TOKEN);stop(&f);
    old=f.current;f.current=TCB+0x3000;CHECK(umcn_cleanup_begin(&f.adapter,f.record,&frame,0x1235)==0);
    f.current=TCB;native_cancel_return(&f,1);CHECK(umcn_after_native_iteration(&f.adapter,0)==0);
    f.current=TCB+0x3000;f.forward_preempts=1;
    CHECK(umcn_cleanup_after_original(&f.adapter,&frame,f.record,0)==0);
    CHECK(f.forwarded==1 && !f.controller.status.callback_references);
    CHECK(umcn_cleanup_after_original(&f.adapter,&frame,f.record,0)==UMCN_STALE && f.forwarded==1);
    f.current=old;CHECK(umcn_service_owner(&f.adapter)==0);
}
static void foreign_record_preserves_old_notification_without_certifying_cleanup(void)
{
    struct fixture f;struct umcn_cleanup_frame frame;uint8_t foreign[520];
    init(&f);start(&f);published(&f,TOKEN);stop(&f);
    CHECK(umcn_cleanup_begin(&f.adapter,foreign,&frame,0x42)==UMCN_STALE);
    CHECK(umcn_cleanup_after_original(&f.adapter,&frame,foreign,0)==UMCN_STALE);
    CHECK(f.forwarded==1 && !f.adapter.trace.original_cleanup_returned && !f.controller.status.cleanup_seen);
    native_cancel_return(&f,1);CHECK(umcn_after_native_iteration(&f.adapter,0)==0);
    CHECK(umcn_service_owner(&f.adapter)==UMC_PENDING);cleanup(&f);CHECK(umcn_service_owner(&f.adapter)==0);
}
static void old_anchor_replacement_before_cleanup_does_not_corrupt_trace(void)
{
    struct fixture f;uint32_t newer=TOKEN+4;
    init(&f);start(&f);published(&f,TOKEN);
    f.coordinator.ticket=f.output.active_ticket=newer;f.slots[newer&3].ticket=newer;
    CHECK(umcn_note_owned_publication(&f.adapter)==UMCN_NATIVE_BUSY);
    CHECK(f.adapter.trace.source_token==TOKEN && f.controller.status.source_token==TOKEN);
}
static void absent_future_callback_exclusion_blocks_observed_completion(void)
{
    struct fixture f;
    init(&f);start(&f);published(&f,TOKEN);stop(&f);cleanup(&f);native_cancel_return(&f,1);
    CHECK(umcn_after_native_iteration(&f.adapter,0)==0);f.witness_bad=1;
    CHECK(umcn_service_owner(&f.adapter)==UMC_PENDING && !f.controller.status.stop_completed_generation);
    f.witness_bad=0;f.witness_calls=0;f.witness_epoch_changes=1;
    CHECK(umcn_service_owner(&f.adapter)==UMC_PENDING);
    f.witness_epoch_changes=0;CHECK(umcn_service_owner(&f.adapter)==0);
}
static void never_published_owner_cancel_and_restart(void)
{
    struct fixture f;uint32_t old,newg;
    init(&f);old=start(&f);stop(&f);native_cancel_return(&f,0);finish(&f);
    newg=start(&f);CHECK(newg==old+1 && !f.adapter.trace.source_token);
    CHECK(umcn_admission(&f.adapter,newg,UMC_GATE_EVENT17));stop(&f);
    CHECK(!umcn_admission(&f.adapter,newg,UMC_GATE_EVENT17));
    CHECK(!umcn_admission(&f.adapter,newg,UMC_GATE_F1));
}
struct test { const char *name;void (*run)(void); };
int main(void)
{
    const struct test tests[]={
        {"missing_and_unsupported_bindings_fail_closed",missing_and_unsupported_bindings_fail_closed},
        {"full_initializer_owner_is_required",full_initializer_owner_is_required},
        {"native_ownership_and_epoch_race_reject_arm",native_ownership_and_epoch_race_reject_arm},
        {"actual_native_token_not_supplied_sample_handle",actual_native_token_not_supplied_sample_handle},
        {"zero_cancel_and_idle_counts_do_not_fake_completion",zero_cancel_and_idle_counts_do_not_fake_completion},
        {"remove_release_and_cancel_counters_are_not_substitutes",remove_release_and_cancel_counters_are_not_substitutes},
        {"exact_native_driver_methods_and_provider_pool_block_done",exact_native_driver_methods_and_provider_pool_block_done},
        {"full_cleanup_reference_survives_original_notification_preemption",full_cleanup_reference_survives_original_notification_preemption},
        {"foreign_record_preserves_old_notification_without_certifying_cleanup",foreign_record_preserves_old_notification_without_certifying_cleanup},
        {"old_anchor_replacement_before_cleanup_does_not_corrupt_trace",old_anchor_replacement_before_cleanup_does_not_corrupt_trace},
        {"absent_future_callback_exclusion_blocks_observed_completion",absent_future_callback_exclusion_blocks_observed_completion},
        {"never_published_owner_cancel_and_restart",never_published_owner_cancel_and_restart}
    };
    size_t i;printf("{\"scope\":\"real adapter ABI/byte observations over host fixtures; no native execution\",\"cases\":[");
    for(i=0;i<sizeof(tests)/sizeof(tests[0]);i++) {tests[i].run();printf("%s{\"name\":\"%s\",\"passed\":true}",i?",":"",tests[i].name);}
    printf("],\"case_count\":%zu,\"all_passed\":true}\n",sizeof(tests)/sizeof(tests[0]));return 0;
}
