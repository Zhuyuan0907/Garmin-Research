/* HOST fixtures, not original native instructions, IRQ, AV lock, audio,
 * cancel completion or a certified ownership witness. Runs actual new guard
 * and immutable control core. Native queue result/post sources are mocks. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "music_session_guard_v3.h"
#include "memory_output.h"
uint32_t memory_output_read(uint32_t i,uint8_t *p,uint32_t n)
{(void)i;(void)p;(void)n;return 0;} /* Unexecuted HOST reader identity only. */
struct fixture {
    struct umc_controller core;struct mcs_guard guard;
    struct umcn_output_view output;struct umcn_slot_view slots[4];
    uint32_t record[130],pool[5*144],other_record[130],params[131];
    uint32_t actor,irq_depth,normal,wakes,queue_invocations,cancel_requests;
    int queue_result,stop_during_queue;
};
static struct fixture *current;
static uint32_t irq_enter(void *p)
{ struct fixture *f=p;uint32_t old=f->irq_depth;f->irq_depth++;return old; }
static void irq_leave(void *p,uint32_t old)
{ struct fixture *f=p;assert(f->irq_depth==old+1u);f->irq_depth=old; }
static uint32_t actor(void *p){return ((struct fixture *)p)->actor;}
static int normal(void *p){return ((struct fixture *)p)->normal!=0;}
static int post(void *p,uint32_t tcb,uint32_t event)
{ struct fixture *f=p;assert(!f->irq_depth && tcb==0x11u && event==0x80000u);f->wakes++;return 0; }
static int prepare(void *p,uint32_t route,uint32_t gen,uint32_t cookie)
{ struct fixture *f=p;assert(route==8u && cookie==0x1352u);return mcs_reserve_scoped(&f->guard,gen); }
static int cancel(void *p,uint32_t route,uint32_t gen,uint32_t cookie)
{ struct fixture *f=p;assert(route==8u && gen && cookie==0x1352u);f->cancel_requests++;return 0; }
static int observe(void *p,uint32_t route,uint32_t gen,uint32_t cookie,
                   struct umc_stop_evidence *e)
{ (void)p;(void)route;(void)gen;(void)cookie;(void)e;return MCS_UNCERTIFIED; }
static int queue_mock(volatile void *list,uint32_t key,uint32_t kind,uint32_t flags,
    const void *params,uint32_t len,const void *metadata)
{
    struct fixture *f=current;uint32_t generation;
    assert(!f->irq_depth);assert(list==(void *)((uint8_t *)f->record+0x1a8u));
    assert(key==0xffffu && kind==10u && flags==12u && params==f->params && len==0x20cu && !metadata);
    f->queue_invocations++;
    if(f->stop_during_queue)assert(umc_request_stop(&f->core,&generation)==UMC_PENDING);
    return f->queue_result;
}
static void setup(struct fixture *f)
{
    struct umc_config cfg={0x11u,8u,0x1352u,1u};
    struct umc_adapters ops={f,irq_enter,irq_leave,actor,post,prepare,cancel,observe};
    uint32_t generation;
    memset(f,0,sizeof(*f));current=f;f->actor=0x11u;f->normal=1;
    f->output.initialized=1;f->output.channel=8;
    assert(umc_init(&f->core,&cfg,&ops)==UMC_OK);
    assert(mcs_init(&f->guard,&f->core,&f->output,f->slots,
        (uint8_t *)f->record,(uint8_t *)f->pool,0x02004000u,normal,f)==UMC_OK);
    mcs_bridge_context=&f->guard;
    assert(umc_runtime_ready(&f->core)==UMC_OK);
    assert(umc_request_start(&f->core,&generation)==UMC_PENDING && generation==1u);
    assert(umc_service(&f->core)==UMC_OK);
    assert(f->core.status.state==UMC_ARMED && f->guard.held);
    f->guard.original_queue=queue_mock;
    f->record[0x160u/4u]=(uint32_t)(uintptr_t)mcs_queue_bridge;
    f->slots[1].ticket=5u;f->slots[1].state=2u;
    f->params[0]=1;f->params[1]=16000;f->params[2]=16;
    f->params[3]=f->guard.anchor;f->params[4]=2;
}
static void select_fixture(struct fixture *f)
{
    /* Declared input: matches exact original provider offsets. It is NOT a
     * native allocation/factory/writer execution or exclusive reservation. */
    uint8_t *r=(uint8_t *)f->record,*p=(uint8_t *)f->pool+2u*576u;
    /* Host-only native registration/selection input, not an original writer. */
    f->guard.registration_ticket=5u;f->output.active_ticket=5u;
    f->output.installed=1;r[2]=1;
    *(uint32_t *)(r+0x108u)=(uint32_t)(uintptr_t)memory_output_read;
    *(uint32_t *)(r+0xf0u)=2;*(uint32_t *)(r+0x10cu)=0x48ee31u;
    p[12]=1;p[28]=1;*(uint32_t *)(p+16)=f->guard.anchor;*(uint32_t *)(p+20)=2;
}
static int dispatch(struct fixture *f)
{ return mcs_queue_dispatch(&f->guard,(uint8_t *)f->record+0x1a8u,0xffff,10,12,
      f->params,0x20c,0); }
static void selected(struct fixture *f)
{ select_fixture(f);assert(mcs_capture_selected(&f->guard,1)==UMC_OK); }
static void group(const char *name){puts(name);}
int main(void)
{
    struct fixture f;struct mcs_borrow_frame b,other;
    struct mcs_event_frame ev;struct umcn_ownership_witness witness,before;
    uint32_t generation,old;int result;
    setup(&f);assert(mcs_register_begin(&f.guard,5)==UMC_OK);
    f.output.active_ticket=5;f.queue_result=5;
    assert(dispatch(&f)==5 && f.queue_invocations==1);
    assert(dispatch(&f)==8 && f.queue_invocations==1);
    assert(mcs_register_end(&f.guard,5)==5 && !f.guard.permit_entered);
    group("01_exact_owned_queue_fingerprint_one_call_original_alloc_failure5");

    setup(&f);assert(mcs_register_begin(&f.guard,5)==0);f.output.active_ticket=5;
    f.actor=0x22;assert(dispatch(&f)==8 && !f.queue_invocations && !f.guard.permit_consumed);
    f.actor=0x11;f.normal=0;assert(dispatch(&f)==8 && !f.queue_invocations);
    f.normal=1;f.params[3]++;assert(dispatch(&f)==8 && !f.queue_invocations);
    f.params[3]--;assert(dispatch(&f)==0 && f.queue_invocations==1);
    assert(mcs_register_end(&f.guard,0)==0);
    group("02_foreign_actor_ISR_wrong_anchor_do_not_consume_owned_permit");

    setup(&f);f.record[0x160u/4u]=0x277c6bu;
    memset(f.other_record,0x61,sizeof(f.other_record));
    old=f.other_record[0x160u/4u];f.guard.original_queue=0;
    assert(mcs_install_queue_callback(&f.guard)==0);
    assert(f.record[0x160u/4u]==(uint32_t)(uintptr_t)mcs_queue_bridge);
    assert(f.other_record[0x160u/4u]==old && mcs_install_queue_callback(&f.guard)==MCS_ALREADY_BOUND);
    group("03_native_callback_slot_only_other_channel_preserved_HOST_RAM_fixture");

    setup(&f);select_fixture(&f);f.actor=0x22;
    assert(mcs_capture_selected(&f.guard,1)==MCS_REJECTED && !f.guard.selected_session);
    group("04_native_matching_pool_wrong_capture_actor_rejected");
    setup(&f);select_fixture(&f);f.guard.generation=2;
    assert(mcs_capture_selected(&f.guard,1)==MCS_REJECTED && !f.guard.selected_session);
    group("05_native_matching_pool_stale_capture_generation_rejected");
    setup(&f);select_fixture(&f);f.normal=0;
    assert(mcs_capture_selected(&f.guard,1)==MCS_REJECTED && !f.guard.selected_session);
    group("06_native_matching_pool_ISR_capture_rejected");

    setup(&f);selected(&f);memset(&b,0,sizeof(b));f.actor=0x33;
    assert(mcs_pull_begin(8,&b)==0 && f.core.status.media_references==1 &&
        f.core.status.callback_references==1 && mcs_reader_admit(&f.guard,2));
    assert(!mcs_reader_admit(&f.guard,1));f.actor=0x44;
    assert(!mcs_reader_admit(&f.guard,2));f.actor=0x33;
    mcs_pull_end(&b,123);assert(b.original_returned && !f.guard.borrow &&
        !f.core.status.media_references && !f.core.status.callback_references);
    assert(!mcs_reader_admit(&f.guard,2));
    group("07_full_pull_actor_index_typed_leases_retained_to_HOST_full_return");

    setup(&f);selected(&f);memset(&b,0,sizeof(b));memset(&other,0,sizeof(other));
    assert(mcs_pull_begin(8,&b)==0);assert(mcs_pull_begin(8,&other)==MCS_REJECTED);
    assert(f.guard.borrow==&b && f.core.status.media_references==1);
    assert(mcs_capture_selected(&f.guard,1)==MCS_REJECTED);
    mcs_pull_end(&b,0);
    group("08_reentry_and_selection_cannot_replace_live_borrow_frame");

    setup(&f);selected(&f);memset(&b,0,sizeof(b));
    assert(mcs_pull_begin(8,&b)==0);
    assert(umc_request_stop(&f.core,&generation)==UMC_PENDING);
    assert(!mcs_reader_admit(&f.guard,2) && umc_request_start(&f.core,&generation)==UMC_BUSY);
    assert(umc_service(&f.core)==UMC_PENDING && f.cancel_requests==1 &&
        f.core.status.state==UMC_STOPPING && f.core.status.callback_references==1);
    mcs_pull_end(&b,0);
    assert(f.core.status.state==UMC_STOPPING && !f.core.status.callback_references);
    assert(umc_service(&f.core)==UMC_PENDING && !f.core.status.stop_completed_generation);
    assert(mcs_release_scoped(&f.guard)==UMC_BUSY);
    group("09_stop_invalidates_read_restart_blocked_empty_refs_NEVER_STOP_DONE");

    setup(&f);selected(&f);memset(&b,0,sizeof(b));
    assert(mcs_pull_begin(8,&b)==0 && mcs_mutation_begin(&f.guard)==UMC_PENDING);
    assert(!f.output.reader_in_flight && f.core.status.callback_references==1);
    mcs_pull_end(&b,0);assert(mcs_mutation_begin(&f.guard)==0);
    memset(&b,0,sizeof(b));assert(mcs_pull_begin(8,&b)==MCS_REJECTED);
    mcs_mutation_end(&f.guard);assert(mcs_pull_begin(8,&b)==0);mcs_pull_end(&b,0);
    group("10_shared_mutation_gate_covers_pre_reader_window_and_complete_native_call_scope");

    setup(&f);assert(mcs_register_begin(&f.guard,5)==0);f.output.active_ticket=5;
    f.stop_during_queue=1;f.queue_result=0;
    result=dispatch(&f);assert(result==0 && f.core.status.state==UMC_STOPPING);
    assert(mcs_register_end(&f.guard,result)==0 && dispatch(&f)==8);
    assert(umc_service(&f.core)==UMC_PENDING && !f.core.status.stop_completed_generation);
    group("11_stop_racing_actual_mock_queue_return0_is_not_cancel_completion");

    setup(&f);memset(&ev,0,sizeof(ev));
    assert(mcs_event_begin(&f.guard,1,UMC_GATE_EVENT17,&ev)==0);
    assert(umc_request_stop(&f.core,&generation)==UMC_PENDING);
    assert(!umc_admission(&f.core,1,UMC_GATE_F1));mcs_event_end(&f.guard,&ev);
    memset(&ev,0,sizeof(ev));assert(mcs_event_begin(&f.guard,1,UMC_GATE_EVENT17,&ev)==MCS_REJECTED);
    assert(mcs_event_begin(&f.guard,1,UMC_GATE_CONSUMER,&ev)==MCS_REJECTED);
    group("12_remote17_F1_consumer_cannot_resume_locally_stopped_route");

    setup(&f);selected(&f);memset(&b,0,sizeof(b));
    assert(mcs_pull_begin(8,&b)==0);mcs_pull_end(&b,0);
    /* Reuse-index adversary: fabricate matching current pool + ticket while
     * stale released frame remains. It cannot resurrect a noncopyable lease. */
    f.guard.borrow=&b;f.guard.selected_session=b.session;f.guard.selected_instance=b.instance;
    assert(!mcs_reader_admit(&f.guard,2));f.guard.borrow=0;
    group("13_delayed_reused_index_and_pool_match_do_not_resurrect_returned_frame");

    setup(&f);memset(&b,0,sizeof(b));mcs_bridge_context=0;
    assert(mcs_pull_begin(5,&b)==0 && !b.entered);
    assert(mcs_pull_begin(8,&b)==MCS_REJECTED);mcs_bridge_context=&f.guard;
    f.normal=0;memset(&b,0,sizeof(b));assert(mcs_pull_begin(9,&b)==0);
    assert(f.core.config.route==8 && f.core.status.state==UMC_ARMED);
    group("14_other_native_channels_passthrough_no_App_source9_binding_granted");

    setup(&f);memset(&witness,0x77,sizeof(witness));before=witness;
    assert(mcs_native_ownership_snapshot(&f.guard,1,5,&witness)==MCS_UNCERTIFIED);
    assert(!memcmp(&before,&witness,sizeof(witness)) && !f.core.status.stop_completed_generation);
    group("15_uncertified_native_writer_closure_leaves_witness_untouched");
    setup(&f);assert(mcs_register_begin(&f.guard,5)==0);f.output.active_ticket=5;
    assert(mcs_queue_dispatch(&f.guard,(uint8_t *)f.record+0x1a8u,0,10,12,
        f.params,0x20c,0)==8 && !f.queue_invocations && !f.guard.permit_consumed);
    assert(dispatch(&f)==0 && f.queue_invocations==1);assert(mcs_register_end(&f.guard,0)==0);
    group("16_original_keyFFFF_r2kind_r3flags_stackparamslenmeta_negative_control");
    setup(&f);f.record[0x160u/4u]=0x277c6bu;
    assert(mcs_register_begin(&f.guard,5)==MCS_REJECTED && !f.guard.permit_entered);
    group("17_original_profile_rewrite_invalidates_guard_callback_permit");
    setup(&f);selected(&f);f.slots[1].state=0;
    memset(&b,0,sizeof(b));assert(mcs_pull_begin(8,&b)==0 && b.session==1);
    assert(mcs_reader_admit(&f.guard,2));mcs_pull_end(&b,0);
    f.slots[1].ticket=9;f.slots[1].state=2;
    memset(&b,0,sizeof(b));assert(mcs_pull_begin(8,&b)==0 && b.session==1);
    assert(mcs_reader_admit(&f.guard,2));mcs_pull_end(&b,0);
    assert(f.guard.registration_ticket==5 && f.output.active_ticket==5 &&
           f.guard.selected_session==1 && f.guard.full_returns==2);
    group("18_HOST_recycled_slot_generation9_does_not_invalidate_session1");

    setup(&f);selected(&f);f.slots[1].ticket=9;f.slots[1].state=2;
    assert(mcs_register_begin(&f.guard,9)==MCS_REJECTED && !f.guard.permit_entered);
    group("19_recycled_FIFO_ticket_cannot_register_a_second_native_anchor");

    setup(&f);selected(&f);assert(mcs_capture_selected(&f.guard,5)==MCS_REJECTED);
    assert(f.guard.selected_session==1);
    group("20_registration_seed5_cannot_be_used_as_session1_selection");

    setup(&f);selected(&f);f.record[0xf0u/4u]=1;
    memset(&b,0,sizeof(b));assert(mcs_pull_begin(8,&b)==MCS_REJECTED);
    group("21_native_record_replacement_rejects_pull_even_with_live_session");

    setup(&f);selected(&f);((uint8_t *)f.pool)[2u*576u+28]=0;
    memset(&b,0,sizeof(b));assert(mcs_pull_begin(8,&b)==MCS_REJECTED);
    group("22_unprepared_native_provider_rejects_live_session_pull");

    setup(&f);selected(&f);memset(&b,0,sizeof(b));
    assert(mcs_pull_begin(8,&b)==0);f.record[0x108u/4u]=0x48edf9u;
    assert(!mcs_reader_admit(&f.guard,2));mcs_pull_end(&b,0);
    group("23_reader_reprofile_detected_inside_full_return_lease");

    setup(&f);selected(&f);memset(&b,0,sizeof(b));
    assert(mcs_pull_begin(8,&b)==0);f.guard.epoch++;
    assert(!mcs_reader_admit(&f.guard,2));mcs_pull_end(&b,0);
    group("24_stale_session_epoch_cannot_reuse_a_live_buffer_generation");

    setup(&f);selected(&f);assert(umc_request_stop(&f.core,&generation)==UMC_PENDING);
    memset(&ev,0,sizeof(ev));
    assert(mcs_event_begin(&f.guard,1,UMC_GATE_CONSUMER,&ev)==MCS_REJECTED);
    assert(!ev.media.held && !ev.callback.held && !f.core.status.stop_completed_generation);
    group("25_Stop_denies_new_producer_copy_lease_without_fabricating_STOP_DONE");
    puts("PASS 25 HOST groups; no native IRQ/AV/audio/exclusivity/STOP_DONE proof");
    return 0;
}
