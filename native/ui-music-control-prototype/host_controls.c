/* Deterministic host adapter controls. No native instruction/IRQ/audio proof. */
#include "ui_music_control.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL:%s:%d:%s\n",__FILE__,__LINE__,#x); exit(1); } } while (0)
#define TCB 0x8801000u
#define COOKIE 0x13528001u
#define TOKEN 0x1231u
struct fixture {
    struct umc_controller control;
    uint32_t current, lock_depth, key, wakes, prepare_calls, cancel_calls, observes;
    int wake_result, prepare_result, cancel_result, observe_result;
    int stop_inside_prepare, publish_inside_prepare, callback_inside_observe, service_on_leave;
    struct umc_lease callback;
    struct umc_stop_evidence evidence;
};
static uint32_t meta_enter(void *ctx)
{
    struct fixture *f=ctx;
    CHECK(!f->lock_depth); f->lock_depth=1; return ++f->key;
}
static void meta_leave(void *ctx,uint32_t key)
{
    struct fixture *f=ctx;
    CHECK(f->lock_depth==1 && key==f->key); f->lock_depth=0;
    if (f->service_on_leave) {
        f->service_on_leave=0;
        CHECK(umc_service(&f->control)==UMC_ADAPTER_FAILED);
    }
}
static uint32_t actor(void *ctx)
{ struct fixture *f=ctx; CHECK(!f->lock_depth); return f->current; }
static int post(void *ctx,uint32_t tcb,uint32_t event)
{
    struct fixture *f=ctx;
    CHECK(!f->lock_depth && tcb==TCB && event==UMC_SOURCE_EVENT);
    f->wakes++; return f->wake_result;
}
static int prepare(void *ctx,uint32_t route,uint32_t generation,uint32_t cookie)
{
    struct fixture *f=ctx; uint32_t token;
    CHECK(!f->lock_depth && f->current==TCB && route==f->control.config.route && cookie==COOKIE);
    f->prepare_calls++;
    if(f->publish_inside_prepare)
        CHECK(umc_source_started(&f->control,route,generation,cookie,TOKEN)==UMC_OK);
    if(f->stop_inside_prepare) {
        CHECK(umc_request_stop(&f->control,&token)==UMC_PENDING && token==generation);
        CHECK(umc_service(&f->control)==UMC_BUSY);
    }
    return f->prepare_result;
}
static int cancel(void *ctx,uint32_t route,uint32_t generation,uint32_t cookie)
{
    struct fixture *f=ctx;
    CHECK(!f->lock_depth && f->current==TCB && route==f->control.config.route && cookie==COOKIE);
    CHECK(generation==f->control.status.generation && !f->control.status.armed);
    f->cancel_calls++; return f->cancel_result;
}
static int observe(void *ctx,uint32_t route,uint32_t generation,uint32_t cookie,
                    struct umc_stop_evidence *out)
{
    struct fixture *f=ctx;
    CHECK(!f->lock_depth && f->current==TCB && route==f->control.config.route && cookie==COOKIE);
    CHECK(generation==f->control.status.generation); f->observes++;
    if(f->callback_inside_observe) {
        f->callback_inside_observe=0;
        CHECK(umc_callback_acquire(&f->control,&f->callback)==UMC_OK);
    }
    *out=f->evidence; return f->observe_result;
}
static void init(struct fixture *f,uint32_t route)
{
    struct umc_config cfg={TCB,route,COOKIE,1};
    struct umc_adapters a={f,meta_enter,meta_leave,actor,post,prepare,cancel,observe};
    memset(f,0,sizeof(*f)); f->current=TCB;
    CHECK(umc_init(&f->control,&cfg,&a)==UMC_OK);
}
static void ready(struct fixture *f)
{ CHECK(umc_runtime_ready(&f->control)==UMC_OK); }
static uint32_t start(struct fixture *f)
{
    uint32_t generation=0;
    CHECK(umc_request_start(&f->control,&generation)==UMC_PENDING);
    CHECK(umc_service(&f->control)==UMC_OK);
    CHECK(f->control.status.armed); return generation;
}
static uint32_t stop(struct fixture *f)
{
    uint32_t generation=0;
    CHECK(umc_request_stop(&f->control,&generation)==UMC_PENDING);
    CHECK(!f->control.status.armed);
    CHECK(umc_service(&f->control)==UMC_PENDING);
    CHECK(!f->control.status.stop_completed_generation); return generation;
}
static void full_evidence(struct fixture *f,int published)
{
    struct umc_stop_evidence *e=&f->evidence;
    memset(e,0,sizeof(*e)); e->generation=f->control.status.generation;
    e->ownership_cookie=COOKIE; e->route=f->control.config.route;
    e->ownership_confirmed=e->cancel_pipeline_returned=e->native_idle=1;
    e->source_was_published=(uint32_t)published;
    e->source_token=published?f->control.status.source_token:0;
    e->never_published_barrier=(uint32_t)!published;
    e->node_removal_returned=e->anchor_release_returned=e->fifo_discard_returned=e->queue_clear_returned=1;
}
static void source(struct fixture *f,uint32_t token)
{ CHECK(umc_source_started(&f->control,f->control.config.route,f->control.status.generation,COOKIE,token)==UMC_OK); }
static void cleaned(struct fixture *f,uint32_t token)
{ CHECK(umc_cleanup_returned(&f->control,f->control.config.route,f->control.status.generation,COOKIE,token)==UMC_OK); }

static void cold_and_resident(void)
{
    struct fixture f; uint32_t g=0; struct umc_config cfg={TCB,8,COOKIE,1};
    struct umc_adapters a;
    init(&f,8); a=f.control.adapters;
    CHECK(umc_request_start(&f.control,&g)==UMC_NOT_READY);
    CHECK(umc_request_stop(&f.control,&g)==UMC_NOT_READY && !g);
    CHECK(!f.wakes && !f.prepare_calls && !f.cancel_calls);
    CHECK(umc_init(&f.control,&cfg,&a)==UMC_PINNED);
    CHECK(f.control.status.state==UMC_BOOTING);
    cfg.resident_storage_confirmed=0;
    CHECK(umc_init(&f.control,&cfg,&a)==UMC_BAD_ARGUMENT);
}
static void owner_only_service(void)
{
    struct fixture f; uint32_t g;
    init(&f,8); f.current=TCB+4;
    CHECK(umc_runtime_ready(&f.control)==UMC_WRONG_OWNER);
    f.current=TCB; ready(&f); CHECK(umc_request_start(&f.control,&g)==UMC_PENDING);
    f.current=TCB+4; CHECK(umc_service(&f.control)==UMC_WRONG_OWNER && !f.prepare_calls);
    f.current=TCB; CHECK(umc_service(&f.control)==UMC_OK);
}
static void start_admission_and_duplicate(void)
{
    struct fixture f; uint32_t g,x; unsigned gate;
    init(&f,8); ready(&f); g=start(&f);
    CHECK(g==1 && f.prepare_calls==1 && f.control.status.state==UMC_ARMED);
    for(gate=UMC_GATE_CONFIG;gate<=UMC_GATE_CONSUMER;gate++) CHECK(umc_admission(&f.control,g,gate));
    CHECK(!umc_admission(&f.control,g+1,UMC_GATE_F1));
    CHECK(umc_request_start(&f.control,&x)==UMC_BUSY && x==g && f.prepare_calls==1);
}
static void queued_start_superseded_by_stop(void)
{
    struct fixture f; uint32_t g,x;
    init(&f,8); ready(&f); CHECK(umc_request_start(&f.control,&g)==UMC_PENDING);
    CHECK(umc_request_stop(&f.control,&x)==UMC_PENDING && x==g);
    CHECK(umc_service(&f.control)==UMC_PENDING && !f.prepare_calls && f.cancel_calls==1);
    CHECK(!f.control.status.stop_completed_generation);
    full_evidence(&f,0); f.evidence.never_published_barrier=0;
    CHECK(umc_service(&f.control)==UMC_PENDING);
    f.evidence.never_published_barrier=1;
    CHECK(umc_service(&f.control)==UMC_OK && f.control.status.stop_completed_generation==g);
}
static void duplicate_stop_and_busy_start(void)
{
    struct fixture f; uint32_t g,x; unsigned wakes;
    init(&f,8); ready(&f); g=start(&f); stop(&f); wakes=f.wakes;
    CHECK(umc_request_stop(&f.control,&x)==UMC_ALREADY && x==g && f.wakes==wakes);
    CHECK(umc_request_start(&f.control,&x)==UMC_BUSY && x==g);
    CHECK(umc_service(&f.control)==UMC_PENDING && f.cancel_calls==1);
}
static void cancel_zero_is_not_completion(void)
{
    struct fixture f;
    init(&f,8); ready(&f); start(&f); source(&f,TOKEN); stop(&f);
    CHECK(f.cancel_calls==1 && f.control.status.state==UMC_STOPPING);
    cleaned(&f,TOKEN);
    CHECK(umc_service(&f.control)==UMC_PENDING && !f.control.status.stop_completed_generation);
    full_evidence(&f,1); f.evidence.cancel_pipeline_returned=0;
    CHECK(umc_service(&f.control)==UMC_PENDING);
    f.evidence.cancel_pipeline_returned=1;
    CHECK(umc_service(&f.control)==UMC_OK);
}
static void every_native_busy_field_blocks_completion(void)
{
    const size_t offsets[]={
        offsetof(struct umc_stop_evidence,node_count), offsetof(struct umc_stop_evidence,methods_live),
        offsetof(struct umc_stop_evidence,provider_active), offsetof(struct umc_stop_evidence,mixer_active),
        offsetof(struct umc_stop_evidence,driver_active), offsetof(struct umc_stop_evidence,native_calls),
        offsetof(struct umc_stop_evidence,reader_in_flight), offsetof(struct umc_stop_evidence,coordinator_busy),
        offsetof(struct umc_stop_evidence,coordinator_ticket), offsetof(struct umc_stop_evidence,coordinator_cancel_pending),
        offsetof(struct umc_stop_evidence,anchor_live), offsetof(struct umc_stop_evidence,owned_busy),
        offsetof(struct umc_stop_evidence,owned_count), offsetof(struct umc_stop_evidence,queue_producer_busy),
        offsetof(struct umc_stop_evidence,queue_consumer_busy), offsetof(struct umc_stop_evidence,queue_pending)
    };
    struct fixture f; size_t i;
    init(&f,8); ready(&f); start(&f); source(&f,TOKEN); stop(&f); cleaned(&f,TOKEN);
    for(i=0;i<sizeof(offsets)/sizeof(offsets[0]);i++) {
        uint32_t *field;
        full_evidence(&f,1); field=(uint32_t *)((unsigned char *)&f.evidence+offsets[i]); *field=1;
        CHECK(umc_service(&f.control)==UMC_PENDING && !f.control.status.stop_completed_generation);
    }
    full_evidence(&f,1); CHECK(umc_service(&f.control)==UMC_OK);
}
static void original_remove_release_discard_return_required(void)
{
    struct fixture f;
    init(&f,8); ready(&f); start(&f); source(&f,TOKEN); stop(&f); cleaned(&f,TOKEN);
    full_evidence(&f,1); f.evidence.node_removal_returned=0; CHECK(umc_service(&f.control)==UMC_PENDING);
    full_evidence(&f,1); f.evidence.anchor_release_returned=0; CHECK(umc_service(&f.control)==UMC_PENDING);
    full_evidence(&f,1); f.evidence.fifo_discard_returned=0; CHECK(umc_service(&f.control)==UMC_PENDING);
    full_evidence(&f,1); CHECK(umc_service(&f.control)==UMC_OK);
}
static void stale_generation_cookie_route_and_token(void)
{
    struct fixture f; uint32_t g;
    init(&f,8); ready(&f); g=start(&f); source(&f,TOKEN); stop(&f);
    CHECK(umc_cleanup_returned(&f.control,8,g+1,COOKIE,TOKEN)==UMC_STALE);
    CHECK(umc_cleanup_returned(&f.control,8,g,COOKIE+1,TOKEN)==UMC_STALE);
    CHECK(umc_cleanup_returned(&f.control,9,g,COOKIE,TOKEN)==UMC_STALE);
    CHECK(umc_cleanup_returned(&f.control,8,g,COOKIE,TOKEN+1)==UMC_STALE);
    full_evidence(&f,1); CHECK(umc_service(&f.control)==UMC_PENDING);
    cleaned(&f,TOKEN); f.evidence.generation++; CHECK(umc_service(&f.control)==UMC_PENDING);
    full_evidence(&f,1); f.evidence.ownership_cookie++; CHECK(umc_service(&f.control)==UMC_PENDING);
    full_evidence(&f,1); f.evidence.route=9; CHECK(umc_service(&f.control)==UMC_PENDING);
    full_evidence(&f,1); f.evidence.source_token++; CHECK(umc_service(&f.control)==UMC_PENDING);
    full_evidence(&f,1); CHECK(umc_service(&f.control)==UMC_OK);
}
static void admission_stays_closed_during_and_after_stop(void)
{
    struct fixture f; uint32_t g; unsigned gate;
    init(&f,8); ready(&f); g=start(&f); stop(&f);
    for(gate=UMC_GATE_CONFIG;gate<=UMC_GATE_CONSUMER;gate++) CHECK(!umc_admission(&f.control,g,gate));
    full_evidence(&f,0); CHECK(umc_service(&f.control)==UMC_OK);
    CHECK(!umc_admission(&f.control,g,UMC_GATE_EVENT17));
    CHECK(!umc_admission(&f.control,g,UMC_GATE_F1));
    CHECK(start(&f)==g+1 && umc_admission(&f.control,g+1,UMC_GATE_EVENT17));
}
static void selected_packet_lease_invalidated_before_release(void)
{
    struct fixture f; struct umc_lease lease={0}; uint32_t g; unsigned before;
    init(&f,8); ready(&f); g=start(&f);
    CHECK(umc_media_acquire(&f.control,g,&lease)==UMC_OK && umc_media_current(&f.control,&lease));
    stop(&f); CHECK(!umc_media_current(&f.control,&lease)); full_evidence(&f,0);
    CHECK(umc_service(&f.control)==UMC_PENDING); before=f.wakes;
    CHECK(umc_media_release(&f.control,&lease)==UMC_OK && f.wakes==before+1);
    CHECK(umc_media_release(&f.control,&lease)==UMC_STALE);
    CHECK(umc_service(&f.control)==UMC_OK);
}
static void entire_cleanup_callback_lifetime_blocks_done(void)
{
    struct fixture f; struct umc_lease callback={0}; unsigned before;
    init(&f,8); ready(&f); start(&f); source(&f,TOKEN); stop(&f);
    CHECK(umc_callback_acquire(&f.control,&callback)==UMC_OK); cleaned(&f,TOKEN); full_evidence(&f,1);
    CHECK(umc_service(&f.control)==UMC_PENDING); before=f.wakes;
    CHECK(umc_callback_release(&f.control,&callback)==UMC_OK && f.wakes==before+1);
    CHECK(umc_service(&f.control)==UMC_OK);
}
static void callback_arriving_during_observation_blocks_done(void)
{
    struct fixture f;
    init(&f,8); ready(&f); start(&f); source(&f,TOKEN); stop(&f); cleaned(&f,TOKEN);
    full_evidence(&f,1); f.callback_inside_observe=1;
    CHECK(umc_service(&f.control)==UMC_PENDING && f.control.status.callback_references==1);
    CHECK(umc_callback_release(&f.control,&f.callback)==UMC_OK);
    CHECK(umc_service(&f.control)==UMC_OK);
}
static void stop_wins_over_synchronous_prepare_return(void)
{
    struct fixture f; uint32_t g;
    init(&f,8); ready(&f); f.stop_inside_prepare=f.publish_inside_prepare=1;
    CHECK(umc_request_start(&f.control,&g)==UMC_PENDING);
    CHECK(umc_service(&f.control)==UMC_PENDING && !f.control.status.armed);
    CHECK(f.control.status.state==UMC_STOPPING && !f.cancel_calls);
    CHECK(umc_service(&f.control)==UMC_PENDING && f.cancel_calls==1);
    cleaned(&f,TOKEN); full_evidence(&f,1); CHECK(umc_service(&f.control)==UMC_OK);
}
static void synchronous_prepare_publication_is_active(void)
{
    struct fixture f;
    init(&f,8); ready(&f); f.publish_inside_prepare=1; start(&f);
    CHECK(f.control.status.state==UMC_ACTIVE && f.control.status.source_token==TOKEN);
}
static void wake_failure_preserves_pending_command(void)
{
    struct fixture f; uint32_t g,x;
    init(&f,8); ready(&f); f.wake_result=-41;
    CHECK(umc_request_start(&f.control,&g)==UMC_WAKE_FAILED && g==1);
    CHECK(umc_request_start(&f.control,&x)==UMC_BUSY && x==g);
    CHECK(f.control.status.last_wake_error==-41 && f.control.pending_start);
    f.wake_result=0; CHECK(umc_kick(&f.control)==UMC_OK);
    CHECK(umc_service(&f.control)==UMC_OK && f.prepare_calls==1);
}
static void dropped_native_stop_cannot_become_done(void)
{
    struct fixture f; unsigned i;
    init(&f,8); ready(&f); start(&f); source(&f,TOKEN); stop(&f);
    full_evidence(&f,1); f.evidence.native_idle=0; f.evidence.cancel_pipeline_returned=0;
    for(i=0;i<8;i++) CHECK(umc_service(&f.control)==UMC_PENDING);
    CHECK(f.control.status.state==UMC_STOPPING && !f.control.status.stop_completed_generation && f.cancel_calls==1);
}
static void cancel_failure_pins_then_explicit_stop_retries(void)
{
    struct fixture f; uint32_t g;
    init(&f,8); ready(&f); start(&f); f.cancel_result=-22;
    CHECK(umc_request_stop(&f.control,&g)==UMC_PENDING);
    CHECK(umc_service(&f.control)==UMC_ADAPTER_FAILED && f.control.status.state==UMC_ERROR_PINNED);
    CHECK(umc_request_start(&f.control,&g)==UMC_PINNED);
    f.cancel_result=0; CHECK(umc_request_stop(&f.control,&g)==UMC_PENDING);
    CHECK(umc_service(&f.control)==UMC_PENDING && f.cancel_calls==2);
    full_evidence(&f,0); CHECK(umc_service(&f.control)==UMC_OK);
}
static void prepare_failure_never_claims_armed_or_done(void)
{
    struct fixture f; uint32_t g;
    init(&f,8); ready(&f); f.prepare_result=-25;
    CHECK(umc_request_start(&f.control,&g)==UMC_PENDING);
    CHECK(umc_service(&f.control)==UMC_ADAPTER_FAILED && !f.control.status.armed);
    CHECK(f.control.status.state==UMC_ERROR_PINNED && !f.control.status.stop_completed_generation);
    CHECK(umc_request_start(&f.control,&g)==UMC_PINNED);
    f.prepare_result=0; stop(&f); full_evidence(&f,0); CHECK(umc_service(&f.control)==UMC_OK);
    CHECK(start(&f)==g+1);
}
static void restart_new_generation_rejects_old_callbacks(void)
{
    struct fixture f; uint32_t old,newg;
    init(&f,8); ready(&f); old=start(&f); source(&f,TOKEN); stop(&f); cleaned(&f,TOKEN);
    full_evidence(&f,1); CHECK(umc_service(&f.control)==UMC_OK);
    newg=start(&f); CHECK(newg==old+1);
    CHECK(umc_cleanup_returned(&f.control,8,old,COOKIE,TOKEN)==UMC_STALE);
    CHECK(umc_source_started(&f.control,8,old,COOKIE,TOKEN)==UMC_STALE);
    CHECK(!f.control.status.cleanup_seen && f.control.status.stop_completed_generation==old);
}
static void remote_cycle_old_anchor_token_is_stale(void)
{
    struct fixture f; uint32_t g;
    init(&f,8); ready(&f); g=start(&f); source(&f,TOKEN);
    CHECK(umc_source_started(&f.control,8,g,COOKIE,TOKEN+1)==UMC_BUSY);
    cleaned(&f,TOKEN); source(&f,TOKEN+1);
    CHECK(!f.control.status.cleanup_seen);
    CHECK(umc_cleanup_returned(&f.control,8,g,COOKIE,TOKEN)==UMC_STALE);
    stop(&f); full_evidence(&f,1); CHECK(umc_service(&f.control)==UMC_PENDING);
    cleaned(&f,TOKEN+1); CHECK(umc_service(&f.control)==UMC_OK);
}
static void generation_and_epoch_do_not_wrap(void)
{
    struct fixture f; uint32_t g;
    init(&f,8); ready(&f); f.control.status.generation=UINT32_MAX;
    CHECK(umc_request_start(&f.control,&g)==UMC_OVERFLOW && !f.wakes);
    init(&f,8); ready(&f); start(&f); f.control.status.admission_epoch=UINT32_MAX;
    stop(&f); CHECK(f.control.status.admission_epoch==UINT32_MAX);
    full_evidence(&f,0); CHECK(umc_service(&f.control)==UMC_OK);
    CHECK(umc_request_start(&f.control,&g)==UMC_OVERFLOW);
}
static void lease_kind_and_start_callback_guards(void)
{
    struct fixture f; struct umc_lease cb={0},media={0}; uint32_t g;
    init(&f,8); ready(&f); CHECK(umc_callback_acquire(&f.control,&cb)==UMC_OK);
    CHECK(umc_request_start(&f.control,&g)==UMC_BUSY);
    CHECK(umc_callback_release(&f.control,&cb)==UMC_OK); g=start(&f);
    CHECK(umc_media_acquire(&f.control,g,&media)==UMC_OK);
    CHECK(umc_callback_acquire(&f.control,&cb)==UMC_OK);
    CHECK(umc_callback_release(&f.control,&media)==UMC_STALE);
    CHECK(umc_media_release(&f.control,&cb)==UMC_STALE);
    CHECK(f.control.status.media_references==1 && f.control.status.callback_references==1);
    CHECK(umc_media_release(&f.control,&media)==UMC_OK);
    CHECK(umc_callback_release(&f.control,&cb)==UMC_OK);
}
static void WAV9_requires_native_clear_and_denies_phone_admission(void)
{
    struct fixture f; uint32_t g;
    init(&f,9); ready(&f); f.publish_inside_prepare=1; g=start(&f);
    CHECK(!umc_admission(&f.control,g,UMC_GATE_F1));
    stop(&f); cleaned(&f,TOKEN); full_evidence(&f,1);
    f.evidence.node_removal_returned=f.evidence.anchor_release_returned=f.evidence.fifo_discard_returned=0;
    f.evidence.queue_clear_returned=0; CHECK(umc_service(&f.control)==UMC_PENDING);
    f.evidence.queue_clear_returned=1; CHECK(umc_service(&f.control)==UMC_OK);
}
static void native_ownership_loss_never_completes(void)
{
    struct fixture f;
    init(&f,8); ready(&f); start(&f); source(&f,TOKEN); stop(&f); cleaned(&f,TOKEN);
    full_evidence(&f,1); f.evidence.ownership_confirmed=0;
    CHECK(umc_service(&f.control)==UMC_PENDING && !f.control.status.stop_completed_generation);
    f.evidence.ownership_confirmed=1; CHECK(umc_service(&f.control)==UMC_OK);
}
static void idle_stop_does_not_manufacture_completion(void)
{
    struct fixture f; uint32_t g=99;
    init(&f,8); ready(&f);
    CHECK(umc_request_stop(&f.control,&g)==UMC_ALREADY && g==0);
    CHECK(!f.control.status.stop_completed_generation && !f.cancel_calls && !f.wakes);
}
static void rejected_start_snapshot_survives_restore_preemption(void)
{
    struct fixture f; uint32_t g,x;
    init(&f,8); ready(&f); CHECK(umc_request_start(&f.control,&g)==UMC_PENDING);
    f.prepare_result=-25; f.service_on_leave=1;
    /* A real owner transition runs at the mocked IRQ-restore boundary. The
     * rejection is BUSY at its snapshot even though current state becomes
     * ERROR_PINNED before request_start returns to its caller. */
    CHECK(umc_request_start(&f.control,&x)==UMC_BUSY && x==g);
    CHECK(f.control.status.state==UMC_ERROR_PINNED && f.prepare_calls==1);
}
struct test { const char *name; void (*run)(void); };
int main(void)
{
    const struct test tests[]={
        {"cold_and_resident",cold_and_resident},{"owner_only_service",owner_only_service},
        {"start_admission_and_duplicate",start_admission_and_duplicate},
        {"queued_start_superseded_by_stop",queued_start_superseded_by_stop},
        {"duplicate_stop_and_busy_start",duplicate_stop_and_busy_start},
        {"cancel_zero_is_not_completion",cancel_zero_is_not_completion},
        {"every_native_busy_field_blocks_completion",every_native_busy_field_blocks_completion},
        {"original_remove_release_discard_return_required",original_remove_release_discard_return_required},
        {"stale_generation_cookie_route_and_token",stale_generation_cookie_route_and_token},
        {"event17_F1_admission_closed_until_explicit_restart",admission_stays_closed_during_and_after_stop},
        {"selected_packet_lease_invalidated_before_release",selected_packet_lease_invalidated_before_release},
        {"entire_cleanup_callback_lifetime_blocks_done",entire_cleanup_callback_lifetime_blocks_done},
        {"callback_arriving_during_observation_blocks_done",callback_arriving_during_observation_blocks_done},
        {"stop_wins_over_synchronous_prepare_return",stop_wins_over_synchronous_prepare_return},
        {"synchronous_prepare_publication_is_active",synchronous_prepare_publication_is_active},
        {"wake_failure_preserves_pending_command",wake_failure_preserves_pending_command},
        {"dropped_native_stop_cannot_become_done",dropped_native_stop_cannot_become_done},
        {"cancel_failure_pins_then_explicit_stop_retries",cancel_failure_pins_then_explicit_stop_retries},
        {"prepare_failure_never_claims_armed_or_done",prepare_failure_never_claims_armed_or_done},
        {"restart_new_generation_rejects_old_callbacks",restart_new_generation_rejects_old_callbacks},
        {"remote_cycle_old_anchor_token_is_stale",remote_cycle_old_anchor_token_is_stale},
        {"generation_and_epoch_do_not_wrap",generation_and_epoch_do_not_wrap},
        {"lease_kind_and_start_callback_guards",lease_kind_and_start_callback_guards},
        {"WAV9_requires_native_clear_and_denies_phone_admission",WAV9_requires_native_clear_and_denies_phone_admission},
        {"native_ownership_loss_never_completes",native_ownership_loss_never_completes},
        {"idle_stop_does_not_manufacture_completion",idle_stop_does_not_manufacture_completion},
        {"rejected_start_snapshot_survives_restore_preemption",rejected_start_snapshot_survives_restore_preemption}
    };
    size_t i;
    printf("{\"scope\":\"deterministic host adapter mocks only\",\"cases\":[");
    for(i=0;i<sizeof(tests)/sizeof(tests[0]);i++) {
        tests[i].run(); printf("%s{\"name\":\"%s\",\"passed\":true}",i?",":"",tests[i].name);
    }
    printf("],\"case_count\":%zu,\"all_passed\":true}\n",sizeof(tests)/sizeof(tests[0]));
    return 0;
}
