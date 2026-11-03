/* Tests actual new glue + frozen controller/adapter with HOST native-state
 * fixtures. Original addresses, ARM bridge, menu constructors, IRQ/kernel,
 * native audio and physical exclusivity are never executed or established. */
#include "ui_music_single.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL:%d:%s\n",__LINE__,#x); exit(1); } } while (0)
#define SOURCE_TCB 0x8801000u
#define GUI_TCB 0x8802000u
#define COOKIE 0x13528011u
static uint32_t common_calls;
struct fixture {
    struct umcn_runtime_view runtime; struct umcn_source_view source;
    struct umcn_coordinator_view coordinator; struct umcn_output_view output;
    struct umcn_owned_view owned; struct umcn_queue_view queue; struct umcn_worker_view decoder;
    struct umcn_slot_view slots[4];
    uint8_t record[520],mixer[304],driver[84],pool[5*576],state;
    uint32_t current,depth,key,posts,prepares,cancels;
};
static struct fixture f;
int native_app_component_entry(void *loader)
{
    CHECK(loader==(void *)0x1352u); CHECK(native_ui_music_entry_phase==UI_MUSIC_ENTRY_CLAIMED);
    common_calls++;
    /* Models only the documented common zero-span effect on NEW storage.
     * Original TTS or native decoder is not executed on this host. */
    memset(&native_ui_music_resident,0,sizeof(native_ui_music_resident)); return 11;
}
static uint32_t save(void *p)
{ struct fixture *x=p; CHECK(!x->depth); x->depth=1; return ++x->key; }
static void restore(void *p,uint32_t key)
{ struct fixture *x=p; CHECK(x->depth==1 && key==x->key); x->depth=0; }
static uint32_t current(void *p)
{ struct fixture *x=p; CHECK(!x->depth); return x->current; }
static void post(void *p,uint32_t tcb,uint32_t event)
{ struct fixture *x=p; CHECK(!x->depth && tcb==SOURCE_TCB && (x->source.pending&event)==event); x->posts++; }
static int witness(void *p,uint32_t generation,uint32_t token,struct umcn_ownership_witness *out)
{
    struct fixture *x=p; CHECK(!x->depth);
    memset(out,0,sizeof(*out)); out->generation=generation; out->cookie=COOKIE;
    out->channel=8; out->owner_tcb=SOURCE_TCB; out->source_token=token; out->epoch=7;
    /* Explicit mock promises, not a native reservation/future-callback proof. */
    out->native_writers_excluded=out->future_borrowing_callbacks_excluded=1; return 0;
}
static int prepare(void *p,uint32_t generation,uint32_t epoch)
{ struct fixture *x=p; CHECK(!x->depth && x->current==SOURCE_TCB && generation && epoch==7); x->prepares++; return 0; }
static int cancel(void *p)
{
    struct fixture *x=p; CHECK(!x->depth && x->current==SOURCE_TCB);
    x->cancels++; x->source.cancel_requested=1; x->coordinator.cancel_pending=1; x->queue.running=0; return 0;
}
static void completed(void *p,const volatile void *record) { (void)p; (void)record; CHECK(0); }
static struct umcn_bindings bindings(void)
{
    struct umcn_bindings b;
    memset(&b,0,sizeof(b)); b.integration_context=&f; b.irq_save=save; b.irq_restore=restore;
    b.current_task=current; b.native_post=post; b.runtime_cancel=cancel; b.original_source_completed=completed;
    b.ownership_snapshot=witness; b.prepare_session=prepare; b.runtime=&f.runtime; b.source=&f.source;
    b.coordinator=&f.coordinator; b.output=&f.output; b.owned=&f.owned; b.queue=&f.queue;
    b.decoder=&f.decoder; b.slots=f.slots; b.source_record=f.record; b.mixer_record=f.mixer;
    b.driver_record=f.driver; b.source_state=&f.state; b.provider_pool=f.pool;
    b.anchor_address=0x02f91124u; b.channel=8; b.resident_storage_confirmed=1; return b;
}
static void ready_fixture(void)
{
    memset(&f,0,sizeof(f)); f.current=SOURCE_TCB; f.state=1;
    f.runtime.initialized=1; f.runtime.channel=8; f.runtime.source_tcb=SOURCE_TCB;
    f.runtime.decoder_tcb=SOURCE_TCB+0x1000u; f.runtime.source_init_done=1; f.runtime.source_init_owner=SOURCE_TCB;
    f.source.tcb=SOURCE_TCB; f.source.entered=1; f.decoder.tcb=SOURCE_TCB+0x1000u; f.decoder.entered=1;
    f.coordinator.initialized=1; f.coordinator.owner_tcb=SOURCE_TCB;
    f.output.initialized=1; f.output.channel=8; f.owned.initialized=1;
}
int main(void)
{
    struct umcn_bindings b; struct umc_status status; struct umc_lease media={0};
    uint32_t generation,old_generation,before;
    CHECK(native_ui_music_attach_channel8(0,GUI_TCB,COOKIE)==UMC_NOT_READY);
    CHECK(!native_ui_music_admission(1,UMC_GATE_EVENT17));
    CHECK(!common_calls && !native_ui_music_resident.attached);

    native_ui_music_resident.last_action_generation=0xbadu;
    CHECK(native_ui_music_single_entry((void *)0x1352u)==11);
    CHECK(common_calls==1 && native_ui_music_entry_phase==UI_MUSIC_ENTRY_DONE);
    CHECK(native_ui_music_resident.bootstrap_done && !native_ui_music_resident.last_action_generation);
    native_ui_music_resident.last_action_generation=0xfeedu;
    CHECK(native_ui_music_single_entry((void *)0x1352u)==UMCN_PINNED);
    CHECK(common_calls==1 && native_ui_music_resident.last_action_generation==0xfeedu);

    ready_fixture(); b=bindings(); b.channel=9;
    CHECK(native_ui_music_attach_channel8(&b,GUI_TCB,COOKIE)==UMCN_UNSUPPORTED_ROUTE);
    b=bindings(); b.ownership_snapshot=0;
    CHECK(native_ui_music_attach_channel8(&b,GUI_TCB,COOKIE)==UMCN_BINDING_MISSING);
    b=bindings(); f.current=GUI_TCB;
    CHECK(native_ui_music_attach_channel8(&b,GUI_TCB,COOKIE)==UMCN_OWNER_MISMATCH);
    CHECK(!native_ui_music_resident.attached && !native_ui_music_resident.control.magic);

    f.current=SOURCE_TCB;
    CHECK(native_ui_music_attach_channel8(&b,GUI_TCB,COOKIE)==0);
    CHECK(native_ui_music_attach_channel8(&b,GUI_TCB,COOKIE)==UMCN_PINNED);
    f.current=GUI_TCB;
    CHECK(native_ui_music_request_start(&generation)==UMC_NOT_READY);
    CHECK(native_ui_music_menu_appearance(UI_MUSIC_MENU_CONTEXT,0,0,0)==4);
    CHECK(native_ui_music_owner_ready()==UMCN_OWNER_MISMATCH);
    f.current=SOURCE_TCB; CHECK(native_ui_music_owner_ready()==0);
    CHECK(native_ui_music_request_start(&generation)==UMC_WRONG_OWNER);
    CHECK(!f.posts && !f.prepares && !f.cancels);

    f.current=GUI_TCB; before=f.posts;
    native_ui_music_menu_activate(UI_MUSIC_MENU_CONTEXT+1);
    CHECK(f.posts==before);
    CHECK(native_ui_music_menu_appearance(UI_MUSIC_MENU_CONTEXT,0,0,0)==0);
    native_ui_music_menu_activate(UI_MUSIC_MENU_CONTEXT);
    CHECK(f.posts>before && !f.prepares && !f.cancels);
    CHECK(native_ui_music_status(&status)==0 && status.state==UMC_START_QUEUED);
    old_generation=status.generation;
    CHECK(native_ui_music_service_owner()==UMC_WRONG_OWNER);
    f.current=SOURCE_TCB; CHECK(native_ui_music_service_owner()==0);
    CHECK(f.prepares==1 && native_ui_music_status(&status)==0 && status.state==UMC_ARMED);
    CHECK(native_ui_music_media_begin(old_generation,&media)==0 && native_ui_music_media_current(&media));

    f.current=GUI_TCB; native_ui_music_menu_activate(UI_MUSIC_MENU_CONTEXT);
    CHECK(native_ui_music_status(&status)==0 && status.state==UMC_STOPPING && !status.armed);
    CHECK(!f.cancels && !status.stop_completed_generation);
    CHECK(!native_ui_music_admission(old_generation,UMC_GATE_EVENT17));
    CHECK(!native_ui_music_admission(old_generation,UMC_GATE_F1));
    CHECK(!native_ui_music_media_current(&media));
    CHECK(native_ui_music_menu_appearance(UI_MUSIC_MENU_CONTEXT,0,0,0)==4);
    f.current=SOURCE_TCB; CHECK(native_ui_music_service_owner()==UMC_PENDING);
    CHECK(f.cancels==1 && native_ui_music_status(&status)==0 && !status.stop_completed_generation);
    CHECK(native_ui_music_after_iteration(0)==UMCN_NATIVE_BUSY);

    f.current=GUI_TCB;
    CHECK(native_ui_music_request_stop(&generation)==UMC_ALREADY && generation==old_generation);
    CHECK(native_ui_music_request_start(&generation)==UMC_BUSY);
    CHECK(!native_ui_music_resident.control.pending_start && native_ui_music_status(&status)==0 && status.state==UMC_STOPPING);
    f.current=SOURCE_TCB; CHECK(native_ui_music_service_owner()==UMC_PENDING && f.prepares==1 && f.cancels==1);
    /* Real adapter reads these mocked returned-iteration counters/bytes. No
     * fabricated umc_stop_evidence is passed directly to the controller. */
    f.source.pump_calls++; f.source.last_result=0; f.source.cancel_requested=0;
    f.coordinator.cancelled++; f.coordinator.last_result=0; f.coordinator.cancel_pending=0;
    CHECK(native_ui_music_after_iteration(0)==0);
    CHECK(native_ui_music_service_owner()==UMC_PENDING);
    CHECK(native_ui_music_status(&status)==0 && !status.stop_completed_generation && status.media_references==1);
    CHECK(native_ui_music_media_end(&media)==0);
    CHECK(native_ui_music_service_owner()==0);
    CHECK(native_ui_music_status(&status)==0 && status.state==UMC_STOPPED && status.stop_completed_generation==old_generation);
    f.current=GUI_TCB;
    CHECK(native_ui_music_request_start(&generation)==UMC_PENDING);
    f.current=SOURCE_TCB; CHECK(native_ui_music_service_owner()==0);
    CHECK(native_ui_music_status(&status)==0 && status.state==UMC_ARMED && status.generation>old_generation && f.prepares==2);
    CHECK(!native_ui_music_admission(old_generation,UMC_GATE_F1));

    before=native_ui_music_resident.control.status.generation;
    CHECK(native_ui_music_single_entry((void *)0x1352u)==UMCN_PINNED);
    CHECK(common_calls==1 && native_ui_music_resident.attached && native_ui_music_resident.control.status.generation==before);
    CHECK(!f.depth);
    puts("{\"all_passed\":true,\"group_count\":8,\"complete_host_scenarios\":1,\"groups\":[\"cold_no_auto_actions\",\"common_bootstrap_once_survives_zero_span\",\"source9_missing_bindings_wrong_init_owner\",\"GUI_source_owner_and_once_attach\",\"menu_posts_then_source_owner_prepares\",\"stop_does_not_cancel_on_GUI_or_fake_done\",\"restart_rejected_until_returned_cancel_barrier_and_media_release\",\"resident_repeat_entry_and_stale_generation\"],\"native_instructions_or_GUI_constructors_executed\":false}");
    return 0;
}
