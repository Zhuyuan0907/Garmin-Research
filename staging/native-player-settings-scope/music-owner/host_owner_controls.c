/* Actual NEW persistent-loop/glue C with explicit HOST ABI spies. This
 * validates event/order preservation, not original IRQ/kernel/audio/session. */
#include "music_owner.h"
#include "../../../native/sbc-prototype/memory_output.h"
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL:%d:%s\n",__LINE__,#x);exit(1);}}while(0)
#define SOURCE 0x8802000u
extern volatile struct umcn_source_view source_worker_state;
extern void source_worker_entry(void);
extern int source_worker_cancel(void);
struct coordinator {uint32_t initialized,owner,busy,ticket,cancel_pending,stop_sent;
    uint32_t starts,completed,cancelled,discarded,remove_calls,pump_calls,cancel_calls,failures;int32_t result;};
volatile struct coordinator coordinator_state;
volatile struct umcn_owned_view owned_media_control;
volatile struct output_control memory_output_control;
struct ui_music_single native_ui_music_resident;
uint32_t native_ui_music_entry_phase;
static jmp_buf end;
static uint32_t actor,depth,key,waits,pumps,cancels,services,publications,after_calls,links,attaches;
static uint32_t scenario,post_bits[16],post_count;
static int after_result[8];static uint32_t after_cancel[8];
uint32_t music_owner_current(void){CHECK(!depth);return actor;}
uint32_t music_owner_irq_save(void){CHECK(!depth);depth=1;return ++key;}
void music_owner_irq_restore(uint32_t value){CHECK(depth==1&&value==key);depth=0;}
void music_owner_post(uint32_t tcb,uint32_t bits)
{CHECK(!depth&&tcb==SOURCE&&post_count<16);CHECK((source_worker_state.pending&bits)==bits);post_bits[post_count++]=bits;}
uint32_t music_owner_wait(void)
{
    CHECK(!depth);waits++;
    if(scenario==6&&waits==1){source_worker_state.pending=UMC_SOURCE_EVENT|0x20000u;return 0xdeadbeefu;}
    longjmp(end,1);return 0;
}
uint32_t music_owner_construct(uint32_t *d){(void)d;CHECK(0);return 0;}
void music_owner_registry(uint32_t *d){(void)d;CHECK(0);}
int media_coordinator_init(void){CHECK(actor==SOURCE&&!depth);coordinator_state.initialized=1;coordinator_state.owner=SOURCE;return 0;}
int media_coordinator_cancel(void)
{
    CHECK(actor==SOURCE&&!depth&&source_worker_state.cancel_requested);cancels++;
    if(scenario==3&&cancels==1){coordinator_state.cancel_pending=1;coordinator_state.ticket=123;return 1;}
    if(scenario==4){coordinator_state.cancel_pending=1;coordinator_state.ticket=0;return 1;}
    coordinator_state.cancel_pending=0;coordinator_state.ticket=0;coordinator_state.cancelled++;return 0;
}
int media_coordinator_pump(void)
{
    CHECK(actor==SOURCE&&!depth);pumps++;
    if(scenario==4){CHECK(coordinator_state.cancel_pending);coordinator_state.cancel_pending=0;coordinator_state.cancelled++;}
    return 0;
}
int native_ui_music_owner_ready(void){CHECK(actor==SOURCE&&!depth);return UMC_OK;}
int native_ui_music_service_owner(void)
{
    CHECK(actor==SOURCE&&!depth);services++;
    if(scenario==2&&services==1){source_worker_state.pending|=0x20000u;music_owner_post(SOURCE,0x20000u);}
    if(scenario==3)CHECK(source_worker_cancel()==0);
    return UMC_OK;
}
int native_ui_music_note_publication(void){CHECK(actor==SOURCE&&!depth);CHECK(pumps+cancels);publications++;return UMCN_STALE;}
int native_ui_music_after_iteration(int result)
{
    CHECK(actor==SOURCE&&!depth&&after_calls<8);
    CHECK(source_worker_state.last_result==result);after_result[after_calls]=result;
    after_cancel[after_calls]=source_worker_state.cancel_requested;after_calls++;
    return UMCN_NATIVE_BUSY; /* Spies never manufacture a STOP_DONE. */
}
int native_ui_music_linked_bindings(struct umcn_bindings *b){links++;b->channel=8;return UMCN_BINDING_MISSING;}
int native_ui_music_attach_channel8(const struct umcn_bindings *b,uint32_t gui,uint32_t cookie)
{(void)b;(void)gui;(void)cookie;attaches++;CHECK(0);return UMCN_BINDING_MISSING;}
void source_publication_hook(void){}
void source_completion_hook(void){}
static void reset(uint32_t id,uint32_t pending,int attached)
{
    scenario=id;actor=SOURCE;depth=key=waits=pumps=cancels=services=publications=after_calls=links=attaches=post_count=0;
    memset((void *)&source_worker_state,0,sizeof(source_worker_state));
    memset((void *)&coordinator_state,0,sizeof(coordinator_state));
    memset((void *)&owned_media_control,0,sizeof(owned_media_control));
    memset((void *)&music_owner_trace,0,sizeof(music_owner_trace));
    memset(&native_ui_music_resident,0,sizeof(native_ui_music_resident));
    source_worker_state.tcb=SOURCE;source_worker_state.pending=pending;
    native_ui_music_resident.attached=(uint32_t)attached;memory_output_control.active_ticket=21;
}
static void run_loop(void)
{
    if(setjmp(end)==0)source_worker_entry();
    CHECK(!depth&&source_worker_state.entered==1&&source_worker_state.finished_on_stack==0);
    CHECK(memory_output_control.active_ticket==21); /* Glue does not clear native audio. */
}
int main(void)
{
    struct umcn_bindings b;
    reset(0,UMC_SOURCE_EVENT,0);run_loop();
    CHECK(music_owner_trace.control_events==1&&!pumps&&!cancels&&!services&&!after_calls);
    CHECK(music_owner_trace.initializer_returns==1);
    reset(1,UMC_SOURCE_EVENT,1);run_loop();
    CHECK(services==1&&!pumps&&!cancels&&!after_calls);
    reset(2,UMC_SOURCE_EVENT|0x10000u,1);run_loop();
    CHECK(services==1&&pumps==2&&publications==2&&after_calls==2&&post_count==1&&post_bits[0]==0x20000u);
    CHECK(music_owner_trace.control_events==1&&music_owner_trace.ordinary_events==2);
    reset(3,UMC_SOURCE_EVENT,1);run_loop();
    CHECK(services==1&&cancels==2&&after_calls==2&&after_result[0]==1&&after_cancel[0]==1);
    CHECK(after_result[1]==0&&after_cancel[1]==0&&source_worker_state.requests==1);
    CHECK(post_count==1&&post_bits[0]==0x40000u&&source_worker_state.cancel_requested==0);
    reset(4,0x40000u,1);source_worker_state.cancel_requested=1;run_loop();
    CHECK(!services&&cancels==1&&pumps==1&&source_worker_state.pump_calls==2&&after_calls==1);
    CHECK(after_result[0]==0&&after_cancel[0]==0&&coordinator_state.cancelled==1);
    reset(5,0,0);actor=SOURCE+4;
    CHECK(music_owner_control_boundary(UMC_SOURCE_EVENT)==UMC_WRONG_OWNER);
    CHECK(music_owner_after_boundary(0)==UMC_WRONG_OWNER&&!services&&!after_calls);
    actor=SOURCE;memset(&b,0,sizeof(b));
    CHECK(music_owner_bind_on_source(&b,SOURCE+0x1000,1)==UMCN_BINDING_MISSING&&links==1&&!attaches);
    b.channel=9;CHECK(music_owner_bind_on_source(&b,SOURCE+0x1000,1)==UMCN_UNSUPPORTED_ROUTE&&links==1&&!attaches);
    reset(6,0,1);run_loop();
    CHECK(waits==2&&source_worker_state.wake_returns==1&&services==1&&pumps==1&&after_calls==1);
    puts("{\"all_passed\":true,\"group_count\":7,\"groups\":[\"unattached_control_fails_closed\",\"control_only_does_not_pump\",\"mixed_original_events_and_service_post_not_lost\",\"stop_pending_then_actual_return_flag_order\",\"original_empty_cancel_double_pump_preserved\",\"wrong_owner_missing_binding_and_source9_rejected\",\"wait_return_uses_durable_pending_not_raw_return\"],\"native_IRQ_kernel_audio_or_ownership_executed\":false,\"actual_NEW_worker_glue_C_with_HOST_ABI_spies\":true}");
    return 0;
}
