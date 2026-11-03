/* NEW source event loop: no embedded packet, no fabricated first PCM.
 * Native preexisting-channel structural admission replaces global cold reset.
 * Durable ownership and actual live navigation readiness remain unproven. */
#include "music_session_guard_v4.h"
#include "memory_output.h"
#include "media_queue.h"
#include "decoder.h"
#define RECORD ((volatile uint8_t *)0x034e7f48u)
#define POOL ((volatile uint8_t *)0x034e3cf4u)
#define MIXER ((volatile uint8_t *)(0x034e5378u+8u*0x130u))
#define POST ((void (*)(uint32_t,uint32_t))0x2fcf44u)
#define WAIT ((uint32_t (*)(void))0x2fd035u)
extern struct mcs_guard aas_guard;
extern int ns_capture_registration(void),ns_bind_selected(void),ns_retire_step(void);
volatile uint32_t mh_stop_requested,mh_stop_on_capacity;
extern struct umc_controller aas_control;
extern int aas_initialize(uint32_t,uint32_t),aas_register(uint32_t),aas_stop(void);
extern int ms_validate_completed_sync(void),owned_media_output_ready(void);
extern uint32_t aas_packet_ticket(void);
extern void aas_status(uint32_t *);
extern volatile uint32_t sbi_source_events,sbi_processed,sbi_errors;
extern volatile int32_t sbi_last_decode_error;
static uint8_t source_stack[16384] __attribute__((aligned(4096),section(".mh_source_stack")));
static uint32_t source_descriptor[5];
volatile uint32_t mh_source_tcb,mh_source_entries,mh_initialized,mh_iterations;
volatile uint32_t mh_command,mh_command_completed,mh_pcm_cycle,mh_ticket,mh_messages;
volatile uint32_t mh_started,mh_stream_error,mh_empty_wakes,mh_deferred_wakes;
volatile int32_t mh_last_result,mh_initialize_result,mh_handoff_result;
volatile uint32_t mh_selector_bridge_calls,mh_selector_denied,mh_original_selector_returns;
volatile uint32_t mh_last_selector_entry_lr,mh_last_original_selector_result;

static int send_mixer(uint32_t kind,uint32_t argument)
{
    uint32_t message[3]={kind | (8u<<8),argument,0};
    uint32_t tcb=*(volatile uint32_t *)(MIXER+0x78u);
    if(!tcb || tcb!=aas_guard.mixer_tcb)return MCS_REJECTED;
    /* Original37BCE4 is a void copied-queue transport; r0 is not a
     * defined zero-success status. Actual native FIFO execution is verified
     * separately. Local0 means valid target and invocation fully returned. */
    ((void (*)(uint32_t,const void *))0x37bce5u)(tcb,message);
    mh_messages++;return 0;
}

/* Structural admission, NOT a durable native channel ownership witness.
 * Acquire the original channel's profile mutex without waiting: IRQ masking
 * protects the free-owner test and native acquisition from another task.
 * No native condition, queue, channel or profile is reset/constructed here.
 * Other native direct queue/provider callers remain outside this boundary. */
volatile uint32_t mw_attempts,mw_attaches,mw_denials,mw_last_reason;
static uint32_t mw_word(const volatile uint8_t *p,uint32_t offset)
{ return *(const volatile uint32_t *)(p+offset); }
static int mw_structural_check(void)
{
    uint32_t timer=*(volatile uint32_t *)0x00f090a0u;
    if(!timer || mw_word(RECORD,0x88u)!=0xd4475b83u ||
       mw_word(RECORD,0x78u)!=timer)return -303;
    if(RECORD[0]!=8u || RECORD[0x1f8u]!=8u || RECORD[0x1a8u]!=8u)return -304;
    if(RECORD[0x15du]!=0u || mw_word(RECORD,0x160u)!=0x277c6bu)return -305;
    if(mw_word(RECORD,0x1acu)!=0xffffu ||
       *(volatile uint16_t *)(RECORD+0x1c0u) ||
       *(volatile uint32_t *)(0x034e68d8u+8u*4u))return -306;
    if(MIXER[0x84u])return -307;
    if(RECORD[2])return -308;
    for(uint32_t i=0;i<68u;i++)if(RECORD[0xf4u+i])return -308;
    if(*(volatile uint8_t *)(0x034e9398u+8u)!=1u)return -309;
    return 0;
}
int mw_attach_stage1(void)
{
    uint32_t flags,actor,owner;int r;
    mw_attempts++;
    /* Existing context check only covers normal task context, not ownership. */
    extern int mcs_native_normal_context(void *);
    if(!mcs_native_normal_context(0)){r=-301;goto denied;}
    actor=((uint32_t (*)(void))0x358d25u)();
    flags=((uint32_t (*)(void))0x21b6ccu)();
    owner=mw_word(RECORD,0x1d0u)|mw_word(RECORD,0x1e8u)|mw_word(RECORD,0x60u);
    if(!actor || owner){
        ((void (*)(uint32_t))0x21b6dcu)(flags);r=-302;goto denied;
    }
    /* Exact locks: profile/outer registration +1C8, direct list writer
     * +1E0, provider/source record +58. All checked free under IRQ exclusion.
     * No wait or lock-order contention is introduced by this acquisition. */
    ((void (*)(volatile void *))0x3009a1u)(RECORD+0x1c8u);
    ((void (*)(volatile void *))0x3009a1u)(RECORD+0x1e0u);
    ((void (*)(volatile void *))0x3009a1u)(RECORD+0x58u);
    r=mw_structural_check();
    extern int rg_claim_locked(uint32_t);
    extern void rg_validation_test_hook(void),rg_abandon_unpublished(void);
    if(!r)r=rg_claim_locked(actor);
    ((void (*)(uint32_t))0x21b6dcu)(flags);
    /* Hook absent unless the offline test task has been explicitly created. */
    if(!r)rg_validation_test_hook();
    if(!r)r=aas_initialize((uint32_t)(uintptr_t)RECORD,(uint32_t)(uintptr_t)POOL);
    if(r)rg_abandon_unpublished();
    ((void (*)(volatile void *))0x3008b1u)(RECORD+0x58u);
    ((void (*)(volatile void *))0x3008b1u)(RECORD+0x1e0u);
    ((void (*)(volatile void *))0x3008b1u)(RECORD+0x1c8u);
    if(r)goto denied;
    mw_attaches++;mw_last_reason=0;return 0;
denied:
    mw_denials++;mw_last_reason=(uint32_t)r;return r;
}
static int initialize_stage1(void)
{ return mw_attach_stage1(); }
static int start_first_external_packet(uint32_t ticket)
{
    if(!ticket || mh_started || mh_stream_error)return MCS_REJECTED;
    int r=aas_register(ticket);if(r)return r;
    r=ns_capture_registration();if(r)return r;
    r=((int (*)(volatile void *))0x277537u)(RECORD+0x1a8u);if(r)return r;
    r=((int (*)(uint32_t,uint32_t))0x3b9b67u)(8,0);if(r)return r;
    mh_handoff_result=ms_validate_completed_sync();
    if(!mh_handoff_result)mh_handoff_result=ns_bind_selected();
    if(!mh_handoff_result)mh_started=1;
    return mh_handoff_result;
}
static void drain_source_event(void)
{
    sbi_source_events++;
    if(mh_initialize_result || mh_stream_error || !media_queue_control.running)return;
    /* Four copied queue slots bound one wake's work. Full output means wait
     * for an actual mixer-reader capacity event, never retry in a spin. */
    for(uint32_t work=0;work<4u;work++){
        if(!media_queue_control.count){mh_empty_wakes++;break;}
        if(!owned_media_output_ready()){mh_deferred_wakes++;break;}
        int r=media_queue_step();
        if(r==1 || r==2){mh_deferred_wakes++;break;}
        sbi_processed++;sbi_last_decode_error=r;
        if(r){sbi_errors++;continue;}
        uint32_t ticket=aas_packet_ticket();
        if(!ticket){mh_stream_error=1;break;}
        mh_ticket=ticket;mh_pcm_cycle++;
        if(!mh_started){
            r=start_first_external_packet(ticket);
            if(r){mh_stream_error=1;mh_handoff_result=r;break;}
        }
        /* Actual native driver activation owns this byte. No activation is
         * manufactured here. New data only asks an already active mixer. */
        if(*(volatile uint8_t *)(MIXER+0x84u)){
            r=send_mixer(18,0);
            if(r){mh_stream_error=1;mh_last_result=r;break;}
        }
    }
}
volatile uint32_t mh_remote_paused,mh_remote_pause_epoch;
volatile uint32_t mh_remote_pause_requests,mh_remote_resume_requests,mh_remote_paused_reads,mh_remote_paused_bytes;

static int process_command(uint32_t command)
{
    int r=0;
    if(command==8u || command==9u){
        uint32_t saved=((uint32_t (*)(void))0x21b6ccu)();
        if(!media_queue_control.running || mh_remote_pause_epoch==UINT32_MAX ||
           *(volatile uint32_t *)(aas_guard.source_record+0x160u)!=(uint32_t)(uintptr_t)mcs_queue_bridge){
            ((void (*)(uint32_t))0x21b6dcu)(saved);return MCS_REJECTED;
        }
        mh_remote_paused=command==8u;mh_remote_pause_epoch++;
        if(command==8u)mh_remote_pause_requests++;else mh_remote_resume_requests++;
        ((void (*)(uint32_t))0x21b6dcu)(saved);
        if(command==9u && mh_started){(void)send_mixer(18,0);}
        return 0;
    }
    if(command==5u){
        r=aas_stop();if(r!=UMC_PENDING && r!=UMC_ALREADY)return r;
        r=ns_retire_step();mh_stop_requested=(r==UMC_PENDING);return r;
        /* Native15/19/20 and full list removal replace the old16/17/18 path.
         * Claim/guard/tasks remain pinned; no STOP_DONE or safe unload. */
    }
    if(aas_control.status.state==UMC_STOPPING || !mh_started || mh_stream_error)return MCS_REJECTED;
    if(command==10u){mh_stop_on_capacity=1;return 0;}
    if(command==1u){(void)send_mixer(18,0);(void)send_mixer(18,0);}
    else if(command==3u){(void)send_mixer(13,0);(void)send_mixer(18,0);}
    else if(command==4u){(void)send_mixer(16,0);(void)send_mixer(17,0);(void)send_mixer(18,0);}
    else if(command==6u){
        r=((int (*)(uint32_t,uint32_t,uint32_t))0x277d27u)(8,1,1);
        if(r!=10)return r?r:MCS_REJECTED;
        r=((int (*)(uint32_t,uint32_t,uint32_t))0x277d27u)(8,0,1);
        if(r)return r;
        (void)send_mixer(18,0);
    }else if(command==7u){
        r=((int (*)(uint32_t,uint32_t))0x3b9b67u)(8,0);
        if(!r)r=ms_validate_completed_sync();
    }else return MCS_REJECTED;
    return r;
}
void mh_source_entry(void)
{
    mh_source_entries++;
    mh_initialize_result=initialize_stage1();mh_initialized=1;
    for(;;){
        uint32_t bits=WAIT();
        uint32_t saved=((uint32_t (*)(void))0x21b6ccu)();
        uint32_t command=mh_command;mh_command=0;
        ((void (*)(uint32_t))0x21b6dcu)(saved);
        /* Stop/commands precede data if their event bits arrive together. */
        if(command){mh_iterations++;mh_last_result=process_command(command);mh_command_completed=command;}
        /* Offline command10 arms an actual Source capacity-wake Stop while
         * Mixer still owns its real full frame. No HOST lease is synthesized. */
        if(mh_stop_on_capacity && aas_guard.borrow && media_queue_control.running){
            mh_stop_on_capacity=0;mh_last_result=process_command(5u);mh_command_completed=5u;
        }
        if(mh_stop_requested){
            int r=ns_retire_step();
            if(r!=UMC_PENDING){mh_last_result=r;mh_stop_requested=0;}
        }
        if((bits&UMC_SOURCE_EVENT) || command==9u){if(!mh_remote_paused)drain_source_event();}
    }
}
uint32_t mh_boot_source(void)
{
    if(mh_source_tcb)return 0;
    source_descriptor[0]=(uint32_t)(uintptr_t)mh_source_entry;source_descriptor[1]=0;
    source_descriptor[2]=(uint32_t)(uintptr_t)(source_stack+sizeof(source_stack));
    source_descriptor[3]=12u<<16;source_descriptor[4]=0;
    mh_source_tcb=((uint32_t (*)(const void *))0x358bf9u)(source_descriptor);
    if(!mh_source_tcb)return 0;
    (void)((int (*)(const void *))0x2fbbbfu)(source_descriptor);
    POST(mh_source_tcb,1u);return mh_source_tcb;
}
int mh_request_command(uint32_t command)
{
    uint32_t saved=((uint32_t (*)(void))0x21b6ccu)();
    if(!mh_source_tcb || !mh_initialized || mh_initialize_result || mh_command ||
       (command!=1u && command!=3u && command!=4u && command!=5u && command!=6u && command!=7u && command!=8u && command!=9u && command!=10u)){
        ((void (*)(uint32_t))0x21b6dcu)(saved);return MCS_REJECTED;
    }
    if((command==8u || command==9u) && (!media_queue_control.running ||
       *(volatile uint32_t *)(aas_guard.source_record+0x160u)!=(uint32_t)(uintptr_t)mcs_queue_bridge)){
        ((void (*)(uint32_t))0x21b6dcu)(saved);return MCS_REJECTED;
    }
    mh_command=command;((void (*)(uint32_t))0x21b6dcu)(saved);
    POST(mh_source_tcb,1u);return 0;
}
uint32_t mh_selector_bridge(uint32_t channel,uint32_t argument)
{
    struct mcs_event_frame borrow={0};
    uint32_t entry_lr=(uint32_t)(uintptr_t)__builtin_return_address(0);
    mh_selector_bridge_calls++;mh_last_selector_entry_lr=entry_lr;
    int r=mcs_mixer_selector_begin(channel,entry_lr,&borrow);
    if(r){mh_selector_denied++;return 0;}
    uint32_t result=((uint32_t (*)(uint32_t,uint32_t))0x2f9f2fu)(channel,argument);
    mh_original_selector_returns++;mh_last_original_selector_result=result;
    (void)mcs_mixer_selector_after_original(channel,&borrow,(int)result);return result;
}
void mh_status(uint32_t *p)
{
    aas_status(p);
    p[30]=mh_source_tcb;p[31]=mh_source_entries;p[32]=mh_initialized;
    p[33]=(uint32_t)mh_initialize_result;p[34]=(uint32_t)mh_handoff_result;
    p[35]=aas_guard.owner;p[36]=aas_guard.mixer_tcb;p[37]=aas_guard.mixer_session;
    p[38]=aas_guard.mixer_generation;p[39]=aas_guard.mixer_admission_epoch;
    p[40]=aas_guard.mixer_handoffs;p[41]=aas_guard.mixer_revocations;
    p[42]=aas_guard.selector_entries;p[43]=aas_guard.selector_returns;
    p[44]=(uint32_t)aas_guard.last_selector_bind_result;
    p[45]=mh_command_completed;p[46]=(uint32_t)mh_last_result;
    p[47]=mh_pcm_cycle;p[48]=mh_ticket;p[49]=mh_messages;
    p[50]=mh_selector_bridge_calls;p[51]=mh_selector_denied;
    p[52]=mh_original_selector_returns;p[53]=mh_last_selector_entry_lr;
    p[54]=mh_last_original_selector_result;
}
const uint32_t mh_offsets[] __attribute__((used,section(".mh_offsets")))={
    offsetof(struct mcs_guard,mixer_tcb),offsetof(struct mcs_guard,mixer_session),
    offsetof(struct mcs_guard,mixer_generation),offsetof(struct mcs_guard,mixer_admission_epoch),
    offsetof(struct mcs_guard,pull_entry_lr)
};
