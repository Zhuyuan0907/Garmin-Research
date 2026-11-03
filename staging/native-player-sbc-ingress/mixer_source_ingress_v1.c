/* NEW source event loop: no embedded packet, no fabricated first PCM.
 * The cold channel setup and allocator/hardware boundaries remain explicit
 * offline contracts; warm-system readiness and SEP publication are separate. */
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
    int r=((int (*)(uint32_t,const void *))0x37bce5u)(tcb,message);
    mh_messages++;return r;
}
static int initialize_stage1(void)
{
    /* Explicit cold-system test caller, NOT suitable for resetting a live
     * navigation system's other channels from a warm loaded module. */
    (void)((int (*)(void))0x277e21u)();
    for(uint32_t i=0;i<18u;i++)(void)((int (*)(uint32_t))0x269f6du)(i);
    int r=((int (*)(uint32_t,uint32_t,uint32_t))0x277d27u)(8,0,1);
    if(r)return r;
    return aas_initialize((uint32_t)(uintptr_t)RECORD,(uint32_t)(uintptr_t)POOL);
}
static int start_first_external_packet(uint32_t ticket)
{
    if(!ticket || mh_started || mh_stream_error)return MCS_REJECTED;
    int r=aas_register(ticket);if(r)return r;
    r=((int (*)(volatile void *))0x277537u)(RECORD+0x1a8u);if(r)return r;
    r=((int (*)(uint32_t,uint32_t))0x3b9b67u)(8,0);if(r)return r;
    mh_handoff_result=ms_validate_completed_sync();
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
static int process_command(uint32_t command)
{
    int r=0;
    if(command==5u){
        r=aas_stop();if(r!=UMC_PENDING)return r;
        if(mh_started){(void)send_mixer(16,0);(void)send_mixer(17,0);(void)send_mixer(18,0);}
        return 0; /* local Stop pending; no hardware STOP_DONE or unload */
    }
    if(!mh_started || mh_stream_error)return MCS_REJECTED;
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
        if(bits&UMC_SOURCE_EVENT)drain_source_event();
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
       (command!=1u && command!=3u && command!=4u && command!=5u && command!=6u && command!=7u)){
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
