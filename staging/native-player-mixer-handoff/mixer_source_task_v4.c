/* NEW kernel-driven resident source actor and original mixer handoff.
 * Source storage is compiled/preallocated; native mixer storage allocation
 * remains an explicitly bounded opaque service in the ROOT runner.
 * Nothing here certifies native ownership, flush/STOP_DONE or installation. */
#include "music_session_guard_v4.h"
#include "memory_output.h"
#include "media_queue.h"
#include <string.h>
#define RECORD ((volatile uint8_t *)0x034e7f48u)
#define POOL ((volatile uint8_t *)0x034e3cf4u)
#define MIXER ((volatile uint8_t *)(0x034e5378u+8u*0x130u))
#define POST ((void (*)(uint32_t,uint32_t))0x2fcf44u)
#define WAIT ((uint32_t (*)(void))0x2fd035u)
extern struct mcs_guard aas_guard;
extern struct umc_controller aas_control;
extern int aas_initialize(uint32_t,uint32_t),aas_register(uint32_t),aas_stop(void);
extern int aas_pcm_publish(const uint8_t *,uint32_t);
extern void aas_status(uint32_t *);
static uint8_t source_stack[16384] __attribute__((aligned(4096),section(".mh_source_stack")));
static uint32_t source_descriptor[5];
static int16_t input_pcm[256];
volatile uint32_t mh_source_tcb,mh_source_entries,mh_initialized,mh_iterations;
volatile uint32_t mh_command,mh_command_completed,mh_pcm_cycle,mh_ticket,mh_messages;
volatile int32_t mh_last_result,mh_initialize_result,mh_handoff_result;
volatile uint32_t mh_selector_bridge_calls,mh_selector_denied,mh_original_selector_returns;
volatile uint32_t mh_last_selector_entry_lr,mh_last_original_selector_result;

static void make_pcm(void)
{
    for(uint32_t i=0;i<256u;i++){
        uint32_t sample=i*181u+mh_pcm_cycle*1207u;
        while(sample>=60001u)sample-=60001u;
        input_pcm[i]=(int16_t)(sample-30000u);
    }
}
static int publish_pcm(void)
{
    make_pcm();int t=aas_pcm_publish((const uint8_t *)input_pcm,sizeof(input_pcm));
    if(t>0){mh_ticket=(uint32_t)t;mh_pcm_cycle++;}
    return t>0?0:t;
}
static int send_mixer(uint32_t kind,uint32_t argument)
{
    uint32_t message[3]={kind | (8u<<8),argument,0};
    uint32_t tcb=*(volatile uint32_t *)(MIXER+0x78u);
    if(!tcb || tcb!=aas_guard.mixer_tcb)return MCS_REJECTED;
    /* Exact native message ABI: type byte0, channel byte1, argument word1.
     * The original send copies all12 bytes into this TCB's real queue. */
    int r=((int (*)(uint32_t,const void *))0x37bce5u)(tcb,message);
    mh_messages++;return r;
}
static int initialize_source(void)
{
    /* Actual native channel mapping/global queues/profile, no host pointer
     * seed for native source fields or mixer source identity. */
    (void)((int (*)(void))0x277e21u)();
    for(uint32_t i=0;i<18u;i++)(void)((int (*)(uint32_t))0x269f6du)(i);
    int r=((int (*)(uint32_t,uint32_t,uint32_t))0x277d27u)(8,0,1);
    if(r)return r;
    r=aas_initialize((uint32_t)(uintptr_t)RECORD,(uint32_t)(uintptr_t)POOL);
    if(r)return r;
    r=publish_pcm();if(r)return r;
    r=aas_register(mh_ticket);if(r)return r;
    r=((int (*)(volatile void *))0x277537u)(RECORD+0x1a8u);if(r)return r;
    /* This initializes actual M+64 descriptor/TCB and queues message13; the
     * lower-priority mixer runs only after this source grants and blocks. */
    r=((int (*)(uint32_t,uint32_t))0x3b9b67u)(8,0);if(r)return r;
    mh_handoff_result=mcs_handoff_source_to_mixer(&aas_guard);
    return mh_handoff_result;
}
static int process_command(uint32_t command)
{
    int r=0;
    if(command==1u){ /* initial copied ticket4, normal full-pull path */
        (void)send_mixer(18,0);(void)send_mixer(18,0);
    }else if(command>=2u && command<=4u){
        r=publish_pcm();if(r)return r;
        if(command==3u)(void)send_mixer(13,0); /* true mixer reselection */
        if(command==4u){
            /* Original SEEK_SEND_RESET plus RESET_DONE path; hardware reset
             * service is explicitly bounded in the ROOT guest. */
            (void)send_mixer(16,0);(void)send_mixer(17,0);
            (void)send_mixer(18,0);
        }else{(void)send_mixer(18,0);(void)send_mixer(18,0);}
    }else if(command==5u){
        r=aas_stop();if(r!=UMC_PENDING)return r;
        (void)send_mixer(16,0);(void)send_mixer(17,0);(void)send_mixer(18,0);
        r=0;
    }else if(command==6u){
        /* Repeating profile0 takes original277D76's cached-profile branch
         * and leaves callbacks untouched. A real transition to profile1
         * returns10, then restoring profile0 returns0 and rewrites callbacks.
         * This also executes original old-list cleanup; no host field seed. */
        r=((int (*)(uint32_t,uint32_t,uint32_t))0x277d27u)(8,1,1);
        if(r!=10)return r ? r : MCS_REJECTED;
        r=((int (*)(uint32_t,uint32_t,uint32_t))0x277d27u)(8,0,1);
        if(r)return r;
        (void)send_mixer(18,0);
    }else return MCS_REJECTED;
    return r;
}
void mh_source_entry(void)
{
    mh_source_entries++;
    mh_initialize_result=initialize_source();mh_initialized=1;
    for(;;){
        uint32_t bits=WAIT();(void)bits;
        uint32_t saved=((uint32_t (*)(void))0x21b6ccu)();
        uint32_t command=mh_command;mh_command=0;
        ((void (*)(uint32_t))0x21b6dcu)(saved);
        if(command){mh_iterations++;mh_last_result=process_command(command);
            mh_command_completed=command;}
    }
}
uint32_t mh_boot_source(void)
{
    if(mh_source_tcb)return 0;
    source_descriptor[0]=(uint32_t)(uintptr_t)mh_source_entry;
    source_descriptor[1]=0;
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
       command<1u || command>6u){((void (*)(uint32_t))0x21b6dcu)(saved);return MCS_REJECTED;}
    mh_command=command;
    ((void (*)(uint32_t))0x21b6dcu)(saved);
    POST(mh_source_tcb,1u);return 0;
}
uint32_t mh_selector_bridge(uint32_t channel,uint32_t argument)
{
    struct mcs_event_frame borrow={0};
    uint32_t entry_lr=(uint32_t)(uintptr_t)__builtin_return_address(0);
    mh_selector_bridge_calls++;mh_last_selector_entry_lr=entry_lr;
    int r=mcs_mixer_selector_begin(channel,entry_lr,&borrow);
    if(r){mh_selector_denied++;return 0;}
    /* Entire original selector/factory/prepare executes. The original result
     * is preserved; post-selector binding result is separately recorded. */
    uint32_t result=((uint32_t (*)(uint32_t,uint32_t))0x2f9f2fu)(channel,argument);
    mh_original_selector_returns++;mh_last_original_selector_result=result;
    (void)mcs_mixer_selector_after_original(channel,&borrow,(int)result);
    return result;
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
