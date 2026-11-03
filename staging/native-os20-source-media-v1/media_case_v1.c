/* One new native producer task; copied packet reaches the true OS20 Source.
 * The idle caller supplies explicit output-driver RAM fixtures and one copied
 * mixer message. Only the original scheduled mixer performs the reader pull. */
#include <stdint.h>
#include "media_addresses_v1.h"
#include "frame_v1.h"
typedef uint32_t (*current_fn)(void);
typedef uint32_t (*wait_fn)(void);
typedef void (*post_fn)(uint32_t,uint32_t);
#define CURRENT() (((current_fn)0x358d25u)())
#define WAIT() (((wait_fn)0x2fd035u)())
#define POST(t,e) (((post_fn)0x2fcf44u)((t),(e)))
#define W(a) (*(volatile uint32_t *)(a))
#define B(a) (*(volatile uint8_t *)(a))
#define MIXER 0x034e5cf8u
#define DESCRIPTOR 0x09800020u
#define BUFFER 0x09801020u
#define SCRATCH 0x09803f00u
struct media_case_result_v1 {
 uint32_t bootstrap_actor,producer_tcb,producer_actor,producer_entries,packet_copied;
 int32_t ingress_result;
 uint32_t packet_poisoned,producer_parked,source_started,source_tcb,mixer_tcb;
 uint32_t initialize_completed,driver_fixture_installed,message_sent,after_message_actor;
 uint32_t output_write_pointer,output_bytes,source_error,source_initialize_status,finished,fail_reason;
};
volatile struct media_case_result_v1 media_case_result_v1;
static uint8_t packet[85];
static uint8_t producer_stack[16384] __attribute__((aligned(4096),section(".producer_stack")));
static uint32_t producer_descriptor[5];
__attribute__((noinline))void media_case_failure_v1(void){for(;;)__asm__ volatile("":::"memory");}
static void check(int test,uint32_t reason){if(!test){media_case_result_v1.fail_reason=reason;media_case_failure_v1();}}
void media_case_producer_v1(void){
 media_case_result_v1.producer_actor=CURRENT();media_case_result_v1.producer_entries++;
 check(media_case_result_v1.producer_actor==media_case_result_v1.producer_tcb,1);
 for(uint32_t i=0;i<85;i++)packet[i]=FRAME_PACKET_V1[i];
 media_case_result_v1.packet_copied=1;
 media_case_result_v1.ingress_result=((int(*)(uint32_t,uint32_t,const uint8_t*,uint32_t))SBI_RECEIVE)(0xf1,0,packet,85);
 check(!media_case_result_v1.ingress_result,2);
 for(uint32_t i=0;i<85;i++)packet[i]=0xa5;
 media_case_result_v1.packet_poisoned=1;media_case_result_v1.producer_parked=1;
 for(;;)(void)WAIT();
}
void media_case_bootstrap_v1(void){
 media_case_result_v1.bootstrap_actor=CURRENT();
 check(W(MH_INITIALIZED)==1 && !W(MH_INITIALIZE_RESULT) && W(MH_READY_POST_RETURNS)==1,3);
 producer_descriptor[0]=(uint32_t)(uintptr_t)media_case_producer_v1;
 producer_descriptor[1]=0;producer_descriptor[2]=(uint32_t)(uintptr_t)(producer_stack+sizeof(producer_stack));
 producer_descriptor[3]=16u<<16;producer_descriptor[4]=0;
 media_case_result_v1.producer_tcb=((uint32_t(*)(uint32_t*))0x358bf9u)(producer_descriptor);
 check(media_case_result_v1.producer_tcb!=0,4);
 ((void(*)(uint32_t*))0x2fbbbfu)(producer_descriptor);
 POST(media_case_result_v1.producer_tcb,8);
 /* Producer16 and Source89/Mixer23 preempt this actual idle240 caller.
  * This POST returns after they run/block, without a host context restore. */
 check(media_case_result_v1.packet_poisoned && media_case_result_v1.producer_parked,5);
 media_case_result_v1.source_tcb=W(MH_SOURCE_TCB);
 media_case_result_v1.source_started=W(MH_STARTED);
 media_case_result_v1.source_error=W(MH_STREAM_ERROR);
 media_case_result_v1.source_initialize_status=W(MH_INITIALIZE_RESULT);
 media_case_result_v1.initialize_completed=W(MS_SYNC_COMPLETED);
 media_case_result_v1.mixer_tcb=W(MIXER+0x78u);
 check(media_case_result_v1.source_started==1 && !media_case_result_v1.source_error &&
       media_case_result_v1.initialize_completed==1 && media_case_result_v1.mixer_tcb,6);
 /* Explicit lower output-driver memory fixture. No hardware activation or
  * speaker acceptance is inferred from this flag or resulting RAM bytes. */
 for(uint32_t i=0;i<2048;i++)B(BUFFER+i)=0xa5;
 for(uint32_t i=0;i<256;i++)B(SCRATCH+i)=0xa5;
 for(uint32_t i=0;i<9;i++)W(DESCRIPTOR+i*4u)=0;
 W(DESCRIPTOR+4)=BUFFER;W(DESCRIPTOR+8)=2048;
 W(DESCRIPTOR+12)=BUFFER+1984;W(DESCRIPTOR+16)=BUFFER+1984;
 W(MIXER)=DESCRIPTOR;W(MIXER+4)=256;W(MIXER+0xb4)=SCRATCH;
 B(MIXER+0x7f)=0;B(MIXER+0x7e)=0;B(MIXER+0x84)=1;
 media_case_result_v1.driver_fixture_installed=1;
 uint32_t message[3]={18u|(8u<<8),0,0};
 ((void(*)(uint32_t,const void*))0x37bce5u)(media_case_result_v1.mixer_tcb,message);
 media_case_result_v1.message_sent=1;media_case_result_v1.after_message_actor=CURRENT();
 media_case_result_v1.output_write_pointer=W(DESCRIPTOR+16);
 uint32_t pointer=media_case_result_v1.output_write_pointer;
 media_case_result_v1.output_bytes=pointer>=BUFFER+1984?pointer-(BUFFER+1984):pointer+64-BUFFER;
 check(media_case_result_v1.output_bytes==256,7);
 check(media_case_result_v1.after_message_actor==media_case_result_v1.bootstrap_actor,8);
 media_case_result_v1.finished=1;
}
