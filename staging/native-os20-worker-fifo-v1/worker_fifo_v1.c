/* New scope: original scheduled OS20 worker -> existing copied queue/PCM FIFO.
 * Controller consumer is a private fixture, not the original mixer or DAC.
 * STOP closes queue admission; module, workspace, adapter and held PCM stay.
 */
#include "worker_fifo_v1.h"
#include <string.h>
typedef uint32_t (*wait_fn)(void);
typedef void (*post_fn)(uint32_t,uint32_t);
typedef uint32_t (*current_fn)(void);
#define WAIT() (((wait_fn)0x002fd035u)())
#define POST(t,e) (((post_fn)0x002fcf44u)((t),(e)))
#define CURRENT() (((current_fn)0x00358d25u)())
#define JOB ((volatile struct resident_music_v1 *)0x09060000u)
#define FRAMES ((const uint8_t *)0x09061000u)
#define OUTPUT ((uint8_t *)0x09062000u)
volatile struct fifo_observations_v1 fifo_observations_v1;
static uint8_t packet[85];

__attribute__((noinline)) void fifo_failure_v1(void) {
    for(;;)__asm__ volatile("" ::: "memory");
}
static void check(int condition,uint32_t reason) {
    if(!condition){JOB->controller_failure=reason;fifo_failure_v1();}
}
void fifo_worker_core_v1(void *argument) {
    volatile struct resident_music_v1 *job=argument;
    if(job!=JOB || job->magic!=0x53425231u)return;
    job->observed_argument=(uint32_t)argument;
    job->worker_entries++;
    job->worker_tcb_observed=CURRENT();
    fifo_observations_v1.worker_initialize_status=owned_media_init(8);
    fifo_observations_v1.worker_initialize_returns++;
    job->notifications++;
    POST(job->controller_tcb,0x400u);
    job->notify_returns++;
    for(;;){
        (void)WAIT();job->wait_returns++;
        uint32_t sequence=job->request_seq;
        if(sequence==job->completed_seq)continue;
        switch(job->operation){
        case RESIDENT_START:
            if(job->active){job->status=-16;job->active_start_rejections++;}
            else if(owned_media_next()){job->status=-25;}
            else{
                job->status=media_queue_begin();
                if(!job->status){job->resets++;job->generation++;job->active=1;}
            }
            break;
        case RESIDENT_DECODE: /* Step the COPIED queue, not job->input. */
            if(!job->active){job->status=-11;job->stopped_rejections++;}
            else{
                job->status=media_queue_step();
                if(!job->status){
                    uint32_t index=job->decode_successes++;
                    if(index<4){
                        fifo_observations_v1.tickets[index]=owned_media_next();
                        fifo_observations_v1.worker_producer_actors[index]=CURRENT();
                    }
                }
            }
            break;
        case RESIDENT_STOP:
            fifo_observations_v1.queue_epoch_before_stop=media_queue_control.epoch;
            job->status=media_queue_stop();job->active=0;job->stops++;
            fifo_observations_v1.queue_epoch_after_stop=media_queue_control.epoch;
            break;
        default:job->status=-22;break;
        }
        job->completed_seq=sequence;job->notifications++;
        POST(job->controller_tcb,0x400u);job->notify_returns++;
    }
}
static uint32_t receive(void){
    uint32_t event=WAIT();check(JOB->event_count<16,1);
    JOB->events[JOB->event_count++]=event;return event;
}
static void command(uint32_t operation,int32_t expected){
    JOB->operation=operation;
    uint32_t sequence=JOB->request_seq+1;JOB->request_seq=sequence;
    uint32_t worker=*(volatile uint32_t *)(JOB->adapter+48u);
    check(worker==JOB->worker_tcb_observed,2);
    POST(worker,1);check(receive()==0x400u,3);
    check(JOB->completed_seq==sequence,4);check(JOB->status==expected,5);
}
static void queue_frame(uint32_t frame){
    memset(packet,0,sizeof(packet));packet[0]=0x80;packet[1]=0x60;
    packet[3]=(uint8_t)frame;packet[12]=1;
    memcpy(packet+13,FRAMES+frame*72u,72);
    check(media_queue_callback(0xf1,0,0,packet,sizeof(packet))==0,11);
    fifo_observations_v1.packet_copies++;
    fifo_observations_v1.packet_count_at_poison[frame]=media_queue_control.count;
    memset(packet,0xa5,sizeof(packet));
    fifo_observations_v1.packet_poisonings++;
}
static void read_fifo(uint32_t index,uint32_t destination,uint32_t capacity){
    uint32_t ticket=owned_media_next();check(ticket!=0,12);
    fifo_observations_v1.controller_consumer_actors[index]=CURRENT();
    uint32_t count=continuous_media_read(OUTPUT+destination,capacity);
    fifo_observations_v1.read_returns[index]=count;
    fifo_observations_v1.count_after_read[index]=owned_media_control.count;
    fifo_observations_v1.offset_after_read[index]=continuous_media_control.offset;
    fifo_observations_v1.slot_state_after_read[index]=memory_output_slots[ticket&3u].state;
    fifo_observations_v1.slot_inflight_after_read[index]=memory_output_slots[ticket&3u].in_flight;
    check(count==capacity,13);
}
void fifo_controller_core_v1(void){
    JOB->controller_tcb_observed=CURRENT();
    check(JOB->controller_tcb_observed==JOB->controller_tcb,6);
    check(receive()==0x400u,7);
    check(fifo_observations_v1.worker_initialize_returns==1 &&
          fifo_observations_v1.worker_initialize_status==0,14);
    JOB->idle_pulse_request=1;check(receive()==0x800u,8);
    command(RESIDENT_START,0);command(RESIDENT_START,-16);
    queue_frame(0);command(RESIDENT_DECODE,0);
    fifo_observations_v1.odd_read=(int32_t)continuous_media_read(OUTPUT+1024,3);
    fifo_observations_v1.null_read=(int32_t)continuous_media_read(0,128);
    read_fifo(0,0,128);check(owned_media_control.count==1,15);
    read_fifo(1,128,128);check(owned_media_control.count==0,16);
    queue_frame(1);command(RESIDENT_DECODE,0);
    fifo_observations_v1.stale_discard=memory_output_discard(4);
    check(fifo_observations_v1.stale_discard==-28 && owned_media_next()==8,17);
    read_fifo(2,256,256);
    command(RESIDENT_STOP,0);
    fifo_observations_v1.stopped_callback=media_queue_callback(0xf1,0,0,packet,sizeof(packet));
    check(fifo_observations_v1.stopped_callback==-22,18);
    command(RESIDENT_DECODE,-11);command(RESIDENT_START,0);
    queue_frame(2);command(RESIDENT_DECODE,0);read_fifo(3,512,256);
    queue_frame(3);command(RESIDENT_DECODE,0);read_fifo(4,768,128);
    command(RESIDENT_STOP,0);
    check(continuous_media_read(OUTPUT+896,128)==0,19);
    command(RESIDENT_START,-25);fifo_observations_v1.pending_start=JOB->status;
    command(RESIDENT_DECODE,-11);
    fifo_observations_v1.held_ticket=owned_media_next();
    fifo_observations_v1.held_bytes=memory_output_slots[0].bytes;
    fifo_observations_v1.held_state=memory_output_slots[0].state;
    fifo_observations_v1.held_offset=continuous_media_control.offset;
    fifo_observations_v1.held_count=owned_media_control.count;
    fifo_observations_v1.observed_slot_generation=memory_output_control.generation;
    check(JOB->generation==2 && JOB->resets==2 && JOB->stops==2,9);
    check(JOB->decode_successes==4 && JOB->worker_entries==1,10);
    JOB->controller_finished=1;for(;;)(void)WAIT();
}
__attribute__((noinline)) void fifo_idle_checkpoint_v1(void){
    __asm__ volatile("" ::: "memory");
}
void fifo_idle_core_v1(void){
    JOB->idle_tcb_observed=CURRENT();
    for(;;){
        if(JOB->idle_pulse_request!=JOB->idle_pulse_delivered){
            JOB->idle_pulse_delivered=JOB->idle_pulse_request;
            POST(JOB->controller_tcb,0x800u);JOB->idle_post_returns++;
        }
        if(JOB->controller_finished)fifo_idle_checkpoint_v1();
    }
}
