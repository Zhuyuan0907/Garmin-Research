/* Offline native OS20 task and controller. No Bluetooth/DAC/UI installation. */
#include "resident_music_v1.h"
typedef uint32_t (*wait_fn)(void);
typedef void (*post_fn)(uint32_t, uint32_t);
typedef uint32_t (*current_fn)(void);
typedef void (*reset_fn)(void);
typedef int (*decode_fn)(const uint8_t *, uint32_t, uint8_t *, uint32_t,
                         struct decoder_result *);
#define WAIT() (((wait_fn)0x002fd035u)())
#define POST(t,e) (((post_fn)0x002fcf44u)((t),(e)))
#define CURRENT() (((current_fn)0x00358d24u)())
#define RESET() (((reset_fn)0x0800223cu)())
#define DECODE(a,b,c,d,e) (((decode_fn)0x08002284u)((a),(b),(c),(d),(e)))
#define JOB ((volatile struct resident_music_v1 *)0x09060000u)

void resident_music_worker_v1(void *argument) {
    volatile struct resident_music_v1 *job=argument;
    if (job->magic!=0x53425231u) return;
    job->observed_argument=(uint32_t)argument;
    job->worker_entries++;
    job->worker_tcb_observed=CURRENT();
    job->notifications++;
    POST(job->controller_tcb,0x400u);
    job->notify_returns++;
    for (;;) {
        (void)WAIT();
        job->wait_returns++;
        uint32_t sequence=job->request_seq;
        if (sequence==job->completed_seq) continue;
        switch (job->operation) {
        case RESIDENT_START:
            if (job->active) {
                job->status=-16;
                job->active_start_rejections++;
            } else {
                RESET();
                job->resets++;
                job->generation++;
                job->active=1;
                job->status=0;
            }
            break;
        case RESIDENT_DECODE:
            if (!job->active) {
                job->status=-11;
                job->stopped_rejections++;
            } else {
                job->status=DECODE(job->input,job->input_bytes,job->output,
                                   job->output_capacity,job->result);
                if (!job->status) job->decode_successes++;
            }
            break;
        case RESIDENT_STOP:
            job->active=0;
            job->stops++;
            job->status=0;
            break;
        default:
            job->status=-22;
            break;
        }
        job->completed_seq=sequence;
        job->notifications++;
        POST(job->controller_tcb,0x400u);
        job->notify_returns++;
    }
}

__attribute__((noinline)) void resident_failure_v1(void) {
    for (;;) __asm__ volatile("" ::: "memory");
}
static void check(int condition,uint32_t reason) {
    if (!condition) {
        JOB->controller_failure=reason;
        resident_failure_v1();
    }
}
static uint32_t receive(void) {
    uint32_t event=WAIT();
    check(JOB->event_count<16,1);
    JOB->events[JOB->event_count++]=event;
    return event;
}
static void command(uint32_t operation,uint32_t frame,uint32_t slot,int32_t expected) {
    volatile struct resident_music_v1 *job=JOB;
    job->operation=operation;
    job->input=(const uint8_t *)(0x09061000u+frame*72u);
    job->input_bytes=72;
    job->output=(uint8_t *)(0x09062000u+slot*256u);
    job->output_capacity=256;
    job->result=(struct decoder_result *)(0x09063000u+slot*36u);
    uint32_t sequence=job->request_seq+1;
    job->request_seq=sequence;
    uint32_t worker=*(volatile uint32_t *)(job->adapter+48u);
    check(worker==job->worker_tcb_observed,2);
    POST(worker,1u);
    check(receive()==0x400u,3);
    check(job->completed_seq==sequence,4);
    check(job->status==expected,5);
}

/* Test controller; fixed fixture addresses are not an App/runtime API. */
void resident_controller_v1(void) {
    volatile struct resident_music_v1 *job=JOB;
    job->controller_tcb_observed=CURRENT();
    check(job->controller_tcb_observed==job->controller_tcb,6);
    check(receive()==0x400u,7);
    /* Let the worker block before posting START. Idle provides a native
     * heartbeat, so both post-before-wait and already-waiting paths execute. */
    job->idle_pulse_request=1;
    check(receive()==0x800u,8);
    command(RESIDENT_START,0,0,0);
    command(RESIDENT_DECODE,0,0,0);
    command(RESIDENT_START,0,0,-16);
    command(RESIDENT_DECODE,1,1,0);
    command(RESIDENT_STOP,0,0,0);
    command(RESIDENT_DECODE,0,4,-11);
    command(RESIDENT_START,0,0,0);
    command(RESIDENT_DECODE,2,2,0);
    command(RESIDENT_DECODE,3,3,0);
    command(RESIDENT_STOP,0,0,0);
    check(job->generation==2 && job->resets==2 && job->stops==2,9);
    check(job->decode_successes==4 && job->worker_entries==1,10);
    job->controller_finished=1;
    for (;;) (void)WAIT();
}

__attribute__((noinline)) void resident_idle_checkpoint_v1(void) {
    __asm__ volatile("" ::: "memory");
}
void resident_idle_v1(void) {
    volatile struct resident_music_v1 *job=JOB;
    job->idle_tcb_observed=CURRENT();
    for (;;) {
        if (job->idle_pulse_request!=job->idle_pulse_delivered) {
            job->idle_pulse_delivered=job->idle_pulse_request;
            POST(job->controller_tcb,0x800u);
            job->idle_post_returns++;
        }
        if (job->controller_finished) resident_idle_checkpoint_v1();
    }
}
