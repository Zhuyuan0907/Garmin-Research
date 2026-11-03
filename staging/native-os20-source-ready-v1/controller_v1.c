/* Offline continuation on the original native controller TCB. Source and
 * typed-FIFO initializer are the sealed warm player's unchanged functions. */
#include <stdint.h>
#include "source_addresses_v1.h"
typedef uint32_t (*current_fn)(void);
typedef uint32_t (*wait_fn)(void);
typedef int (*bind_fn)(uint32_t);
#define CURRENT() (((current_fn)0x358d25u)())
#define WAIT() (((wait_fn)0x2fd035u)())
#define WORD(a) (*(volatile uint32_t *)(a))
struct source_ready_result_v1 {
    uint32_t controller,created_tcb,entered,creator_return_count,adapter;
    uint32_t adapter_tcb,ready_before_wait,post_returns_before_wait;
    int32_t wrong_actor_bind;
    uint32_t event,controller_after_wait,initialized,initializer_status;
    uint32_t ready_posts_at_wake,ready_post_returns_at_wake,source_self;
    uint32_t callback_argument,callback_entries,publication_checks,publication_errors;
    uint32_t output_initialized,queue_running,queue_epoch,queue_count,observed_ready;
    uint32_t fail_reason;
};
volatile struct source_ready_result_v1 source_ready_result_v1;
__attribute__((noinline)) void source_ready_failure_v1(void){for(;;)__asm__ volatile("":::"memory");}
static void check(int test,uint32_t reason){if(!test){source_ready_result_v1.fail_reason=reason;source_ready_failure_v1();}}
void source_ready_controller_v1(uint32_t created){
    source_ready_result_v1.controller=CURRENT();
    source_ready_result_v1.created_tcb=created;source_ready_result_v1.entered++;
    check(source_ready_result_v1.controller==WORD(MH_READY_CONTROLLER),1);
    source_ready_result_v1.creator_return_count=WORD(MH_CREATE_RETURNS);
    source_ready_result_v1.adapter=WORD(MH_ADAPTER);
    check(source_ready_result_v1.creator_return_count==1 && source_ready_result_v1.adapter,2);
    source_ready_result_v1.adapter_tcb=WORD(source_ready_result_v1.adapter+48u);
    check(created==source_ready_result_v1.adapter_tcb,3);
    source_ready_result_v1.ready_before_wait=WORD(MH_INITIALIZED);
    source_ready_result_v1.post_returns_before_wait=WORD(MH_READY_POST_RETURNS);
    check(!source_ready_result_v1.ready_before_wait,4);
    source_ready_result_v1.wrong_actor_bind=((bind_fn)MH_BIND_READY)(created);
    check(source_ready_result_v1.wrong_actor_bind==-401,5);
    source_ready_result_v1.event=WAIT();
    source_ready_result_v1.controller_after_wait=CURRENT();
    check(source_ready_result_v1.event==0x400u &&
          source_ready_result_v1.controller_after_wait==source_ready_result_v1.controller,6);
    source_ready_result_v1.initialized=WORD(MH_INITIALIZED);
    source_ready_result_v1.initializer_status=WORD(MH_INITIALIZE_RESULT);
    source_ready_result_v1.ready_posts_at_wake=WORD(MH_READY_POSTS);
    source_ready_result_v1.ready_post_returns_at_wake=WORD(MH_READY_POST_RETURNS);
    source_ready_result_v1.source_self=WORD(MH_SELF_TCB);
    source_ready_result_v1.callback_argument=WORD(MH_CALLBACK_ARGUMENT);
    source_ready_result_v1.callback_entries=WORD(MH_WORKER_ENTRIES);
    source_ready_result_v1.publication_checks=WORD(MH_PUBLICATION_CHECKS);
    source_ready_result_v1.publication_errors=WORD(MH_PUBLICATION_ERRORS);
    source_ready_result_v1.output_initialized=WORD(MEMORY_OUTPUT_CONTROL);
    source_ready_result_v1.queue_count=WORD(MEDIA_QUEUE_CONTROL+8u);
    source_ready_result_v1.queue_epoch=WORD(MEDIA_QUEUE_CONTROL+12u);
    source_ready_result_v1.queue_running=WORD(MEDIA_QUEUE_CONTROL+16u);
    check(source_ready_result_v1.initialized==1 && !source_ready_result_v1.initializer_status,7);
    check(source_ready_result_v1.ready_posts_at_wake==1 && source_ready_result_v1.source_self==created,8);
    check(source_ready_result_v1.callback_argument==MH_CONTEXT && source_ready_result_v1.callback_entries==1,9);
    check(source_ready_result_v1.publication_checks==2 && !source_ready_result_v1.publication_errors,10);
    check(source_ready_result_v1.output_initialized==1 && source_ready_result_v1.queue_running==1 &&
          source_ready_result_v1.queue_epoch==1 && !source_ready_result_v1.queue_count,11);
    source_ready_result_v1.observed_ready=1;
    /* Original WAIT now lets Source fully return from its ready POST and
     * block on its persistent loop; observer stops at native idle destination. */
    for(;;)(void)WAIT();
}
