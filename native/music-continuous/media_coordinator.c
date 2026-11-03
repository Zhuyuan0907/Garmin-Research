/* Offline one-owner source coordinator. Direct private imports bind an exact
 * unchanged owned-media ELF. Exclusive channel/list and pinned modules remain
 * contracts; actor identity is not cross-channel reservation/quiescence.
 */
#include <stdint.h>
#include "memory_output.h"
extern uint32_t owned_media_next(void);
extern int owned_media_release(uint32_t);
extern int media_queue_stop(void);
extern int continuous_media_cancel_ready(void);
struct owned_media_control {
    uint32_t initialized,busy,read,write,count,gather_bytes,rate,channels;
    uint32_t committed,failed,canceled,released,last_ticket;
};
extern volatile struct owned_media_control owned_media_control;
_Static_assert(sizeof(struct owned_media_control)==52,"owned pipeline ABI differs");
struct coordinator_state {
    uint32_t initialized,owner_tcb,busy,ticket,cancel_pending,stop_sent;
    uint32_t starts,completed,cancelled,discarded,remove_calls,pump_calls,cancel_calls;
    uint32_t failures;
    int32_t last_result;
};
volatile struct coordinator_state coordinator_state;

static uint32_t lock(void) { return ((uint32_t (*)(void))0x21b6cc)(); }
static void unlock(uint32_t f) { ((void (*)(uint32_t))0x21b6dc)(f); }
static uint32_t current(void) { return ((uint32_t (*)(void))0x358d25)(); }
static volatile uint8_t *record(void)
{ return (volatile uint8_t *)(0x034e6f08u+memory_output_control.channel*520u); }
static uint32_t nodes(void)
{ return *(volatile uint16_t *)(record()+0x1c0u); }
static int native_idle(void)
{
    uint32_t c=memory_output_control.channel;
    volatile uint8_t *r=record();
    if (c>=18u || r[2] || *(volatile uint8_t *)(0x034e5378u+c*304u+0x84u) ||
        *(volatile uint16_t *)(0x034e32bcu+c*84u) ||
        *(volatile uint8_t *)(0x034e9398u+c)!=1u ||
        memory_output_control.native_calls || memory_output_control.reader_in_flight)
        return 0;
    for (uint32_t i=0;i<68u;i++) if (r[0xf4u+i]) return 0;
    return 1;
}
static int enter(void)
{
    if (!coordinator_state.initialized || current()!=coordinator_state.owner_tcb) return -34;
    uint32_t f=lock();
    if (coordinator_state.busy) { unlock(f); return -25; }
    coordinator_state.busy=1;unlock(f);return 0;
}
static int finish(int result)
{
    uint32_t f=lock();
    coordinator_state.last_result=result;
    if (result<0) coordinator_state.failures++;
    coordinator_state.busy=0;unlock(f);return result;
}
int media_coordinator_init(void)
{
    uint32_t tcb=current(),f=lock();
    if (!tcb || !memory_output_control.initialized || memory_output_control.channel>=18u ||
        coordinator_state.initialized || memory_output_control.active_ticket ||
        nodes() || !native_idle()) { unlock(f);return -25; }
    coordinator_state.owner_tcb=tcb;coordinator_state.initialized=1;
    unlock(f);return 0;
}
static int register_head(uint32_t ticket)
{
    coordinator_state.ticket=ticket;
    return memory_output_register(ticket);
}
static int remove_stopped(uint32_t ticket)
{
    uint32_t f=lock();
    if (!native_idle() || nodes()!=1u || memory_output_control.active_ticket!=ticket ||
        memory_output_slots[ticket & 3u].in_flight) { unlock(f);return -25; }
    /* Keep private native_calls held through the ENTIRE original mutex/list
     *removal. No blocking native function is called with IRQ exclusion held.
     */
    memory_output_control.native_calls++;
    unlock(f);
    int result=((int (*)(volatile void *,uint32_t))0x277675)(record()+0x1a8u,0);
    f=lock();memory_output_control.native_calls--;unlock(f);
    if (!result && !nodes()) coordinator_state.remove_calls++;
    else if (!result) result=-31;
    return result;
}
static int cancel_step(void)
{
    if(owned_media_control.busy || memory_output_control.reader_in_flight)return 1;
    uint32_t ticket=coordinator_state.ticket;
    if(ticket){
        if(!native_idle()){
            uint32_t state=*(volatile uint8_t *)(0x034e9398u+memory_output_control.channel);
            if(!coordinator_state.stop_sent && (state==3u || state==4u)){
                int result=((int (*)(uint32_t,uint32_t))0x36af75)(memory_output_control.channel,1);
                if(result)return result;
                coordinator_state.stop_sent=1;
            }
            return 1;
        }
        if(nodes()==1u){int result=remove_stopped(ticket);if(result)return result;}
        else if(nodes())return -31;
        int result=memory_output_release(ticket);if(result)return result;
        coordinator_state.ticket=coordinator_state.stop_sent=0;
    }
    int discarded=continuous_media_cancel_ready();if(discarded<0)return discarded;
    coordinator_state.discarded+=(uint32_t)discarded;
    coordinator_state.cancel_pending=0;coordinator_state.cancelled++;return 0;
}
int media_coordinator_cancel(void)
{
    int result=enter();if (result) return result;
    coordinator_state.cancel_calls++;
    if (!coordinator_state.cancel_pending) {
        result=media_queue_stop();
        if (result) return finish(result);
        coordinator_state.cancel_pending=1;
    }
    return finish(cancel_step());
}
int media_coordinator_pump(void)
{
    int result=enter();if(result)return result;
    coordinator_state.pump_calls++;
    if(coordinator_state.cancel_pending)return finish(cancel_step());
    /* A single native source remains active while packets are consumed/reused.
     * Only explicit cancellation performs original stop/remove/anchor release.
     */
    if(coordinator_state.ticket)return finish(1);
    uint32_t ticket=owned_media_next();if(!ticket)return finish(1);
    result=register_head(ticket);if(result)return finish(result);
    result=memory_output_selection_guard(ticket);if(result)return finish(result);
    result=((int (*)(uint32_t,uint32_t))0x36b721)(memory_output_control.channel,0);
    if(!result)coordinator_state.starts++;
    return finish(result);
}
const void *const coordinator_api[] __attribute__((used,section(".coordinator_api")))={
    (const void *)media_coordinator_init,(const void *)media_coordinator_pump,
    (const void *)media_coordinator_cancel
};
