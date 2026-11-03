/* Offline integration driver. Local slot/ticket/resident storage are declared
 * fixtures. Native IRQ and current-actor functions run original instructions.
 * This does not bootstrap an App, source task, Bluetooth or a speaker. */
#include "music_session_guard_v2.h"
extern int mcs_native_normal_context(void *);
struct umc_controller qcs_control;
struct mcs_guard qcs_guard;
struct umcn_output_view qcs_output;
struct umcn_slot_view qcs_slots[4];
uint32_t qcs_generation, qcs_wakes;
static uint32_t irq_enter(void *p)
{ (void)p;return ((uint32_t (*)(void))0x21b6ccu)(); }
static void irq_leave(void *p,uint32_t f)
{ (void)p;((void (*)(uint32_t))0x21b6dcu)(f); }
static uint32_t current_actor(void *p)
{ (void)p;return ((uint32_t (*)(void))0x358d25u)(); }
static int wake_fixture(void *p,uint32_t actor,uint32_t bits)
{ (void)p;if(actor!=qcs_guard.owner || bits!=UMC_SOURCE_EVENT)return -1;
  qcs_wakes++;return 0; }
static int prepare_scoped(void *p,uint32_t route,uint32_t generation,uint32_t cookie)
{ (void)p;if(route!=8 || cookie!=0x1352)return -1;
  return mcs_reserve_scoped(&qcs_guard,generation); }
static int cancel_fixture(void *p,uint32_t route,uint32_t generation,uint32_t cookie)
{ (void)p;(void)route;(void)generation;(void)cookie;return -200; }
static int observe_uncertified(void *p,uint32_t route,uint32_t generation,
    uint32_t cookie,struct umc_stop_evidence *e)
{ (void)p;(void)route;(void)generation;(void)cookie;(void)e;return -200; }
int qcs_initialize(uint32_t record,uint32_t pool,uint32_t anchor)
{
 struct umc_config cfg={current_actor(0),8,0x1352,1};
 struct umc_adapters ops={0,irq_enter,irq_leave,current_actor,wake_fixture,
                         prepare_scoped,cancel_fixture,observe_uncertified};
 int result;
 qcs_output.initialized=1;qcs_output.channel=8;
 result=umc_init(&qcs_control,&cfg,&ops);if(result)return result;
 result=mcs_init(&qcs_guard,&qcs_control,&qcs_output,qcs_slots,
     (uint8_t *)record,(uint8_t *)pool,anchor,mcs_native_normal_context,0);
 if(result)return result;
 mcs_bridge_context=&qcs_guard;
 result=umc_runtime_ready(&qcs_control);if(result)return result;
 result=umc_request_start(&qcs_control,&qcs_generation);
 if(result!=UMC_PENDING)return result;
 result=umc_service(&qcs_control);if(result)return result;
 qcs_slots[1].ticket=5;qcs_slots[1].state=2;qcs_output.active_ticket=5;
 return mcs_install_queue_callback(&qcs_guard);
}
int qcs_begin(void){return mcs_register_begin(&qcs_guard,5);}
int qcs_end(int result){return mcs_register_end(&qcs_guard,result);}
int qcs_stop(void){return umc_request_stop(&qcs_control,&qcs_generation);}
void qcs_status(uint32_t *p)
{
 p[0]=qcs_guard.queue_calls;p[1]=qcs_guard.foreign_rejections;
 p[2]=qcs_guard.permit_entered;p[3]=qcs_guard.permit_consumed;
 p[4]=qcs_guard.held;p[5]=qcs_guard.generation;
 p[6]=qcs_control.status.state;p[7]=qcs_control.status.armed;
 p[8]=qcs_control.status.media_references;
 p[9]=qcs_control.status.callback_references;
 p[10]=qcs_control.status.stop_completed_generation;p[11]=qcs_wakes;
}
void *memcpy(void *destination,const void *source,unsigned n)
{ unsigned char *d=destination;const unsigned char *s=source;
  for(unsigned i=0;i<n;i++)d[i]=s[i];return destination; }
void *__aeabi_memcpy(void *d,const void *s,unsigned n){return memcpy(d,s,n);}
