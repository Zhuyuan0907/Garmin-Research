/* Entry barriers for five exact original APIs, VM-only installation.
 * These close selected admission paths, NOT all native writers or Stop/unload.
 * Claim is boot-pinned until a future complete native retirement protocol.
 */
#include "music_session_guard_v4.h"
#include <stdint.h>
#define RECORD ((volatile uint8_t *)0x034e7f48u)
#define POST ((void (*)(uint32_t,uint32_t))0x2fcf44u)
#define WAIT ((uint32_t (*)(void))0x2fd035u)
extern struct mcs_guard aas_guard;
extern int mcs_native_normal_context(void *);
extern int rg_stock_profile(uint32_t,uint32_t,uint32_t);
extern int rg_stock_queue(volatile void *,uint32_t,uint32_t,uint32_t,const void *,uint32_t,const void *);
extern int rg_stock_selector(uint32_t,uint32_t);
extern int rg_stock_prepare(volatile void *,uint32_t,uint32_t,uint32_t);
extern uint32_t rg_stock_allocate(volatile uint32_t *);
volatile uint32_t rg_active,rg_owner,rg_epoch;
volatile uint32_t rg_profile_denied,rg_queue_denied,rg_selector_denied,rg_prepare_denied,rg_allocate_denied;
volatile uint32_t rg_profile_forwarded,rg_queue_forwarded,rg_selector_forwarded,rg_prepare_forwarded,rg_allocate_forwarded;
static uint32_t actor(void){return ((uint32_t (*)(void))0x358d25u)();}
static int valid_guard(void)
{return aas_guard.magic==MCS_MAGIC && aas_guard.control && aas_guard.control->magic==UMC_MAGIC &&
 aas_guard.held && aas_guard.owner==rg_owner && aas_guard.generation==aas_guard.control->status.generation;}
static int mixer_authorized(void)
{return valid_guard() && mcs_native_normal_context(0) && aas_guard.mixer_tcb &&
 actor()==aas_guard.mixer_tcb && aas_guard.native_mutation &&
 aas_guard.registration_ticket && aas_guard.mixer_session==aas_guard.epoch;}
/* Caller owns all three original per-route mutexes and has IRQs masked.
 * This API is internal to the new warm initialization, not a public witness. */
int rg_claim_locked(uint32_t owner)
{
 if(rg_active || !owner || owner!=actor() || rg_epoch==UINT32_MAX)return -310;
 rg_owner=owner;rg_epoch++;rg_active=1;return 0;
}
void rg_abandon_unpublished(void)
{rg_active=0;rg_owner=0;}
int rg_profile_gate(uint32_t channel,uint32_t profile,uint32_t override)
{
 if(rg_active && channel==8u){rg_profile_denied++;return 8;}
 rg_profile_forwarded++;return rg_stock_profile(channel,profile,override);
}
int rg_queue_gate(volatile void *list,uint32_t key,uint32_t kind,uint32_t flags,
 const void *params,uint32_t length,const void *metadata)
{
 if(rg_active && list==(volatile void *)(RECORD+0x1a8u)){
  struct mcs_guard *g=&aas_guard;
  if(!valid_guard() || !mcs_native_normal_context(0) || actor()!=rg_owner ||
     !g->permit_entered || !g->permit_consumed || g->permit_actor!=rg_owner ||
     !g->control->status.armed || g->output->active_ticket!=g->permit_ticket ||
     g->slots[g->permit_ticket&3u].ticket!=g->permit_ticket || key!=0xffffu ||
     kind!=10u || flags!=12u || !params || length!=0x20cu || metadata){rg_queue_denied++;return 8;}
 }
 rg_queue_forwarded++;return rg_stock_queue(list,key,kind,flags,params,length,metadata);
}
int rg_selector_gate(uint32_t channel,uint32_t argument)
{
 if(rg_active && channel==8u && !mixer_authorized()){rg_selector_denied++;return 8;}
 rg_selector_forwarded++;return rg_stock_selector(channel,argument);
}
int rg_prepare_gate(volatile void *record,uint32_t a,uint32_t kind,uint32_t p)
{
 if(rg_active && record==(volatile void *)RECORD && !mixer_authorized()){rg_prepare_denied++;return 8;}
 rg_prepare_forwarded++;return rg_stock_prepare(record,a,kind,p);
}
uint32_t rg_allocate_gate(volatile uint32_t *out)
{
 uint32_t flags=((uint32_t (*)(void))0x21b6ccu)(),r;
 if(rg_active && out==(volatile uint32_t *)(RECORD+0xf0u) && !mixer_authorized()){
  rg_allocate_denied++;r=0xffffu;
 }else{
  /* Original scanner contains no wait. Keep free-byte check+claim atomic
   * across this exact entry. Direct reset/free/alias paths remain unguarded. */
  rg_allocate_forwarded++;r=rg_stock_allocate(out);
 }
 ((void (*)(uint32_t))0x21b6dcu)(flags);return r;
}
/* Explicit compiled interference task, only enabled by the offline harness.
 * Original POST/preemption/WAIT executes; no HOST actor context restoration.
 */
static uint8_t racer_stack[8192] __attribute__((aligned(4096)));
static uint32_t racer_descriptor[5];
static uint8_t racer_params[0x20c];
volatile uint32_t rg_racer_tcb,rg_racer_runs,rg_hook_posts;
volatile uint32_t rg_attack_results[5];
static void rg_racer_entry(void)
{
 for(;;){
  (void)WAIT();
  rg_attack_results[0]=((uint32_t (*)(uint32_t,uint32_t,uint32_t))0x277d27u)(8,1,1);
  rg_attack_results[1]=((uint32_t (*)(volatile void *,uint32_t,uint32_t,uint32_t,const void *,uint32_t,const void *))0x277c6bu)(RECORD+0x1a8u,0xffffu,10,12,racer_params,sizeof(racer_params),0);
  rg_attack_results[2]=((uint32_t (*)(uint32_t,uint32_t))0x2f9f2fu)(8,0);
  rg_attack_results[3]=((uint32_t (*)(volatile void *,uint32_t,uint32_t,uint32_t))0x4379d5u)(RECORD,0,10,(uint32_t)(uintptr_t)racer_params);
  rg_attack_results[4]=((uint32_t (*)(volatile uint32_t *))0x48ee69u)((volatile uint32_t *)(RECORD+0xf0u));
  rg_racer_runs++;
 }
}
uint32_t rg_boot_racer(void)
{
 if(rg_racer_tcb)return 0;
 racer_descriptor[0]=(uint32_t)(uintptr_t)rg_racer_entry;racer_descriptor[1]=0;
 racer_descriptor[2]=(uint32_t)(uintptr_t)(racer_stack+sizeof(racer_stack));
 racer_descriptor[3]=8u<<16;racer_descriptor[4]=0;
 rg_racer_tcb=((uint32_t (*)(const void *))0x358bf9u)(racer_descriptor);
 if(rg_racer_tcb)(void)((int (*)(const void *))0x2fbbbfu)(racer_descriptor);
 return rg_racer_tcb;
}
void rg_validation_test_hook(void)
{if(rg_racer_tcb){rg_hook_posts++;POST(rg_racer_tcb,1);}}
uint32_t rg_request_attack(void)
{if(!rg_racer_tcb)return 0;POST(rg_racer_tcb,1);return rg_racer_tcb;}
