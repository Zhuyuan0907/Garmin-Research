/* Six selected public provider APIs. VM-only, boot-pinned reservation.
 * Backend aliases, unknown writers, hardware and physical installation remain unproved. */
#include "music_session_guard_v4.h"
#include <stdint.h>
#define REC ((volatile uint8_t *)0x034e7f48u)
#define POOL ((volatile uint8_t *)0x034e3cf4u)
extern struct mcs_guard aas_guard;
extern volatile uint32_t rg_active,rg_owner;
extern volatile uint32_t ns_stage,ns_hold,ns_epoch,ns_generation,ns_instance;
extern int mcs_native_normal_context(void *);
extern uint32_t rg_stock_allocate(volatile uint32_t *);
extern uint32_t pg_stock_start(uint32_t,void *,uint32_t);
extern int pg_stock_stop(uint32_t);
extern void pg_stock_free(uint32_t);
extern int pg_stock_config(uint32_t,const void *,uint32_t);
extern void pg_stock_reset(void);
extern int pg_stock_seek(uint32_t,uint32_t);
volatile uint32_t pg_pinned,pg_index,pg_epoch,pg_allocation_notes,pg_masked_scans;
volatile uint32_t pg_denied[6],pg_forwarded[6];
static uint32_t actor(void){return ((uint32_t (*)(void))0x358d25u)();}
static int guarded_mixer(int reading)
{
 struct mcs_guard *g=&aas_guard;
 return g->magic==MCS_MAGIC && g->control && g->control->magic==UMC_MAGIC &&
  g->held && g->owner==rg_owner && g->generation==g->control->status.generation &&
  g->mixer_tcb && actor()==g->mixer_tcb && mcs_native_normal_context(0) &&
  g->mixer_session==g->epoch && g->mixer_generation==g->generation &&
  (g->mixer_admission_epoch==g->control->status.admission_epoch ||
   (ns_stage==3u && ns_hold==1u && ns_epoch==g->epoch && ns_generation==g->generation &&
    ns_instance==pg_index && g->native_mutation && g->output->native_calls==1u &&
    g->control->status.state==UMC_STOPPING)) &&
  g->registration_ticket && (g->native_mutation || (reading && g->borrow));
}
/* Called inside existing IRQ exclusion immediately after native busy-byte
 * allocation. This is a private reservation, never an ownership witness. */
void pg_note_allocate(volatile uint32_t *out,uint32_t result)
{
 if(rg_active && out==(volatile uint32_t *)(REC+0xf0u) && result==0 &&
    guarded_mixer(0) && *out<5u && POOL[*out*576u+12u]){
  pg_index=*out;pg_epoch=aas_guard.epoch;pg_pinned=1;pg_allocation_notes++;
 }
}
/* Original scanner is nonblocking and caller already masks IRQs. Keep the
 * private retired slot unavailable to this selected allocator until yield.
 * Restore its exact native busy byte before leaving exclusion. */
uint32_t pg_scan_allocator(volatile uint32_t *out)
{
 uint32_t r;volatile uint8_t *busy;
 if(rg_active && pg_pinned && pg_index<5u && out!=(volatile uint32_t *)(REC+0xf0u)){
  busy=POOL+pg_index*576u+12u;
  if(!*busy){*busy=1;pg_masked_scans++;r=rg_stock_allocate(out);*busy=0;return r;}
 }
 return rg_stock_allocate(out);
}
static int blocked(uint32_t index,uint32_t kind,int reading)
{
 if(rg_active && pg_pinned && index==pg_index &&
    (pg_epoch!=aas_guard.epoch || !guarded_mixer(reading))){pg_denied[kind]++;return 1;}
 pg_forwarded[kind]++;return 0;
}
uint32_t pg_start_gate(uint32_t index,void *buffer,uint32_t length)
{return blocked(index,0,1)?8u:pg_stock_start(index,buffer,length);}
int pg_stop_gate(uint32_t index)
{return blocked(index,1,0)?8:pg_stock_stop(index);}
void pg_free_gate(uint32_t index)
{if(!blocked(index,2,0))pg_stock_free(index);}
int pg_config_gate(uint32_t index,const void *parameters,uint32_t argument)
{return blocked(index,3,0)?8:pg_stock_config(index,parameters,argument);}
void pg_reset_gate(void)
{if(rg_active){pg_denied[4]++;return;}pg_forwarded[4]++;pg_stock_reset();}
int pg_seek_gate(uint32_t index,uint32_t command)
{return blocked(index,5,0)?8:pg_stock_seek(index,command);}
/* Offline-only real native kernel racer; production trigger is absent. */
static uint8_t pg_racer_stack[8192] __attribute__((aligned(4096)));
static uint32_t pg_racer_descriptor[5],pg_parameters[140],pg_buffer[64];
volatile uint32_t pg_racer_tcb,pg_racer_runs,pg_attack_results[6];
static void pg_racer_entry(void)
{
 for(;;){
  (void)((uint32_t (*)(void))0x2fd035u)();
  pg_attack_results[0]=((uint32_t (*)(uint32_t,void *,uint32_t))0x48edf9u)(pg_index,pg_buffer,sizeof(pg_buffer));
  pg_attack_results[1]=((uint32_t (*)(uint32_t))0x48ee13u)(pg_index);
  ((void (*)(uint32_t))0x48ee59u)(pg_index);pg_attack_results[2]=0xf0u;
  pg_attack_results[3]=((uint32_t (*)(uint32_t,const void *,uint32_t))0x48eea5u)(pg_index,pg_parameters,2);
  ((void (*)(void))0x48eed1u)();pg_attack_results[4]=0xf0u;
  pg_attack_results[5]=((uint32_t (*)(uint32_t,uint32_t))0x48eee9u)(pg_index,6);
  pg_racer_runs++;
 }
}
uint32_t pg_boot_racer(void)
{
 if(pg_racer_tcb)return 0;
 pg_racer_descriptor[0]=(uint32_t)(uintptr_t)pg_racer_entry;
 pg_racer_descriptor[1]=0;pg_racer_descriptor[2]=(uint32_t)(uintptr_t)(pg_racer_stack+sizeof(pg_racer_stack));
 pg_racer_descriptor[3]=7u<<16;pg_racer_descriptor[4]=0;
 pg_racer_tcb=((uint32_t (*)(const void *))0x358bf9u)(pg_racer_descriptor);
 if(pg_racer_tcb)(void)((int (*)(const void *))0x2fbbbfu)(pg_racer_descriptor);
 return pg_racer_tcb;
}
uint32_t pg_request_attack(void)
{if(!pg_racer_tcb || !pg_pinned)return 0;((void (*)(uint32_t,uint32_t))0x2fcf44u)(pg_racer_tcb,1);return pg_racer_tcb;}
