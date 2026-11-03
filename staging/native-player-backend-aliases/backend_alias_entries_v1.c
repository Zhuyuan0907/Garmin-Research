/* Selected shared backend entry protection. VM-only, not all native writers. */
#include <stdint.h>
extern int pg_backend_allow(const volatile void *,int);
extern volatile uint32_t pg_pinned,pg_index;
extern int al_stock_config(volatile void *,const void *,uint32_t);
extern int al_stock_stop(volatile void *);
extern uint32_t al_stock_start(volatile void *,void *,uint32_t,uint32_t);
extern int al_stock_seek(volatile void *,uint32_t);
extern int al_stock_clear(volatile void *);
volatile uint32_t al_denied[5],al_forwarded[5];
int al_config_gate(volatile void *object,const void *parameters,uint32_t argument)
{if(!pg_backend_allow(object,0)){al_denied[0]++;return 8;}al_forwarded[0]++;return al_stock_config(object,parameters,argument);}
int al_stop_gate(volatile void *object)
{if(!pg_backend_allow(object,0)){al_denied[1]++;return 8;}al_forwarded[1]++;return al_stock_stop(object);}
uint32_t al_start_gate(volatile void *object,void *buffer,uint32_t count,uint32_t mode)
{if(!pg_backend_allow(object,1)){al_denied[2]++;return 8;}al_forwarded[2]++;return al_stock_start(object,buffer,count,mode);}
int al_seek_gate(volatile void *object,uint32_t command)
{if(!pg_backend_allow(object,0)){al_denied[3]++;return 8;}al_forwarded[3]++;return al_stock_seek(object,command);}
int al_clear_gate(volatile void *object)
{if(!pg_backend_allow(object,0)){al_denied[4]++;return 8;}al_forwarded[4]++;return al_stock_clear(object);}
/* Real native kernel interference task, enabled only by offline test. */
static uint8_t al_racer_stack[8192] __attribute__((aligned(4096)));
static uint32_t al_descriptor[5],al_parameters[140],al_buffer[64];
volatile uint32_t al_racer_tcb,al_racer_runs,al_results[6];
uint32_t al_other_object[4];
static void al_racer_entry(void)
{
 for(;;){
  (void)((uint32_t (*)(void))0x2fd035u)();
  volatile void *p=(volatile void *)(uintptr_t)(0x034e3cf4u+pg_index*576u+16u);
  al_results[0]=((int (*)(volatile void *,const void *,uint32_t))0x4cae19u)(p,al_parameters,2);
  al_results[1]=((int (*)(volatile void *))0x4cae45u)(p);
  al_results[2]=((uint32_t (*)(volatile void *,void *,uint32_t,uint32_t))0x4cae6du)(p,al_buffer,sizeof(al_buffer),1);
  al_results[3]=((int (*)(volatile void *,uint32_t))0x4caf2fu)(p,6);
  al_results[4]=((int (*)(volatile void *))0x5e75b3u)(p);
  al_results[5]=((int (*)(volatile void *))0x5e75b3u)((volatile uint8_t *)p+4);
  al_racer_runs++;
 }
}
uint32_t al_boot_racer(void)
{
 if(al_racer_tcb)return 0;
 al_descriptor[0]=(uint32_t)(uintptr_t)al_racer_entry;al_descriptor[1]=0;
 al_descriptor[2]=(uint32_t)(uintptr_t)(al_racer_stack+sizeof(al_racer_stack));al_descriptor[3]=6u<<16;al_descriptor[4]=0;
 al_racer_tcb=((uint32_t (*)(const void *))0x358bf9u)(al_descriptor);
 if(al_racer_tcb)(void)((int (*)(const void *))0x2fbbbfu)(al_descriptor);
 return al_racer_tcb;
}
uint32_t al_request_attack(void)
{if(!al_racer_tcb || !pg_pinned)return 0;((void (*)(uint32_t,uint32_t))0x2fcf44u)(al_racer_tcb,1);return al_racer_tcb;}
