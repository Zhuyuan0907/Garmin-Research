/* NEW explicit software backing extent through original initialized-heap API.
 * This is a guest caller-boundary wrapper, not an installed MAIN hook. All
 * original mixer initialization executes after the true original append API.
 * New 0x18400000 RAM is only a VM software fixture, not physical availability.
 */
#include <stdint.h>
#define W(a) (*(volatile uint32_t *)(a))
#define CURRENT() (((uint32_t(*)(void))0x358d25u)())
#define WORK 0x03a7f170u
struct allocator_supply_result_v1 {
 uint32_t actor,entries,old_head,old_cached,old_virtual_pool,old_total_backing;
 uint32_t new_head,new_cached,new_virtual_pool,new_total_backing,append_returned;
 uint32_t original_mixer_result,original_mixer_returned,fail_reason;
};
volatile struct allocator_supply_result_v1 allocator_supply_result_v1;
static const uint32_t new_extent[2]={0x18400000u,65536u};
__attribute__((noinline))void allocator_supply_failure_v1(void){for(;;)__asm__volatile("":::"memory");}
static void check(int test,uint32_t reason){if(!test){allocator_supply_result_v1.fail_reason=reason;allocator_supply_failure_v1();}}
uint32_t allocator_supply_then_mixer_v1(uint32_t channel,uint32_t flags){
 allocator_supply_result_v1.actor=CURRENT();allocator_supply_result_v1.entries++;
 check(allocator_supply_result_v1.actor==0x183140a0u && channel==8 && !flags,1);
 ((uint32_t(*)(uint32_t,uint32_t,uint32_t))0x3009a1u)(WORK+0x1cu,2,0);
 allocator_supply_result_v1.old_head=W(WORK+4);allocator_supply_result_v1.old_cached=W(WORK+8);
 allocator_supply_result_v1.old_virtual_pool=W(WORK+0x18);allocator_supply_result_v1.old_total_backing=W(WORK+0x50);
 check(allocator_supply_result_v1.old_head==0x18308000u && !allocator_supply_result_v1.old_cached && allocator_supply_result_v1.old_virtual_pool,2);
 /* Existing-pool branch skips bitmap init and listeners. First table appends
  * backing pages. Fourth argument zero excludes the managed-virtual-table path. */
 ((void(*)(const uint32_t*,uint32_t,const void*,uint32_t))0x388b6du)(new_extent,1,0,0);
 allocator_supply_result_v1.new_head=W(WORK+4);allocator_supply_result_v1.new_cached=W(WORK+8);
 allocator_supply_result_v1.new_virtual_pool=W(WORK+0x18);allocator_supply_result_v1.new_total_backing=W(WORK+0x50);
 check(allocator_supply_result_v1.new_head==0x18400000u && !allocator_supply_result_v1.new_cached &&
       allocator_supply_result_v1.new_virtual_pool==allocator_supply_result_v1.old_virtual_pool &&
       allocator_supply_result_v1.new_total_backing==allocator_supply_result_v1.old_total_backing+65536u,3);
 allocator_supply_result_v1.append_returned=1;
 ((void(*)(uint32_t))0x3008b1u)(WORK+0x1cu);
 uint32_t result=((uint32_t(*)(uint32_t,uint32_t))0x3b9b67u)(channel,flags);
 allocator_supply_result_v1.original_mixer_result=result;allocator_supply_result_v1.original_mixer_returned=1;
 return result;
}
