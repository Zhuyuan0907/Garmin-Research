/* NEW guest-only caller bridge. Actual native Source grants CONFIG after the
 * original descriptor/TCB publication and before first copied msg13 POST.
 * Original send, priorities, native selector/factory and complete pulls remain.
 */
#include <stdint.h>
#include "warm_addresses_v1.h"
#define W(a) (*(volatile uint32_t *)(a))
#define MIXER 0x034e5cf8u
struct config_before_send_result_v1 {
 uint32_t actor,entries,mixer_tcb,message_pointer,original_entry_LR;
 int32_t grant_result;
 uint32_t grant_completed,original_send_returned;
};
volatile struct config_before_send_result_v1 config_before_send_result_v1;
__attribute__((noinline))void config_before_send_failure_v1(void){for(;;)__asm__ volatile("":::"memory");}
uint32_t config_before_send_v1(uint32_t tcb,const uint8_t *message){
 if(message[1]!=8u)return ((uint32_t(*)(uint32_t,const void*))0x37bce5u)(tcb,message);
 config_before_send_result_v1.actor=((uint32_t(*)(void))0x358d25u)();config_before_send_result_v1.entries++;
 config_before_send_result_v1.mixer_tcb=tcb;config_before_send_result_v1.message_pointer=(uint32_t)(uintptr_t)message;
 config_before_send_result_v1.original_entry_LR=(uint32_t)(uintptr_t)__builtin_return_address(0);
 if(config_before_send_result_v1.actor!=W(MH_SOURCE_TCB) || !W(MH_INITIALIZED) || message[0]!=13u ||
    tcb!=W(MIXER+0x78u) || config_before_send_result_v1.original_entry_LR!=0x3b9c4fu)config_before_send_failure_v1();
 config_before_send_result_v1.grant_result=((int32_t(*)(void*))MCS_HANDOFF)((void*)AAS_GUARD);
 if(config_before_send_result_v1.grant_result)config_before_send_failure_v1();
 config_before_send_result_v1.grant_completed=1;
 uint32_t result=((uint32_t(*)(uint32_t,const void*))0x37bce5u)(tcb,message);
 config_before_send_result_v1.original_send_returned=1;return result;
}
