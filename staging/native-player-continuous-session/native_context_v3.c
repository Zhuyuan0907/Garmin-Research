/* NEW include binding; original context-check logic retained. */
#include "music_session_guard_v3.h"
int mcs_native_normal_context(void *unused)
{
    uint32_t cpsr;volatile uint32_t *marker=(volatile uint32_t *)0x00f09094u;
    (void)unused;
    __asm__ volatile("mrs %0,cpsr":"=r"(cpsr));
    /* Source/mixer normal privileged execution only. Same current TCB during
     * a hardware IRQ is not a permit to register/borrow an owned generation. */
    return ((cpsr&31u)==0x1fu || (cpsr&31u)==0x13u) && !*marker;
}
