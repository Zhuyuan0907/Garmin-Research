#include "music_owner.h"
uint32_t music_owner_irq_save(void) { return ((uint32_t (*)(void))0x21b6ccu)(); }
void music_owner_irq_restore(uint32_t f) { ((void (*)(uint32_t))0x21b6dcu)(f); }
uint32_t music_owner_current(void) { return ((uint32_t (*)(void))0x358d25u)(); }
void music_owner_post(uint32_t tcb,uint32_t bits)
{ ((void (*)(uint32_t,uint32_t))0x2fcf44u)(tcb,bits); }
uint32_t music_owner_wait(void) { return ((uint32_t (*)(void))0x2fd035u)(); }
uint32_t music_owner_construct(uint32_t *descriptor)
{ return ((uint32_t (*)(uint32_t *))0x358bf9u)(descriptor); }
void music_owner_registry(uint32_t *descriptor)
{ ((void (*)(uint32_t *))0x2fbbbfu)(descriptor); }
