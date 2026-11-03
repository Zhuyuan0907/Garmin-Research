#include <stdint.h>
#include "exact_abi.h"

/* Function pointers carry the original Thumb bit. Normal C BLX calls keep
 * the active native stack; no SP/ready/owner/context/synthetic result writes. */
uint32_t cg_read32(uint32_t p) {
    volatile const uint8_t *b=(volatile const uint8_t *)(uintptr_t)p;
    return (uint32_t)b[0]|(uint32_t)b[1]<<8|(uint32_t)b[2]<<16|(uint32_t)b[3]<<24;
}
uint8_t cg_read8(uint32_t p) { return *(volatile const uint8_t *)(uintptr_t)p; }
void cg_write32(uint32_t p,uint32_t v) { *(volatile uint32_t *)(uintptr_t)p=v; }
void cg_write8(uint32_t p,uint8_t v) { *(volatile uint8_t *)(uintptr_t)p=v; }
uint32_t cg_current_sp(void) { uint32_t p; __asm__ volatile("mov %0, sp":"=r"(p)); return p; }
uint32_t cg_current_cpsr(void) { uint32_t p; __asm__ volatile("mrs %0, cpsr":"=r"(p)); return p; }

uint32_t cg_settings_set(uint32_t k,const void *p,uint32_t n,uint32_t cache) {
    typedef uint32_t (*fn)(uint32_t,const void *,uint32_t,uint32_t);
    return ((fn)(uintptr_t)0x2ca82d)(k,p,n,cache);
}
uint32_t cg_settings_read(uint32_t k,uint32_t *p) {
    typedef uint32_t (*fn)(uint32_t,uint32_t *);
    return ((fn)(uintptr_t)0x2cabbd)(k,p);
}
/* These void declarations deliberately discard unspecified original r0. */
void cg_widget_init(void) { ((void (*)(void))(uintptr_t)0x395981)(); }
void cg_display_init(void) { ((void (*)(void))(uintptr_t)0x2db541)(); }
uint32_t cg_platform_hash(void) { return ((uint32_t (*)(void))(uintptr_t)0x25dc81)(); }
uint32_t cg_gir_register(uint32_t gir,uint8_t *kind) {
    return ((uint32_t (*)(uint32_t,uint8_t *))(uintptr_t)0x41cc47)(gir,kind);
}
uint32_t cg_gir_catalog(void) { return ((uint32_t (*)(void))(uintptr_t)0x41b15b)(); }
void cg_static_fonts_init(void) { ((void (*)(void))(uintptr_t)0x4df249)(); }
uint32_t cg_external_fonts_init(uint32_t mode) {
    return ((uint32_t (*)(uint32_t))(uintptr_t)0x4de237)(mode);
}
void cg_menu_signals_init(void) { ((void (*)(void))(uintptr_t)0x4a388b)(); }
void cg_db_set_cell(uint32_t menu,uint32_t icon,uint32_t cell,uint32_t size) {
    ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t))(uintptr_t)0x316277)(menu,icon,cell,size);
}
