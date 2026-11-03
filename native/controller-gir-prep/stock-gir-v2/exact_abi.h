#ifndef CONTROLLER_GIR_EXACT_ABI_H
#define CONTROLLER_GIR_EXACT_ABI_H
#include <stdint.h>
uint32_t cg_read32(uint32_t);
uint8_t cg_read8(uint32_t);
void cg_write32(uint32_t,uint32_t);
void cg_write8(uint32_t,uint8_t);
uint32_t cg_current_sp(void);
uint32_t cg_current_cpsr(void);
uint32_t cg_settings_set(uint32_t,const void *,uint32_t,uint32_t);
uint32_t cg_settings_read(uint32_t,uint32_t *);
void cg_widget_init(void);
void cg_display_init(void);
uint32_t cg_platform_hash(void);
uint32_t cg_gir_register(uint32_t,uint8_t *);
uint32_t cg_gir_catalog(void);
void cg_static_fonts_init(void);
uint32_t cg_external_fonts_init(uint32_t);
void cg_menu_signals_init(void);
void cg_db_set_cell(uint32_t,uint32_t,uint32_t,uint32_t);
#endif
