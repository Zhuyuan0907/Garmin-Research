#include "controller_gir_prep.h"
#include "exact_abi.h"

_Static_assert(sizeof(struct cg_config)==68,"Config ABI size differs");
_Static_assert(sizeof(struct cg_result)==80,"Result ABI size differs");

static volatile uint32_t resident_started;

static int in_range(uint32_t p,uint32_t n,uint32_t low,uint32_t high) {
    return high>=low && n<=high-low && p>=low && p-low<=high-low-n;
}
static int32_t fail(struct cg_result *r,int32_t status) { r->status=status; return status; }
#define START(p) do { r->phase=(p); } while(0)
#define RETURNED(p) do { \
    r->controller_after=cg_read32(0xf09090); \
    if (r->controller_after!=c->controller_tcb || (cg_current_cpsr()&31)!=31 || cg_read32(0xf09094)!=0) \
        return fail(r,CG_WRONG_CONTROLLER); \
    if (cg_current_sp()!=sp) return fail(r,CG_BAD_STACK); \
    r->completed_call_mask|=UINT32_C(1)<<(p); \
} while(0)

int32_t cg_controller_prepare(const struct cg_config *c,struct cg_result *r) {
    uint32_t sp,setting_one=1,data=0,catalog,begin,end,cap;
    uint8_t kind=0xcc;
    if (!c || !r || ((uintptr_t)c&3) || ((uintptr_t)r&3)) return CG_BAD_CONFIG;
    if (c->magic!=CG_CONFIG_MAGIC || c->bytes!=sizeof(*c) || c->flags!=CG_EXPLICIT_INPUT_FLAGS ||
        !c->controller_tcb || c->stock_gir!=0x0b800000 ||
        !in_range(c->stock_gir,32,c->stock_gir,c->stock_gir+c->stock_gir_bytes) ||
        c->stock_gir_bytes>0x01000000 || c->stock_gir+c->stock_gir_bytes<c->stock_gir ||
        c->catalog_record_low>=c->catalog_record_high || c->settings_data_low>=c->settings_data_high ||
        c->lower_db_provider!=0x084c0000 || c->player_id!=0x7f135201 || c->selected_cell!=12 || c->selected_size!=0)
        return CG_BAD_CONFIG;
    if (resident_started) return CG_ALREADY_STARTED;
    /* Keep the partial run resident on every failure. There is no reset or
     * retry over native initialized globals, subscriptions or SQL state. */
    resident_started=1;
    for (uint32_t i=0;i<sizeof(*r)/sizeof(uint32_t);++i) ((uint32_t *)r)[i]=0;
    r->bytes=sizeof(*r);r->phase=CG_ADMISSION;
    r->controller_before=cg_read32(0xf09090);sp=cg_current_sp();r->adapter_sp=sp;
    if (r->controller_before!=c->controller_tcb || (cg_current_cpsr()&31)!=31 || cg_read32(0xf09094)!=0)
        return fail(r,CG_WRONG_CONTROLLER);
    if (!in_range(sp,8,c->controller_stack_low,c->controller_stack_high)) return fail(r,CG_BAD_STACK);
    /* flags bit1 is caller admission that full original settings init was
     * verified. Readybyte alone is set before that initializer completes. */
    if (cg_read8(0xf06ef7)!=1) return fail(r,CG_SETTINGS_NOT_READY);
    if (cg_read32(c->stock_gir+20)!=c->stock_gir_bytes ||
        cg_read32(c->stock_gir+28)!=c->stock_gir_directory_bytes) return fail(r,CG_BAD_CONFIG);

    START(CG_SETTING_WRITE);
    r->settings_return=cg_settings_set(0x19b,&setting_one,4,0);
    RETURNED(CG_SETTING_WRITE);
    if (r->settings_return!=0) return fail(r,CG_SETTINGS_WRITE_FAILED);
    START(CG_SETTING_READ);
    r->settings_length=cg_settings_read(0x19b,&data);r->settings_data=data;
    RETURNED(CG_SETTING_READ);
    if (r->settings_length!=4 || !in_range(data,4,c->settings_data_low,c->settings_data_high) || cg_read32(data)!=1)
        return fail(r,CG_SETTINGS_READ_FAILED);
    START(CG_WIDGET_REGISTRY);cg_widget_init();RETURNED(CG_WIDGET_REGISTRY);
    START(CG_DISPLAY_LIST);cg_display_init();RETURNED(CG_DISPLAY_LIST);
    START(CG_PLATFORM);r->platform_hash=cg_platform_hash();RETURNED(CG_PLATFORM);
    if (r->platform_hash!=cg_read32(c->stock_gir+12)) return fail(r,CG_PLATFORM_MISMATCH);
    START(CG_GIR_REGISTER);r->gir_return=cg_gir_register(c->stock_gir,&kind);r->gir_kind=kind;RETURNED(CG_GIR_REGISTER);
    if (r->gir_return!=1) return fail(r,CG_GIR_REJECTED);
    START(CG_GIR_CATALOG);catalog=cg_gir_catalog();r->gir_catalog=catalog;RETURNED(CG_GIR_CATALOG);
    /* Catalog itself is the exact original three-word BSS vector. */
    if (catalog!=0x034f7730) return fail(r,CG_CATALOG_MISMATCH);
    begin=cg_read32(catalog);end=cg_read32(catalog+4);cap=cg_read32(catalog+8);r->gir_record=begin;
    if ((begin&3) || end<begin || cap<end || end-begin!=24 ||
        !in_range(begin,cap-begin,c->catalog_record_low,c->catalog_record_high) ||
        cg_read8(begin)!=kind || cg_read8(begin+1)!=1 ||
        cg_read32(begin+12)!=c->stock_gir || cg_read32(begin+16)!=c->stock_gir_directory_bytes)
        return fail(r,CG_CATALOG_MISMATCH);
    START(CG_STATIC_FONTS);cg_static_fonts_init();RETURNED(CG_STATIC_FONTS);
    START(CG_EXTERNAL_FONTS);r->font_return=cg_external_fonts_init(1);RETURNED(CG_EXTERNAL_FONTS);
    if (r->font_return!=0) return fail(r,CG_FONTS_RETURN_FAILED);
    START(CG_MENU_SIGNALS);cg_menu_signals_init();RETURNED(CG_MENU_SIGNALS);
    START(CG_DB_BIND);r->menu=cg_read32(0xf11e0c);r->lower_db_provider=c->lower_db_provider;
    if (!r->menu || (r->menu&3) || r->menu>UINT32_MAX-29) return fail(r,CG_DB_PROVIDER_INVALID);
    /* Explicit lower SQL-provider fixture fields, never a Widget/vtable,
     * semaphore, frame, ready/current pointer or menu-tree fabrication. */
    cg_write32(r->menu+24,c->lower_db_provider);cg_write8(r->menu+28,1);cg_write32(c->lower_db_provider,0);
    START(CG_DB_SELECT);cg_db_set_cell(r->menu,c->player_id,c->selected_cell,c->selected_size);RETURNED(CG_DB_SELECT);
    r->db_setter_returned=1;
    r->phase=CG_NATIVE_SEQUENCE_RETURNED;
    /* Setter r0 is unspecified. Native API return is not DB commit evidence.
     * Root must verify actual selected row and closed original SQL wrappers. */
    return fail(r,CG_DB_OBSERVATION_NEEDED);
}
