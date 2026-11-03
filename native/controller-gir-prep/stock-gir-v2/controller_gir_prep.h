#ifndef CONTROLLER_GIR_PREP_H
#define CONTROLLER_GIR_PREP_H
#include <stdint.h>

#define CG_CONFIG_MAGIC UINT32_C(0x13520800)
#define CG_EXPLICIT_INPUT_FLAGS UINT32_C(15)
enum cg_status {
    CG_DB_OBSERVATION_NEEDED = 1,
    CG_BAD_CONFIG = -1, CG_WRONG_CONTROLLER = -2, CG_BAD_STACK = -3,
    CG_SETTINGS_NOT_READY = -4, CG_SETTINGS_WRITE_FAILED = -5,
    CG_SETTINGS_READ_FAILED = -6, CG_PLATFORM_MISMATCH = -7,
    CG_GIR_REJECTED = -8, CG_CATALOG_MISMATCH = -9,
    CG_FONTS_RETURN_FAILED = -10, CG_DB_PROVIDER_INVALID = -11,
    CG_ALREADY_STARTED = -12
};
enum cg_phase {
    CG_ADMISSION = 1, CG_SETTING_WRITE, CG_SETTING_READ, CG_WIDGET_REGISTRY,
    CG_DISPLAY_LIST, CG_PLATFORM, CG_GIR_REGISTER, CG_GIR_CATALOG,
    CG_STATIC_FONTS, CG_EXTERNAL_FONTS, CG_MENU_SIGNALS, CG_DB_BIND,
    CG_DB_SELECT, CG_NATIVE_SEQUENCE_RETURNED
};

/* All ranges are declared RAM/readonly input fixtures, not discovered RAM. */
struct cg_config {
    uint32_t magic, bytes, flags;
    uint32_t controller_tcb, controller_stack_low, controller_stack_high;
    uint32_t stock_gir, stock_gir_bytes, stock_gir_directory_bytes;
    uint32_t gir_input_low, gir_input_high;
    uint32_t catalog_record_low, catalog_record_high;
    uint32_t settings_data_low, settings_data_high;
    uint32_t lower_db_provider, player_id, selected_cell, selected_size;
};
struct cg_result {
    uint32_t bytes, phase, completed_call_mask;
    int32_t status;
    uint32_t controller_before, controller_after, adapter_sp;
    uint32_t settings_return, settings_length, settings_data;
    uint32_t platform_hash, gir_return, gir_kind, gir_catalog, gir_record;
    uint32_t font_return, menu, lower_db_provider;
    uint32_t db_setter_returned, db_row_or_closed_SQL_verified;
};

/* One invocation per loaded companion, including failed partial runs.
 * The config/result must remain valid while original calls may block.
 * Original Manager393A2C and callback405340 are intentionally absent. */
int32_t cg_controller_prepare(const struct cg_config *, struct cg_result *);
#endif
