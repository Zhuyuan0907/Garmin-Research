#ifndef GARMIN_1352_OS20_CREATE_ABI_V2_H
#define GARMIN_1352_OS20_CREATE_ABI_V2_H

/* Research declaration for Taiwan HWID1352 MAIN8.00, not a public SDK.
 * Offline execution proved original allocation, name conversion, native TCB,
 * registry/adapter writes and POST/create return. Root/callback execution,
 * physical heap, real boot inventory and installation remain unverified.
 * Caller must supply a live NUL-terminated CP1252 name, never NULL.
 * Only the short ASCII name "Garmin Music" was tested in the new scope.
 * Priority index bounds, exhaustion and lifetime contracts remain unknown.
 */
#include <stddef.h>
#include <stdint.h>

typedef void (*garmin_os20_entry_v2)(void *argument);

struct garmin_os20_record_v2 {
    void *workspace;
    uint32_t workspace_bytes;
    uint32_t priority_index;
    garmin_os20_entry_v2 entry;
    void *argument;
    void *stack_top;
    uint32_t opaque_24_40[5];
    uint8_t adapter_state;
    uint8_t padding_45_47[3];
    void *native_tcb;
    uint32_t opaque_52_60[3];
};

typedef struct garmin_os20_record_v2 *(*garmin_os20_create_fn_v2)(
    garmin_os20_entry_v2 entry, void *argument, uint32_t requested_workspace_bytes,
    uint32_t priority_index, const char *name_cp1252);

#if defined(__arm__)
_Static_assert(sizeof(void *) == 4, "Recovered ARM32 ABI only");
_Static_assert(sizeof(struct garmin_os20_record_v2) == 64, "OS20 record stride");
_Static_assert(offsetof(struct garmin_os20_record_v2, entry) == 12, "Callback slot");
_Static_assert(offsetof(struct garmin_os20_record_v2, argument) == 16, "Argument slot");
_Static_assert(offsetof(struct garmin_os20_record_v2, adapter_state) == 44, "Adapter state");
_Static_assert(offsetof(struct garmin_os20_record_v2, native_tcb) == 48, "TCB identity");

/* Instruction entry is Thumb521E5E; a function pointer requires bit0=1. */
static inline garmin_os20_create_fn_v2 garmin_os20_create_address_v2(void) {
    return (garmin_os20_create_fn_v2)(uintptr_t)0x00521e5fu;
}
#endif
#endif
