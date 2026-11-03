#include "create_abi_v2.h"

/* Compile only. This is not an installation entry or a running player. */
struct garmin_os20_record_v2 *create_abi_check_v2(
    garmin_os20_entry_v2 entry, void *argument) {
    return garmin_os20_create_address_v2()(entry, argument, 4096u, 0u,
                                         "Garmin Music");
}
