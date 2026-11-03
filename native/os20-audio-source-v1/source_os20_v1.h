#ifndef GARMIN_1352_SOURCE_OS20_V1_H
#define GARMIN_1352_SOURCE_OS20_V1_H

/* Research ABI, exact Taiwan HWID1352/SW8.00. No installation/unload API. */
#include <stdint.h>
#include "../os20-task-bridge/create_abi_v2.h"

#define MH_OS20_READY_EVENT_V1 0x400u
#define MH_OS20_WORKSPACE_BYTES_V1 16384u
#define MH_OS20_PRIORITY_INDEX_V1 7u /* Native byte89, below controller16. */

struct mh_os20_callback_context_v1 {
    uint32_t magic;
    uint32_t version;
};

/* Bind before boot from the actual original controller task. Boot returns a
 * constructed TCB, not initialized readiness. Controller must original-WAIT
 * for READY_EVENT, then inspect mh_initialize_result. READY_POST may preempt
 * Source before its POST returns; ready_post_returns is a separate observation.
 */
int mh_bind_ready_controller(uint32_t controller_tcb);
uint32_t mh_boot_source(void);
void mh_os20_source_callback(void *argument);
uint32_t mh_os20_context_address(void);
uint32_t mh_os20_legacy_source_stack(void);
uint32_t mh_os20_legacy_source_descriptor(void);

extern volatile uint32_t mh_os20_adapter, mh_os20_boot_attempts;
extern volatile uint32_t mh_os20_create_started, mh_os20_create_returns;
extern volatile uint32_t mh_os20_worker_entries, mh_os20_callback_argument;
extern volatile uint32_t mh_os20_self_tcb, mh_os20_ready_controller;
extern volatile uint32_t mh_os20_ready_posts, mh_os20_ready_post_returns;
extern volatile uint32_t mh_os20_publication_checks, mh_os20_publication_errors;
extern volatile int32_t mh_os20_last_error, mh_os20_ready_status;

#endif
