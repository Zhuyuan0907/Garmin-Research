/* Research-only recovery for Taiwan HWID1352/SW8.00, not a Garmin SDK.
 * Stock create ABI is statically mapped, not executed or safe for installation.
 * uint32_t fields are original address words, not host pointers. */
#ifndef RESEARCH_OS20_TASK_BRIDGE_H
#define RESEARCH_OS20_TASK_BRIDGE_H
#include <stdint.h>
#include <stddef.h>
#define OS20_RESEARCH_POOL_ADDRESS 0x03a1b294u
#define OS20_RESEARCH_ADAPTER_RECORDS 15u
#define OS20_RESEARCH_LOOKUP_THUMB 0x00521d7du
#define OS20_RESEARCH_CURRENT_RECORD_THUMB 0x00521db1u
#define OS20_RESEARCH_CREATE_THUMB 0x00521e5fu
struct os20_research_record {
 uint32_t workspace_base, workspace_request_bytes, priority_index;
 uint32_t user_entry_word, user_argument_word, initial_stack_top;
 uint32_t reserved18,reserved1c,reserved20,reserved24,reserved28;
 uint8_t state2c,padding2d[3];
 uint32_t native_task_word,wait_link,reserved38,reserved3c;
};
_Static_assert(sizeof(struct os20_research_record)==64,"Recovered stride");
_Static_assert(offsetof(struct os20_research_record,native_task_word)==48,"Identity field");
_Static_assert(offsetof(struct os20_research_record,state2c)==44,"Observed state byte");
/* Observed entry521E5E saves first4 argument registers. It passes argument5
 * from entrySP to native constructor. The caller521F16 forwards argument6,
 * which is not read within the recovered complete521E5E body. Semantics of
 * constructor_arg5, priority index bounds and allocation guarantee are OPEN.
 * Allocator calls and task creation are not verified by index helper tests. */
typedef struct os20_research_record *(*os20_research_create_signature)(
 uint32_t user_entry_word,uint32_t user_argument_word,
 uint32_t requested_workspace_bytes,uint32_t priority_index,
 uint32_t constructor_arg5,uint32_t forwarded_unused_arg6);
/* No callable wrapper is provided. Not-yet-entered scheduling, warm heap,
   guaranteed capacity and reclaiming the task remain physical prerequisites. */
#endif
