#ifndef GARMIN_UI_MUSIC_NATIVE_ADAPTER_H
#define GARMIN_UI_MUSIC_NATIVE_ADAPTER_H
#include <stdint.h>
#include <stddef.h>
#include "../ui-music-control-prototype/ui_music_control.h"

#define UMCN_MAGIC 0x554e4131u
enum umcn_result { UMCN_OK=0, UMCN_BINDING_MISSING=-100,
    UMCN_OWNER_MISMATCH=-101, UMCN_NATIVE_BUSY=-102, UMCN_STALE=-103,
    UMCN_PINNED=-104, UMCN_UNSUPPORTED_ROUTE=-105 };

/* Exact current continuous/source-worker private ABI. uint32 address words
 * remain32-bit on the host; no host pointer is used to reinterpret opaque
 * native heap handles. The separately bound record/pool byte arrays use exact
 * verified offsets, never a guessed struct cast of an allocation descriptor.
 */
struct umcn_source_view {
    uint32_t tcb,entered,wake_returns,pending,publications,completions;
    uint32_t requests,pump_calls,cancel_requested,quit_requested,finished_on_stack;
    int32_t init_result,last_result;
};
struct umcn_runtime_view {
    uint32_t initialized,channel,decoder_tcb,source_tcb;
    int32_t last_error;
    uint32_t source_init_done;
    int32_t source_init_result;
    uint32_t source_init_owner,last_status,snapshots;
};
struct umcn_coordinator_view {
    uint32_t initialized,owner_tcb,busy,ticket,cancel_pending,stop_sent;
    uint32_t starts,completed,cancelled,discarded,remove_calls,pump_calls,cancel_calls,failures;
    int32_t last_result;
};
struct umcn_output_view {
    uint32_t initialized,channel,generation,active_ticket,installed;
    uint32_t native_calls,reader_in_flight,reads,bytes_read,releases,full;
    int32_t last_native_result;
};
struct umcn_slot_view { uint32_t ticket,state,bytes,instance,reads,in_flight; };
struct umcn_owned_view {
    uint32_t initialized,busy,read,write,count,gather_bytes,rate,channels;
    uint32_t committed,failed,canceled,released,last_ticket;
};
struct umcn_queue_view {
    uint32_t read,write,count,epoch,running,producer_busy,worker_busy,consume_address,reset_address;
};
struct umcn_worker_view {
    uint32_t tcb,entered,wake_returns,handled_packets,capacity_deferrals,quit_requested,finished_on_stack;
    int32_t last_step;
};
_Static_assert(sizeof(struct umcn_source_view)==52,"source-worker ABI");
_Static_assert(sizeof(struct umcn_runtime_view)==40,"runtime ABI");
_Static_assert(sizeof(struct umcn_coordinator_view)==60,"coordinator ABI");
_Static_assert(sizeof(struct umcn_output_view)==48,"output ABI");
_Static_assert(sizeof(struct umcn_slot_view)==24,"owned-slot ABI");
_Static_assert(sizeof(struct umcn_owned_view)==52,"owned FIFO ABI");
_Static_assert(sizeof(struct umcn_queue_view)==36,"queue ABI");
_Static_assert(sizeof(struct umcn_worker_view)==32,"decoder-worker ABI");
_Static_assert(offsetof(struct umcn_source_view,cancel_requested)==32,"source cancel offset");
_Static_assert(offsetof(struct umcn_coordinator_view,remove_calls)==40,"remove return counter");
_Static_assert(offsetof(struct umcn_output_view,releases)==36,"release return counter");

struct umcn_ownership_witness {
    uint32_t generation,cookie,channel,owner_tcb,source_token,epoch;
    uint32_t native_writers_excluded,future_borrowing_callbacks_excluded;
};
struct umcn_bindings {
    void *integration_context;
    uint32_t (*irq_save)(void *);
    void (*irq_restore)(void *,uint32_t);
    uint32_t (*current_task)(void *);
    void (*native_post)(void *,uint32_t,uint32_t);
    int (*runtime_cancel)(void *);
    void (*original_source_completed)(void *,const volatile void *record);
    /* Unrecovered native reservation/session glue MUST be supplied. These
     * return a serialized witness and prepare a coherent AV session; no
     * default success or callback-count-derived witness is implemented. */
    int (*ownership_snapshot)(void *,uint32_t generation,uint32_t source_token,
                              struct umcn_ownership_witness *);
    int (*prepare_session)(void *,uint32_t generation,uint32_t ownership_epoch);
    volatile struct umcn_runtime_view *runtime;
    volatile struct umcn_source_view *source;
    volatile struct umcn_coordinator_view *coordinator;
    volatile struct umcn_output_view *output;
    volatile struct umcn_owned_view *owned;
    volatile struct umcn_queue_view *queue;
    volatile struct umcn_worker_view *decoder;
    volatile struct umcn_slot_view *slots;
    volatile uint8_t *source_record;  /*034E6F08+8*520, length520*/
    volatile uint8_t *mixer_record;   /*034E5378+8*304, length304*/
    volatile uint8_t *driver_record;  /*034E32BC+8*84, length84*/
    volatile uint8_t *source_state;   /*034E9398+8, length1*/
    volatile uint8_t *provider_pool;  /*034E3CF4,5*576 bytes*/
    uint32_t anchor_address;         /*exact linked anchor_zero address*/
    uint32_t channel,resident_storage_confirmed;
};
struct umcn_control_functions {
    int (*init)(struct umc_controller *,const struct umc_config *,const struct umc_adapters *);
    int (*ready)(struct umc_controller *);
    int (*service)(struct umc_controller *);
    int (*status)(struct umc_controller *,struct umc_status *);
    int (*gate)(struct umc_controller *,uint32_t,uint32_t);
    int (*started)(struct umc_controller *,uint32_t,uint32_t,uint32_t,uint32_t);
    int (*cleaned)(struct umc_controller *,uint32_t,uint32_t,uint32_t,uint32_t);
    int (*callback_acquire)(struct umc_controller *,struct umc_lease *);
    int (*callback_release)(struct umc_controller *,struct umc_lease *);
    int (*kick)(struct umc_controller *);
};
struct umcn_trace {
    uint32_t generation,source_token,ownership_epoch;
    uint32_t source_remove_baseline,source_release_baseline;
    uint32_t cancel_generation,cancel_count_baseline,pump_baseline;
    uint32_t original_cleanup_returned,owner_cancel_iteration_returned;
};
struct umcn_context {
    uint32_t magic,cookie;
    struct umc_controller *control;
    struct umcn_bindings native;
    struct umcn_control_functions core;
    struct umcn_trace trace;
};

/* Fixed64-byte ARM wrapper frame. record_address is a native32-bit address,
 * not an opaque allocator descriptor. The host uses it only as low32 address
 * identity after the full pointer has matched the bound record. */
struct umcn_cleanup_frame {
    struct umc_lease callback;
    uint32_t generation,cookie,source_token,route,record_address,entry_lr;
    int32_t capture_result;
    uint32_t entry_address,original_returned,reserved[2];
};
_Static_assert(sizeof(struct umcn_cleanup_frame)==64,"native wrapper frame");

int umcn_init(struct umcn_context *,struct umc_controller *,const struct umcn_bindings *,
              const struct umcn_control_functions *,uint32_t cookie);
int umcn_owner_ready(struct umcn_context *);
int umcn_service_owner(struct umcn_context *);
int umcn_admission(struct umcn_context *,uint32_t generation,uint32_t gate);
/* Hook AFTER original owned registration has returned, BEFORE native START.
 * Token is read from actual coordinator/output/slot; caller cannot supply one.
 */
int umcn_note_owned_publication(struct umcn_context *);
/* Hook after source_worker lines71-72, with the real native iteration result. */
int umcn_after_native_iteration(struct umcn_context *,int result);
int umcn_cleanup_begin(struct umcn_context *,const volatile void *record,
                        struct umcn_cleanup_frame *,uint32_t entry_lr);
/* Only the full-return wrapper calls this after original3B9DFC continuation.
 * It forwards unchanged source_worker_completed and releases whole frame ref. */
int umcn_cleanup_after_original(struct umcn_context *,struct umcn_cleanup_frame *,
                                 const volatile void *record,int original_result);
int umcn_set_cleanup_bridge(struct umcn_context *);
extern struct umcn_context *umcn_cleanup_bridge_context;
void umcn_cleanup_bridge(void);
/* Populate exact immutable continuous-module addresses/kernel functions only.
 * ownership_snapshot/prepare_session remain NULL; init then fails closed.
 * New relinks must supply recalculated addresses, not reuse this map. */
int umcn_fill_exact_continuous_bindings(struct umcn_bindings *);
#endif
