/* NEW scoped admission/borrow component; no physical install or native
 * exclusivity proof. All storage and callbacks remain resident forever. */
#ifndef GARMIN_NEW_MUSIC_SESSION_GUARD_H
#define GARMIN_NEW_MUSIC_SESSION_GUARD_H
#include <stdint.h>
#include <stddef.h>
#include "../../../native/ui-music-native-adapter/native_adapter.h"
#define MCS_MAGIC 0x4d435331u
#define MCS_CHANNEL 8u
#define MCS_NATIVE_UNAVAILABLE 8
enum mcs_result { MCS_UNCERTIFIED=-200, MCS_REJECTED=-201,
    MCS_WRONG_FRAME=-202, MCS_ALREADY_BOUND=-203 };
typedef int (*mcs_queue_fn)(volatile void *,uint32_t,uint32_t,uint32_t,
                            const void *,uint32_t,const void *);
struct mcs_borrow_frame {
    struct umc_lease media,callback;
    uint32_t actor,generation,epoch,ticket,instance,channel,entered,original_returned;
};
_Static_assert(sizeof(struct mcs_borrow_frame)==72,"ARM complete-pull frame ABI");
struct mcs_event_frame { struct umc_lease media,callback; uint32_t generation,gate; };
struct mcs_guard {
    uint32_t magic,epoch,owner,anchor,held,generation;
    uint32_t permit_ticket,permit_actor,permit_consumed,permit_entered;
    uint32_t selected_ticket,selected_instance,native_mutation;
    uint32_t queue_calls,foreign_rejections,pulls,pull_rejections,full_returns;
    uint32_t queued_generations[4];
    struct umc_controller *control;
    volatile struct umcn_output_view *output;
    volatile struct umcn_slot_view *slots;
    volatile uint8_t *source_record,*pool;
    /* Per-actor pointer to stack-owned frame, pinned until complete return.
     * Nested channel8 pull is rejected, never overwritten. */
    struct mcs_borrow_frame *borrow;
    mcs_queue_fn original_queue;
    int (*normal_context)(void *);
    void *normal_context_arg;
};
extern struct mcs_guard *mcs_bridge_context;
int mcs_init(struct mcs_guard *,struct umc_controller *,
    volatile struct umcn_output_view *,volatile struct umcn_slot_view *,
    volatile uint8_t *,volatile uint8_t *,uint32_t,
    int (*)(void *),void *);
/* Local resident reservation governs only paths actually redirected to this
 * guard. It does NOT certify all native writers or future callbacks. */
int mcs_reserve_scoped(struct mcs_guard *,uint32_t generation);
int mcs_release_scoped(struct mcs_guard *);
int mcs_install_queue_callback(struct mcs_guard *);
int mcs_register_begin(struct mcs_guard *,uint32_t ticket);
int mcs_register_end(struct mcs_guard *,int original_result);
int mcs_queue_dispatch(struct mcs_guard *,volatile void *,uint32_t,uint32_t,
                       uint32_t,const void *,uint32_t,const void *);
int mcs_queue_bridge(volatile void *,uint32_t,uint32_t,uint32_t,const void *,
                     uint32_t,const void *);
/* Invoked AFTER exact original factory/selector return; reads actual native
 * record/provider fields. No host seed or guessed handle layout. */
int mcs_capture_selected(struct mcs_guard *,uint32_t ticket);
int mcs_pull_begin(uint32_t channel,struct mcs_borrow_frame *);
void mcs_pull_end(struct mcs_borrow_frame *,int original_result);
int mcs_reader_admit(struct mcs_guard *,uint32_t instance);
int mcs_mutation_begin(struct mcs_guard *);
void mcs_mutation_end(struct mcs_guard *);
int mcs_event_begin(struct mcs_guard *,uint32_t generation,uint32_t gate,
                     struct mcs_event_frame *);
void mcs_event_end(struct mcs_guard *,struct mcs_event_frame *);
/* Explicit fail-closed witness: no code-path coverage bit/count is authority.
 * This cannot be replaced by callbacks==0 or an idle record snapshot. */
int mcs_native_ownership_snapshot(void *,uint32_t,uint32_t,
                                 struct umcn_ownership_witness *);
/* Actual coherent AV session implementation in NEW owning stream TU.
 * Usable by a future certified reservation; this alone is not ownership. */
int mcs_prepare_session(void *,uint32_t,uint32_t);
void mcs_pull_bridge(void);
#endif
