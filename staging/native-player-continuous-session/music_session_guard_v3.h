/* NEW continuous-session admission prototype. Offline/resident only.
 * A native session is identified by scoped epoch plus controller generation;
 * a FIFO ticket identifies only one copied buffer and may be recycled.
 * Neither a matching provider nor this local reservation certifies native
 * channel exclusivity. There is no hardware, installed hook or STOP_DONE. */
#ifndef GARMIN_CONTINUOUS_SESSION_GUARD_V3_H
#define GARMIN_CONTINUOUS_SESSION_GUARD_V3_H
#include <stdint.h>
#include <stddef.h>
#include "../../native/ui-music-native-adapter/native_adapter.h"
#define MCS_MAGIC 0x4d435333u
#define MCS_CHANNEL 8u
#define MCS_NATIVE_UNAVAILABLE 8
enum mcs_result { MCS_UNCERTIFIED=-200, MCS_REJECTED=-201,
    MCS_WRONG_FRAME=-202, MCS_ALREADY_BOUND=-203 };
typedef int (*mcs_queue_fn)(volatile void *,uint32_t,uint32_t,uint32_t,
                            const void *,uint32_t,const void *);
struct mcs_borrow_frame {
    struct umc_lease media,callback;
    uint32_t actor,generation,epoch,session,instance,channel,entered,original_returned;
};
_Static_assert(sizeof(struct mcs_borrow_frame)==72,"ARM complete-pull frame ABI");
struct mcs_event_frame { struct umc_lease media,callback; uint32_t generation,gate; };
struct mcs_guard {
    uint32_t magic,epoch,owner,anchor,held,generation;
    uint32_t permit_ticket,permit_actor,permit_consumed,permit_entered;
    uint32_t selected_session,selected_instance,native_mutation;
    uint32_t queue_calls,foreign_rejections,pulls,pull_rejections,full_returns;
    /* Immutable bootstrap audit token for the native registration. After
     * publication it does NOT claim that its old FIFO slot remains owned.
     * The unchanged output.active_ticket field retains this legacy source
     * registration token; its associated slot can hold ticket8,12,... later. */
    uint32_t registration_ticket;
    struct umc_controller *control;
    volatile struct umcn_output_view *output;
    volatile struct umcn_slot_view *slots;
    volatile uint8_t *source_record,*pool;
    struct mcs_borrow_frame *borrow;
    mcs_queue_fn original_queue;
    int (*normal_context)(void *);
    void *normal_context_arg;
};
extern struct mcs_guard *mcs_bridge_context;
int mcs_init(struct mcs_guard *,struct umc_controller *,
    volatile struct umcn_output_view *,volatile struct umcn_slot_view *,
    volatile uint8_t *,volatile uint8_t *,uint32_t,int (*)(void *),void *);
int mcs_reserve_scoped(struct mcs_guard *,uint32_t generation);
int mcs_release_scoped(struct mcs_guard *);
int mcs_install_queue_callback(struct mcs_guard *);
int mcs_register_begin(struct mcs_guard *,uint32_t ticket);
int mcs_register_end(struct mcs_guard *,int original_result);
int mcs_queue_dispatch(struct mcs_guard *,volatile void *,uint32_t,uint32_t,
                       uint32_t,const void *,uint32_t,const void *);
int mcs_queue_bridge(volatile void *,uint32_t,uint32_t,uint32_t,const void *,
                     uint32_t,const void *);
/* AFTER original selector/factory return; session is current scoped epoch.
 * Reads actual native record/provider/anchor. No recyclable ticket argument. */
int mcs_capture_selected(struct mcs_guard *,uint32_t session);
int memory_output_bind_selected_session(uint32_t session);
int memory_output_release_session(uint32_t session);
int mcs_pull_begin(uint32_t channel,struct mcs_borrow_frame *);
void mcs_pull_end(struct mcs_borrow_frame *,int original_result);
int mcs_reader_admit(struct mcs_guard *,uint32_t instance);
int mcs_mutation_begin(struct mcs_guard *);
void mcs_mutation_end(struct mcs_guard *);
int mcs_event_begin(struct mcs_guard *,uint32_t generation,uint32_t gate,
                     struct mcs_event_frame *);
void mcs_event_end(struct mcs_guard *,struct mcs_event_frame *);
int mcs_native_ownership_snapshot(void *,uint32_t,uint32_t,
                                 struct umcn_ownership_witness *);
void mcs_pull_bridge(void);
#endif
