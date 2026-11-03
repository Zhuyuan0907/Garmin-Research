/* Offline research ABI; pinned objects, one controller, one worker. */
#ifndef GARMIN_OS20_WORKER_FIFO_V1_H
#define GARMIN_OS20_WORKER_FIFO_V1_H
#include "../../native/os20-task-bridge/resident_music_v1.h"
#include "../../native/sbc-prototype/media_queue.h"
#include "../../native/sbc-prototype/memory_output.h"
struct fifo_owned_control_v1 {
    uint32_t initialized,busy,read,write,count,gather_bytes,rate,channels;
    uint32_t committed,failed,canceled,released,last_ticket;
};
struct fifo_read_control_v1 {
    uint32_t offset,reads,payload_bytes,silence_bytes,packets_consumed,underflows;
    uint32_t canceled_reads,capacity_posts;
};
extern volatile struct fifo_owned_control_v1 owned_media_control;
extern volatile struct fifo_read_control_v1 continuous_media_control;
extern int owned_media_init(uint32_t);
extern uint32_t owned_media_next(void);
extern uint32_t continuous_media_read(uint8_t *,uint32_t);
struct fifo_observations_v1 {
    uint32_t worker_initialize_returns;
    int32_t worker_initialize_status;
    uint32_t packet_copies,packet_poisonings,packet_count_at_poison[4];
    uint32_t tickets[4],worker_producer_actors[4],controller_consumer_actors[5];
    uint32_t decoder_calls,decoder_returns,decoder_actors[4];
    uint32_t read_returns[5],count_after_read[5],offset_after_read[5];
    uint32_t slot_state_after_read[5],slot_inflight_after_read[5];
    int32_t stale_discard,odd_read,null_read,stopped_callback,pending_start;
    uint32_t queue_epoch_before_stop,queue_epoch_after_stop;
    uint32_t held_ticket,held_bytes,held_state,held_offset,held_count;
    uint32_t observed_slot_generation,original_factory_calls,original_mixer_calls;
};
_Static_assert(sizeof(struct fifo_owned_control_v1)==52,"owned FIFO ABI");
_Static_assert(sizeof(struct fifo_read_control_v1)==32,"continuous FIFO ABI");
extern volatile struct fifo_observations_v1 fifo_observations_v1;
void fifo_worker_core_v1(void *);
void fifo_controller_core_v1(void);
void fifo_idle_core_v1(void);
void fifo_failure_v1(void);
void fifo_idle_checkpoint_v1(void);
#endif
