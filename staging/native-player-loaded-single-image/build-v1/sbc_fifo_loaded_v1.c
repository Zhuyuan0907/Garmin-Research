/* Resident compiled ingress. This is not a recovered SEP-registration API.
 * A native callback provider must publish aas_media_ingress only after Stage1.
 * This bounded image never unloads or releases its scoped ownership guard. */
#include "music_session_guard_v4.h"
#include "owned_media_loaded_v1.c"
extern volatile uint32_t mh_source_tcb,mh_initialized;
extern volatile int32_t mh_initialize_result;
#define SBI_POST ((void (*)(uint32_t,uint32_t))0x2fcf44u)
volatile uint32_t sbi_callbacks,sbi_accepted,sbi_rejected,sbi_ingress_posts;
volatile uint32_t sbi_capacity_posts,sbi_source_events,sbi_processed,sbi_errors;
volatile int32_t sbi_last_result,sbi_last_decode_error;

int aas_pcm_initialize(uint32_t channel)
{ int r=owned_media_init(channel);return r?r:media_queue_begin(); }
uint32_t aas_packet_ticket(void){return owned_media_control.last_ticket;}

/* Exact original application callback ABI: F1,status,temporary handle,
 * packet pointer,length. Only copied bytes survive the native caller.
 * Both typed leases cover borrowed input validation and copied queue publication.
 * They end before POST so first native registration can require quiescence.
 * Module code stays resident through the foreign callback full return; this
 * adapter has no unload or native STOP_DONE path.
 * No callback/temporary handle/payload pointer is retained in the queue. */
int aas_media_ingress(uint32_t event,uint32_t status,const void *handle,
                      const uint8_t *packet,uint32_t bytes)
{
    struct mcs_guard *g=mcs_bridge_context;
    struct mcs_event_frame frame={0};
    uint32_t saved=lock();sbi_callbacks++;unlock(saved);
    int r=MCS_REJECTED;
    if(!g || g->magic!=MCS_MAGIC || !mh_source_tcb || !mh_initialized ||
       mh_initialize_result || g->owner!=mh_source_tcb ||
       *(volatile uint32_t *)(g->source_record+0x160u)!=(uint32_t)(uintptr_t)mcs_queue_bridge)
        goto finish;
    r=mcs_event_begin(g,g->generation,UMC_GATE_F1,&frame);
    if(r)goto finish;
    r=media_queue_callback(event,status,handle,packet,bytes);
    if(!r && (!umc_media_current(g->control,&frame.media) ||
       *(volatile uint32_t *)(g->source_record+0x160u)!=(uint32_t)(uintptr_t)mcs_queue_bridge))
        r=MCS_REJECTED;
    if(!r){
        saved=lock();sbi_accepted++;sbi_ingress_posts++;unlock(saved);
    }
    mcs_event_end(g,&frame);
    /* No foreign payload/temporary handle is read after this point. The queue
     * owns a complete copy. Resident code/guard remains pinned across POST;
     * Stop may close admission, in which case Source ignores the wake. */
    if(!r)SBI_POST(g->owner,UMC_SOURCE_EVENT);
finish:
    saved=lock();sbi_last_result=r;if(r)sbi_rejected++;unlock(saved);
    return r;
}

/* Four-argument caller convenience, not native SEP registration.
 * The compiler supplies the real fifth callback argument on its own stack. */
int sbi_receive_packet(uint32_t event,uint32_t status,const uint8_t *packet,uint32_t bytes)
{return aas_media_ingress(event,status,0,packet,bytes);}

void sbi_capacity_wake(void)
{
    struct mcs_guard *g=mcs_bridge_context;
    if(!g || g->magic!=MCS_MAGIC || !mh_initialized || mh_initialize_result ||
       g->owner!=mh_source_tcb || !media_queue_control.running ||
       !media_queue_control.count || !mcs_reader_admit(g,g->selected_instance))return;
    uint32_t saved=lock();sbi_capacity_posts++;unlock(saved);
    /* The original full mixer frame remains borrowed. Source may run now,
     * copy into freed private FIFO slots, then yield back to that mixer frame.
     * No anchor/list/selection or native source mutation is performed. */
    SBI_POST(g->owner,UMC_SOURCE_EVENT);
}

void aas_pcm_status(uint32_t *p)
{
 p[0]=owned_media_control.initialized;p[1]=owned_media_control.count;
 p[2]=owned_media_control.committed;p[3]=owned_media_control.released;
 p[4]=owned_media_control.last_ticket;p[5]=continuous_media_control.offset;
 p[6]=continuous_media_control.reads;p[7]=continuous_media_control.payload_bytes;
 p[8]=continuous_media_control.silence_bytes;p[9]=continuous_media_control.packets_consumed;
 p[10]=media_queue_control.running;p[11]=media_queue_control.epoch;
}
void sbi_status(uint32_t *p)
{
 p[0]=sbi_callbacks;p[1]=sbi_accepted;p[2]=sbi_rejected;p[3]=sbi_ingress_posts;
 p[4]=sbi_capacity_posts;p[5]=sbi_source_events;p[6]=sbi_processed;p[7]=sbi_errors;
 p[8]=(uint32_t)sbi_last_result;p[9]=(uint32_t)sbi_last_decode_error;
}
