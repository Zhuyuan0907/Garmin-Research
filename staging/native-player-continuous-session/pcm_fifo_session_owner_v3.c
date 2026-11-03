/* NEW bounded raw PCM producer; no SBC/phone/native decoder-worker claim.
 * Includes frozen copied-FIFO consumer unchanged. Each submit copy obtains a
 * controller media/callback lease and publishes only if that admission and
 * the unchanged local queue epoch remain current after the copy. */
#include "music_session_guard_v3.h"
#include "../../native/music-continuous/owned_media.c"

static int unavailable_packet(uint32_t event,uint32_t status,const void *handle,
                            const uint8_t *packet,uint32_t length)
{
    (void)event;(void)status;(void)handle;(void)packet;(void)length;
    return MCS_REJECTED;
}
static int raw_pcm_reset(void)
{return owned_media_control.busy || owned_media_control.count ? -25 : 0;}
int aas_pcm_initialize(uint32_t channel)
{
    if(owned_media_control.initialized)return -25;
    int result=memory_output_configure(channel);
    if(result)return result;
    memset((void *)&owned_media_control,0,sizeof(owned_media_control));
    result=media_queue_init(unavailable_packet,raw_pcm_reset);
    if(result)return result;
    result=media_queue_begin();
    if(!result)owned_media_control.initialized=1;
    return result;
}
int aas_pcm_publish(const uint8_t *pcm,uint32_t bytes)
{
    struct mcs_guard *g=mcs_bridge_context;
    struct mcs_event_frame borrow={0};
    if(!g || g->magic!=MCS_MAGIC)return MCS_REJECTED;
    int r=mcs_event_begin(g,g->generation,UMC_GATE_CONSUMER,&borrow);
    if(r)return r;
    uint32_t f=lock(),epoch=media_queue_control.epoch;
    if(!owned_media_control.initialized || !media_queue_control.running ||
       owned_media_control.busy || owned_media_control.count==4){
        unlock(f);mcs_event_end(g,&borrow);return -25;
    }
    owned_media_control.busy=1;unlock(f);
    int ticket=memory_output_submit(pcm,bytes),result=ticket;
    f=lock();
    if(ticket>0){
        if(!media_queue_control.running || media_queue_control.epoch!=epoch ||
           !umc_media_current(g->control,&borrow.media)){
            result=-24;owned_media_control.canceled++;
        }else{
            tickets[owned_media_control.write]=(uint32_t)ticket;
            owned_media_control.write=(owned_media_control.write+1u)%4u;
            owned_media_control.count++;owned_media_control.committed++;
            owned_media_control.last_ticket=(uint32_t)ticket;
        }
    }
    if(result<0)owned_media_control.failed++;
    owned_media_control.busy=0;unlock(f);
    if(ticket>0 && result<0)(void)memory_output_discard((uint32_t)ticket);
    mcs_event_end(g,&borrow);return result;
}
void aas_pcm_status(uint32_t *p)
{
    p[0]=owned_media_control.initialized;p[1]=owned_media_control.count;
    p[2]=owned_media_control.committed;p[3]=owned_media_control.released;
    p[4]=owned_media_control.last_ticket;
    p[5]=continuous_media_control.offset;p[6]=continuous_media_control.reads;
    p[7]=continuous_media_control.payload_bytes;
    p[8]=continuous_media_control.silence_bytes;
    p[9]=continuous_media_control.packets_consumed;
    p[10]=media_queue_control.running;p[11]=media_queue_control.epoch;
}
