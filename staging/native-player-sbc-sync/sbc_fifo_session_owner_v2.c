/* Compressed queue processing runs on the real compiled source task.
 * Incoming packet bytes below are explicit offline fixtures, not Bluetooth. */
#include "music_session_guard_v4.h"
#include "owned_media_typed_v2.c"
int aas_pcm_initialize(uint32_t channel)
{ int r=owned_media_init(channel);return r?r:media_queue_begin(); }
int aas_packet_process(const uint8_t *packet,uint32_t bytes)
{ int r=media_queue_callback(0xf1u,0,0,packet,bytes);return r?r:media_queue_step(); }
uint32_t aas_packet_ticket(void){return owned_media_control.last_ticket;}
void aas_pcm_status(uint32_t *p)
{
 p[0]=owned_media_control.initialized;p[1]=owned_media_control.count;
 p[2]=owned_media_control.committed;p[3]=owned_media_control.released;
 p[4]=owned_media_control.last_ticket;p[5]=continuous_media_control.offset;
 p[6]=continuous_media_control.reads;p[7]=continuous_media_control.payload_bytes;
 p[8]=continuous_media_control.silence_bytes;p[9]=continuous_media_control.packets_consumed;
 p[10]=media_queue_control.running;p[11]=media_queue_control.epoch;
}
