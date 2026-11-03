/* Offline whole-packet SBC/FIR -> owned persistent PCM FIFO backend.
 * One producer owns decode/FIR and submit; native source lifecycle remains
 * the explicit serialized actor contract in memory_output.h. No live hooks.
 */
#include <stdint.h>
#include "music_session_guard_v4.h"
#include <string.h>
#include "decoder.h"
#include "pcm_converter.h"
#include "memory_output.h"
#include "media_queue.h"
#include "media_worker.h"
#include "playback_imports.h"
extern int owned_packet_parse(uint32_t,uint32_t,const void *,const uint8_t *,uint32_t);
struct owned_media_control {
    uint32_t initialized, busy, read, write, count, gather_bytes, rate, channels;
    uint32_t committed, failed, canceled, released, last_ticket;
};
volatile struct owned_media_control owned_media_control;
static uint32_t tickets[4];
static int16_t source_pcm[256], converted_pcm[128];
static uint8_t gather[4096] __attribute__((section(".gather"), aligned(4096)));

static uint32_t lock(void) { return ((uint32_t (*)(void))0x21b6cc)(); }
static void unlock(uint32_t saved) { ((void (*)(uint32_t))0x21b6dc)(saved); }
static int reset_codec(void)
{
    pcm_converter_clear();
    owned_media_control.rate=owned_media_control.channels=0;
    return garmin_sbc_reset();
}
int owned_media_reset(void)
{
    /* Starting a new stream cannot mix with previously queued PCM. */
    if (owned_media_control.busy || owned_media_control.count) return -25;
    return reset_codec();
}
int owned_media_output_ready(void)
{
    uint32_t saved=lock();
    int ready=0;
    if (owned_media_control.initialized && !owned_media_control.busy &&
        owned_media_control.count<4 && memory_output_control.initialized)
        for (uint32_t i=0;i<4;i++) if (!memory_output_slots[i].state) { ready=1; break; }
    unlock(saved);
    /* Single producer contract excludes another submit between this check
     *and commit. No decoder/FIR advancement while all PCM slots are held.
     */
    return ready;
}
int owned_media_submit_frame(const uint8_t *input,uint32_t length,struct decoder_result *result)
{
    int status=garmin_sbc_decode_frame(input,length,(uint8_t *)source_pcm,sizeof(source_pcm),result);
    if (status) return status;
    if (!owned_media_control.rate) {
        status=pcm_converter_reset(result->sample_rate,result->channels);
        if (status) return status;
        owned_media_control.rate=result->sample_rate;
        owned_media_control.channels=result->channels;
    } else if (owned_media_control.rate!=result->sample_rate ||
               owned_media_control.channels!=result->channels) return DECODER_FORMAT_CHANGE;
    uint32_t bytes=0;
    status=pcm_converter_process(source_pcm,result->samples_per_channel,converted_pcm,
                                 sizeof(converted_pcm),&bytes);
    if (status) return status;
    if (bytes>sizeof(gather)-owned_media_control.gather_bytes) return -4;
    memcpy(gather+owned_media_control.gather_bytes,converted_pcm,bytes);
    owned_media_control.gather_bytes+=bytes;
    result->written=bytes; result->sample_rate=16000; result->channels=1;
    result->samples_per_channel=bytes/2;
    return 0;
}
int owned_media_consume(uint32_t event,uint32_t status,const void *handle,
                        const uint8_t *packet,uint32_t length)
{
    struct mcs_guard *g=mcs_bridge_context;
    struct mcs_event_frame borrow={0};
    if(!g || g->magic!=MCS_MAGIC ||
       g->control->adapters.current_actor(g->control->adapters.context)!=g->owner ||
       *(volatile uint32_t *)(g->source_record+0x160u)!=(uint32_t)(uintptr_t)mcs_queue_bridge)
        return MCS_REJECTED;
    int admitted=mcs_event_begin(g,g->generation,UMC_GATE_CONSUMER,&borrow);
    if(admitted)return admitted;
    if(!owned_media_output_ready()){mcs_event_end(g,&borrow);return -25;}
    uint32_t saved=lock(), epoch=media_queue_control.epoch;
    owned_media_control.busy=1; owned_media_control.gather_bytes=0;
    unlock(saved);
    int result=owned_packet_parse(event,status,handle,packet,length);
    saved=lock();
    if (!media_queue_control.running || media_queue_control.epoch!=epoch ||
                !umc_media_current(g->control,&borrow.media) ||
                *(volatile uint32_t *)(g->source_record+0x160u)!=(uint32_t)(uintptr_t)mcs_queue_bridge) {
        result=-24; owned_media_control.canceled++;
    }
    unlock(saved);
    /* No prefix is published if a later frame fails CRC or stop precedes commit.
     * Decoder/FIR reset discards speculative history after failed packets.
     */
    if (!result && owned_media_control.gather_bytes) {
        int ticket=memory_output_submit(gather,owned_media_control.gather_bytes);
        if (ticket<=0) result=ticket;
        else {
            saved=lock();
            if (!media_queue_control.running || media_queue_control.epoch!=epoch ||
                !umc_media_current(g->control,&borrow.media) ||
                *(volatile uint32_t *)(g->source_record+0x160u)!=(uint32_t)(uintptr_t)mcs_queue_bridge) {
                result=-24; owned_media_control.canceled++;
            } else {
                tickets[owned_media_control.write]=(uint32_t)ticket;
                owned_media_control.write=(owned_media_control.write+1u)%4u;
                owned_media_control.count++; owned_media_control.committed++;
                owned_media_control.last_ticket=(uint32_t)ticket;
            }
            unlock(saved);
            if (result) (void)memory_output_discard((uint32_t)ticket);
        }
    }
    if (result) { owned_media_control.failed++; (void)reset_codec(); }
    saved=lock(); owned_media_control.busy=0; unlock(saved);
    mcs_event_end(g,&borrow);
    return result;
}
int owned_media_init(uint32_t channel)
{
    if (owned_media_control.initialized) return -25;
    int result=memory_output_configure(channel);
    if (result) return result;
    memset((void *)&owned_media_control,0,sizeof(owned_media_control));
    result=media_queue_init(owned_media_consume,owned_media_reset);
    if (!result) owned_media_control.initialized=1;
    return result;
}
uint32_t owned_media_next(void)
{
    uint32_t saved=lock();
    uint32_t ticket=owned_media_control.count ? tickets[owned_media_control.read] : 0;
    unlock(saved); return ticket;
}
/* Finite ticket release is not a persistent source retirement API. */
int owned_media_release(uint32_t ticket) { (void)ticket;return -25; }

struct continuous_media_control {
    uint32_t offset,reads,payload_bytes,silence_bytes,packets_consumed,underflows;
    uint32_t canceled_reads,capacity_posts;
};
volatile struct continuous_media_control continuous_media_control;

/* Mixer reader is the sole FIFO consumer. Producer owns codec/submit only.
 * Never free or advance a FIFO buffer before its unlocked copy completes.
 * Native anchor retirement is independent of FIFO reuse and checks this lease.
 * Stop invalidates epoch; no new producer publication is allowed thereafter.
 */
uint32_t continuous_media_read(uint8_t *output,uint32_t capacity)
{
    if(!output || !capacity || capacity>8192u || (capacity&1u) ||
       (uintptr_t)output>UINT32_MAX-capacity)return 0;
    uint32_t saved=lock(),epoch=media_queue_control.epoch,written=0,freed=0;
    int running=media_queue_control.running;
    unlock(saved);
    if(!running)return 0;
    for(uint32_t visits=0;visits<4u && written<capacity;visits++){
        saved=lock();
        if(!media_queue_control.running || media_queue_control.epoch!=epoch ||
           !owned_media_control.count){unlock(saved);break;}
        uint32_t ticket=tickets[owned_media_control.read],index=ticket&3u;
        volatile struct owned_slot *slot=&memory_output_slots[index];
        uint32_t offset=continuous_media_control.offset;
        if(!ticket || slot->ticket!=ticket || slot->state!=2u || slot->in_flight || offset>=slot->bytes){
            unlock(saved);break;
        }
        uint32_t n=slot->bytes-offset;
        if(n>capacity-written)n=capacity-written;
        slot->in_flight++;
        /* pcm_pages are exact local copied buffers, not runtime-imported host
         * pointers; their addresses are fixed by this component linker. */
        const uint8_t *source=(const uint8_t *)(uintptr_t)playback_pcm_pages[index];
        unlock(saved);
        memcpy(output+written,source+offset,n);
        saved=lock();slot->in_flight--;slot->reads++;
        if(media_queue_control.running && media_queue_control.epoch==epoch){
            written+=n;continuous_media_control.offset=offset+n;
            continuous_media_control.payload_bytes+=n;
            if(offset+n==slot->bytes){
                slot->state=0;owned_media_control.read=(owned_media_control.read+1u)%4u;
                owned_media_control.count--;owned_media_control.released++;
                continuous_media_control.offset=0;continuous_media_control.packets_consumed++;
                freed++;
            }
        }
        unlock(saved);
    }
    saved=lock();running=media_queue_control.running && media_queue_control.epoch==epoch;
    continuous_media_control.reads++;
    if(!running)continuous_media_control.canceled_reads++;
    else if(written<capacity){continuous_media_control.underflows++;
        continuous_media_control.silence_bytes+=capacity-written;}
    int wake=freed && running && media_queue_control.count && media_worker_state.tcb &&
        !media_worker_state.quit_requested;
    if(wake)continuous_media_control.capacity_posts++;
    unlock(saved);
    if(!running){memset(output,0,capacity);return 0;}
    if(written<capacity)memset(output+written,0,capacity-written);
    if(wake)(void)media_worker_notify_capacity();
    return capacity; /* temporary underrun is silence, never finite EOF */
}

/* Only source actor calls after native stop/cleanup/list removal/anchor release.
 * READY slots were never borrowed by native code; count is not anchor ownership.
 */
int continuous_media_cancel_ready(void)
{
    uint32_t saved=lock();
    if(owned_media_control.busy || memory_output_control.reader_in_flight ||
       memory_output_control.active_ticket){unlock(saved);return -25;}
    uint32_t count=0;
    while(owned_media_control.count && count<4u){
        uint32_t ticket=tickets[owned_media_control.read];
        volatile struct owned_slot *slot=&memory_output_slots[ticket&3u];
        if(!ticket || slot->ticket!=ticket || slot->state!=2u || slot->in_flight){unlock(saved);return -31;}
        slot->state=0;owned_media_control.read=(owned_media_control.read+1u)%4u;
        owned_media_control.count--;owned_media_control.released++;count++;
    }
    continuous_media_control.offset=0;unlock(saved);return (int)count;
}

const void *const owned_media_api[] __attribute__((used,section(".owned_api")))={
    (const void *)owned_media_init,(const void *)owned_media_reset,
    (const void *)owned_media_output_ready,(const void *)owned_media_consume,
    (const void *)owned_media_next,(const void *)owned_media_release
};
