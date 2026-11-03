/* NEW owning TU for exact frozen stream. Retains original native AV locking,
 * validation, queue lifecycle, cancel and source-worker publication. */
#include "music_session_guard_v2.h"
#include "../../../native/sbc-prototype/media_queue.h"
static int mcs_enqueue_scoped(uint32_t,uint32_t,const void *,const uint8_t *,uint32_t);
static int mcs_init_queue(media_fn,reset_fn);
#define music_stream_output_prepare mcs_original_stream_output_prepare
#define music_stream_configuration_gate mcs_original_stream_configuration_gate
#define music_stream_callback mcs_original_stream_callback
#define music_stream_consume mcs_original_stream_consume
#define media_queue_callback mcs_enqueue_scoped
#define media_queue_init mcs_init_queue
#include "../../../native/music-continuous/stream.c"
#undef music_stream_output_prepare
#undef music_stream_configuration_gate
#undef music_stream_callback
#undef music_stream_consume
#undef media_queue_callback
#undef media_queue_init
int music_stream_consume(uint32_t,uint32_t,const void *,const uint8_t *,uint32_t);
static int mcs_init_queue(media_fn consume,reset_fn reset)
{
    (void)consume;
    return media_queue_init(music_stream_consume,reset);
}
static int mcs_enqueue_scoped(uint32_t event,uint32_t status,const void *h,
                             const uint8_t *p,uint32_t n)
{
    struct mcs_guard *g=mcs_bridge_context;uint32_t slot=media_queue_control.write;
    uint32_t generation;int r;
    if(!g || slot>=4u)return MCS_REJECTED;
    /* Called INSIDE original stream's AV lock, before decoder post. Store the
     * captured controller generation beside original slot session/queueepoch. */
    /* Outer callback already holds media + wholecallback leases. In
     * particular it prevents a restart while this captured generation is
     * stored. Do not post from a nested lease release under the AV mutex. */
    generation=g->generation;
    if(!umc_admission(g->control,generation,UMC_GATE_F1))return MCS_REJECTED;
    r=media_queue_callback(event,status,h,p,n);
    if(!r)g->queued_generations[slot]=generation;
    return r;
}
int music_stream_output_prepare(uint32_t channel_index)
{
    if(channel_index!=8u)return UMCN_UNSUPPORTED_ROUTE;
    return mcs_original_stream_output_prepare(channel_index);
}
int music_stream_configuration_gate(uint32_t context,uint32_t signal,uint32_t tx,
                                     const uint8_t *p,uint32_t n)
{
    struct mcs_guard *g=mcs_bridge_context;
    if(signal==3u && p && n && n<=128u && (uintptr_t)p<=UINT32_MAX-n){
        uint32_t seid=p[0]>>2;
        if(seid>=1u && seid<=3u &&
           *(volatile uint32_t *)sep(seid-1u)==(uint32_t)native_music_callback &&
           (!g || !umc_admission(g->control,g->generation,UMC_GATE_CONFIG))){
            if(context<2u){uint32_t ch=((volatile uint8_t *)(0x3a88eb8u+context*28u))[0x13];
                if(ch<12u)return ((int (*)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t))
                    0x5756adu)(ch,tx,signal,0,0x31);}
            return MCS_REJECTED;
        }
    }
    return mcs_original_stream_configuration_gate(context,signal,tx,p,n);
}
int music_stream_callback(uint32_t event,uint32_t status,const void *h,
                            const uint8_t *p,uint32_t n)
{
    struct mcs_guard *g=mcs_bridge_context;struct mcs_event_frame b={0};
    struct umc_lease callback={0};uint32_t gate=0;int r;
    if(!g || g->magic!=MCS_MAGIC)return MCS_REJECTED;
    if(event==9u)gate=UMC_GATE_CONFIG;
    else if(event==17u)gate=UMC_GATE_EVENT17;
    else if(event==0xf1u)gate=UMC_GATE_F1;
    if(gate){r=mcs_event_begin(g,g->generation,gate,&b);if(r)return r;}
    else {r=umc_callback_acquire(g->control,&callback);if(r)return r;}
    r=mcs_original_stream_callback(event,status,h,p,n);
    if(gate)mcs_event_end(g,&b);
    else (void)umc_callback_release(g->control,&callback);
    return r;
}
int music_stream_consume(uint32_t event,uint32_t status,const void *h,
                         const uint8_t *p,uint32_t n)
{
    struct mcs_guard *g=mcs_bridge_context;struct mcs_event_frame b={0};
    uint32_t slot=media_queue_control.read;int r;
    if(!g || slot>=4u)return MCS_REJECTED;
    r=mcs_event_begin(g,g->queued_generations[slot],UMC_GATE_CONSUMER,&b);
    if(r)return r;
    r=mcs_original_stream_consume(event,status,h,p,n);
    mcs_event_end(g,&b);return r;
}
int mcs_prepare_session(void *context,uint32_t generation,uint32_t epoch)
{
    struct mcs_guard *g=context;int r=0;
    if(!g || g->magic!=MCS_MAGIC || !g->held || g->generation!=generation ||
       g->epoch!=epoch || g->control->config.route!=8u)return MCS_REJECTED;
    if(g->control->adapters.current_actor(g->control->adapters.context)!=g->owner)
        return UMC_WRONG_OWNER;
    if(lock()<0)return -31;
    if(!music_stream_state.prepared ||
       (music_runtime_status()&(MUSIC_RUNTIME_READY|MUSIC_RUNTIME_BUSY))!=MUSIC_RUNTIME_READY ||
       media_queue_control.producer_busy || media_queue_control.worker_busy ||
       media_queue_control.count || owned_media_control.busy || owned_media_control.count)
        r=MUSIC_BUSY;
    else if(guard()->active && !media_queue_control.running){
        uint32_t seid=guard()->local_seid;
        uint8_t h[12]={0};struct music_native_view v;
        if(seid<1u || seid>3u)r=MUSIC_BAD_SEID;
        else {
            volatile uint8_t *s=sep(seid-1u);uint32_t ctx=s[0x11];
            if(ctx>=2u)r=MUSIC_BAD_SESSION;
            else {
                h[4]=(uint8_t)seid;h[5]=s[0x10];
                for(uint32_t i=0;i<6u;i++)h[6+i]=
                    ((volatile uint8_t *)(0x3a88eb8u+ctx*28u+0x16u))[i];
                r=snapshot(h,&v);
                if(!r)r=music_guard_packet(guard(),guard()->session,&v,13u);
                if(!r)r=media_queue_control.epoch>=UINT32_MAX-1u?
                    MUSIC_BAD_SESSION:media_queue_begin();
                if(!r)music_stream_state.queue_epoch=media_queue_control.epoch;
            }
        }
    }
    /* No active guard: arm reception only. Never fabricate SEP/remote START,
     * native channel, codec, session ID, clock, mixer state or pending ACK. */
    return done(r);
}
const void *const mcs_stream_api[] __attribute__((used,section(".mcs_stream_api")))={
    (const void *)music_stream_callback,(const void *)music_stream_consume,
    (const void *)music_stream_configuration_gate,(const void *)mcs_prepare_session
};
