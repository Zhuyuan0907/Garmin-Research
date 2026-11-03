/* Guarded copying queue/decoder integration for HWID1352/8.00, VM ONLY.
 * AVDTP mutex serializes configuration/callback snapshots and queued epochs.
 * Existing queue IRQ sections protect worker metadata. Real lock ordering,
 * OS tasks, source actor, device pinning and concurrent reload are unproven.
 * Private READY PCM is not DAC output; no new App/menu is installed.
 */
#include "stream.h"
#include "../avdtp-policy/policy.h"
#include "../avdtp-gate/gate.h"
#include "../sbc-prototype/media_queue.h"
#include "../sbc-prototype/memory_output.h"
#include <string.h>

extern int native_music_callback(uint32_t,uint32_t,const void *,const uint8_t *,uint32_t);
extern int owned_media_init(uint32_t),owned_media_reset(void);
extern int owned_media_consume(uint32_t,uint32_t,const void *,const uint8_t *,uint32_t);
extern uint32_t owned_media_next(void);
struct owned_control {
    uint32_t initialized,busy,read,write,count,gather_bytes,rate,channels;
    uint32_t committed,failed,canceled,released,last_ticket;
};
extern volatile struct owned_control owned_media_control;
_Static_assert(sizeof(struct owned_control)==52,"Owned ABI changed");

struct stream_state {
    struct music_guard guard;
    uint32_t prepared,configured,next_session,queue_epoch;
    uint32_t callbacks,enqueued,rejected,consumed,consumer_rejected;
    uint32_t cancellations,private_retired,slot_sessions[4];
    int32_t last_error;
};
volatile struct stream_state music_stream_state;
static int lock(void){return ((int (*)(volatile uint32_t *))0x5523dfu)((volatile uint32_t *)0xf50098u);}
static int unlock(void){return ((int (*)(volatile uint32_t *))0x5523fdu)((volatile uint32_t *)0xf50098u);}
static uint32_t irq_lock(void){return ((uint32_t (*)(void))0x21b6cc)();}
static void irq_unlock(uint32_t f){((void (*)(uint32_t))0x21b6dc)(f);}
static int done(int result){if(unlock()<0)result=-38;music_stream_state.last_error=result;return result;}
static volatile uint8_t *sep(uint32_t i){return (volatile uint8_t *)(0x3a88ef0u+i*32u);}
static volatile uint8_t *channel(uint32_t i){return (volatile uint8_t *)(0x3a88f50u+i*8u);}
static struct music_guard *guard(void){return (struct music_guard *)&music_stream_state.guard;}

/* Handle bytes0..3 are UNINITIALIZED by stock: read only4..11. A snapshot
 * remains coherent under AVDTP lock; never derive an epoch from a reused LCID.
 */
static int snapshot(const void *handle,struct music_native_view *v)
{
    const uint8_t *h=(const uint8_t *)handle;
    if(!h || (uintptr_t)h>UINT32_MAX-12u)return MUSIC_BAD_ARGUMENT;
    uint32_t local=h[4];
    if(local<1u || local>3u || local!=guard()->local_seid)return MUSIC_BAD_SEID;
    volatile uint8_t *s=sep(local-1u);uint32_t context=s[0x11];
    if(*(volatile uint32_t *)s!=(uint32_t)native_music_callback || context>=2u || h[5]!=s[0x10])
        return MUSIC_BAD_SESSION;
    const volatile uint8_t *peer=(const volatile uint8_t *)(0x3a88eb8u+context*28u+0x16u);
    for(uint32_t i=0;i<6u;i++)if(h[6+i]!=peer[i])return MUSIC_BAD_SESSION;
    uint32_t index=s[0xf];if(index>=12u)return MUSIC_BAD_CHANNEL;
    volatile uint8_t *c=channel(index);
    v->state=s[0x12];v->pending=s[0x13];v->local_seid=local;v->remote_seid=s[0x10];
    v->channel_index=index;v->sep_channel_index=s[0xf];
    v->lcid=*(volatile uint16_t *)c;v->type=c[4];v->owner_sep=c[6];v->flags=c[5];
    v->codec_word=*(volatile uint32_t *)(s+0x14);v->local_receive_mtu=*(volatile uint16_t *)(s+12);
    return 0;
}

static int frames(const uint8_t *p,uint32_t n,uint32_t session)
{
    if(!p || n<13u || n>4096u || (uintptr_t)p>UINT32_MAX-n || p[0]>>6!=2u)
        return MUSIC_BAD_PACKET_SIZE;
    uint32_t end=n;
    if(p[0]&0x20u){uint32_t padding=p[n-1];if(!padding || padding>n-12u)return -60;end-=padding;}
    uint32_t off=12u+4u*(p[0]&15u);
    if(off>=end)return -60;
    if(p[0]&0x10u){
        if(end-off<4u)return -60;
        uint32_t extension=4u+4u*((uint32_t)p[off+2]<<8|p[off+3]);
        if(extension>=end-off)return -60;
        off+=extension;
    }
    uint32_t header=p[off++],count=header&15u;
    if(header&0xf0u || !count)return -61; /* Fragmentation unsupported. */
    for(uint32_t i=0;i<count;i++){
        int length=music_guard_frame(guard(),session,p+off,end-off);
        if(length<0)return length;
        off+=(uint32_t)length;
    }
    return off==end?0:-62;
}

/* First configuration only, before any worker is running. This is private
 * output initialization; caller still must establish real channel ownership.
 */
int music_stream_output_prepare(uint32_t channel_index)
{
    if(lock()<0)return -31;
    if(music_stream_state.prepared || guard()->active)return done(MUSIC_BUSY);
    int result=owned_media_init(channel_index);
    if(!result)result=media_queue_init(music_stream_consume,owned_media_reset);
    if(!result)music_stream_state.prepared=1;
    return done(result);
}

/* Original dispatcher already holds AVDTP mutex. Gate before stock accepts
 * configuration: cannot replace a session with pending queue/PCM ownership.
 * Other endpoints and all malformed/unsupported configuration validation
 * remain owned by the frozen compiled preaccept gate.
 */
int music_stream_configuration_gate(uint32_t context,uint32_t signal,uint32_t tx,
                                     const uint8_t *p,uint32_t n)
{
    if(signal==3u && p && n && n<=128u && (uintptr_t)p<=UINT32_MAX-n){
        uint32_t seid=p[0]>>2;
        if(seid>=1u && seid<=3u && *(volatile uint32_t *)sep(seid-1u)==(uint32_t)native_music_callback){
            uint32_t f=irq_lock();
            int busy=!music_stream_state.prepared || guard()->active || media_queue_control.running ||
                media_queue_control.producer_busy || media_queue_control.worker_busy ||
                owned_media_control.busy || owned_media_control.count || music_stream_state.next_session==UINT32_MAX ||
                media_queue_control.epoch>=UINT32_MAX-1u;
            irq_unlock(f);
            if(busy && context<2u){
                uint32_t ch=((volatile uint8_t *)(0x3a88eb8u+context*28u))[0x13];
                if(ch<12u)return ((int (*)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t))0x5756adu)(ch,tx,signal,0,0x31);
            }
        }
    }
    return music_configuration_gate(context,signal,tx,p,n);
}

static int configure(const void *handle,const uint8_t *p,uint32_t n)
{
    const uint8_t *h=(const uint8_t *)handle;
    if(!h || !p || n>126u || (uintptr_t)h>UINT32_MAX-12u || (uintptr_t)p>UINT32_MAX-n)
        return MUSIC_BAD_ARGUMENT;
    uint32_t seid=h[4];if(seid<1u || seid>3u)return MUSIC_BAD_SEID;
    volatile uint8_t *s=sep(seid-1u);
    if(*(volatile uint32_t *)s!=(uint32_t)native_music_callback || s[0x12]!=2u || s[0x13] || h[5]!=s[0x10])
        return MUSIC_BAD_STATE;
    uint8_t body[128];body[0]=(uint8_t)(seid<<2);body[1]=(uint8_t)(h[5]<<2);
    for(uint32_t i=0;i<n;i++)body[i+2]=p[i];
    struct music_config config;int result=music_validate_configuration(body,n+2u,seid,&config);
    if(result)return result;
    if(*(volatile uint32_t *)(s+0x14)!=config.codec_word || !music_stream_state.prepared ||
        guard()->active || music_stream_state.next_session==UINT32_MAX)return MUSIC_BAD_STATE;
    result=music_guard_bind(guard(),++music_stream_state.next_session,&config);
    if(result)return result;
    result=media_queue_begin();
    if(result){(void)music_guard_unbind(guard(),guard()->session);return result;}
    music_stream_state.queue_epoch=media_queue_control.epoch;music_stream_state.configured++;
    return 0;
}

int music_stream_callback(uint32_t event,uint32_t status,const void *handle,
                           const uint8_t *packet,uint32_t length)
{
    if(lock()<0)return -31;
    music_stream_state.callbacks++;
    int result=0;
    if(event==9u && !status)result=configure(handle,packet,length);
    else if(event==0xf2u){
        (void)media_queue_stop();
        if(guard()->active)(void)music_guard_unbind(guard(),guard()->session);
        music_stream_state.cancellations++;
    }else if(event==19u && !status){(void)media_queue_stop();music_stream_state.cancellations++;}
    else if(event==17u && !status && guard()->active && !media_queue_control.running){
        result=media_queue_control.epoch>=UINT32_MAX-1u?MUSIC_BAD_SESSION:media_queue_begin();
        if(!result)music_stream_state.queue_epoch=media_queue_control.epoch;
    }else if(event==0xf1u){
        struct music_native_view v;uint32_t session=guard()->session;
        result=status?MUSIC_BAD_STATE:snapshot(handle,&v);
        if(!result)result=music_guard_packet(guard(),session,&v,length);
        if(!result)result=frames(packet,length,session);
        if(!result && (!media_queue_control.running || media_queue_control.epoch!=music_stream_state.queue_epoch))
            result=MUSIC_BAD_SESSION;
        if(!result){
            uint32_t slot=media_queue_control.write;
            if(slot>=4u)return done(MUSIC_BAD_STATE);
            /* Hold AV lock through bounded copy/metadata publication. A later
             * disconnect/SetConfig cannot change the epoch before enqueue.
             */
            result=media_queue_callback(event,status,handle,packet,length);
            if(!result){music_stream_state.slot_sessions[slot]=session;music_stream_state.enqueued++;}
        }
        if(result)music_stream_state.rejected++;
    }
    return done(result);
}

/* media_queue_step owns worker_busy and its slot throughout this call.
 * Begin cannot replace the stream until it releases that lease. Capture the
 * stored session, not the current LCID. Stop invalidates existing queue epoch;
 * original owned consume rechecks epoch before publishing finite PCM.
 */
int music_stream_consume(uint32_t event,uint32_t status,const void *handle,
                          const uint8_t *packet,uint32_t length)
{
    if(lock()<0)return -31;
    uint32_t slot=media_queue_control.read;
    if(slot>=4u)return done(MUSIC_BAD_STATE);
    uint32_t session=music_stream_state.slot_sessions[slot];
    int result=(session!=guard()->session || !guard()->active || !media_queue_control.running ||
                media_queue_control.epoch!=music_stream_state.queue_epoch)?MUSIC_BAD_SESSION:0;
    if(!result){
        uint8_t local_handle[12]={0};struct music_native_view v;
        uint32_t seid=guard()->local_seid;
        if(seid<1u || seid>3u)result=MUSIC_BAD_SEID;
        else{
            volatile uint8_t *s=sep(seid-1u);uint32_t context=s[0x11];
            if(context>=2u)result=MUSIC_BAD_SESSION;
            else{
                local_handle[4]=(uint8_t)seid;local_handle[5]=(uint8_t)guard()->remote_seid;
                const volatile uint8_t *peer=(const volatile uint8_t *)(0x3a88eb8u+context*28u+0x16u);
                for(uint32_t i=0;i<6u;i++)local_handle[6+i]=peer[i];
                result=snapshot(local_handle,&v);
                if(!result)result=music_guard_packet(guard(),session,&v,length);
            }
        }
    }
    if(!result)result=frames(packet,length,session);
    if(unlock()<0)return -38;
    if(!result)result=owned_media_consume(event,status,handle,packet,length);
    if(result)music_stream_state.consumer_rejected++;else music_stream_state.consumed++;
    music_stream_state.last_error=result;return result;
}

/* Cancel a NEVER-published READY FIFO ticket. Useful for App stop/failed
 * initialization; cannot retire QUEUED/ACTIVE output or a live source actor.
 * This does not emulate a speaker consuming PCM or prove safe module unload.
 */
int music_stream_retire_private(uint32_t ticket)
{
    if(lock()<0)return -31;
    if(memory_output_control.active_ticket || memory_output_control.native_calls ||
       memory_output_control.reader_in_flight || owned_media_control.busy || owned_media_next()!=ticket)
        return done(MUSIC_BUSY);
    int result=memory_output_discard(ticket);
    if(!result){
        uint32_t f=irq_lock();owned_media_control.read=(owned_media_control.read+1u)%4u;
        owned_media_control.count--;owned_media_control.released++;irq_unlock(f);
        music_stream_state.private_retired++;
    }
    return done(result);
}

const void *const music_stream_api[] __attribute__((used,section(".music_stream_api")))={
    (const void *)music_stream_output_prepare,(const void *)music_stream_configuration_gate,
    (const void *)music_stream_callback,(const void *)music_stream_consume,(const void *)music_stream_retire_private
};
