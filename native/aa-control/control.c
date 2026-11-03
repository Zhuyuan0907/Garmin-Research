/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "control.h"
#include "pb_encode.h"
#include "pb_decode.h"
#include <string.h>
#define MAGIC 0x41434331u
#define QCOUNT 4u
#define SLOT_BYTES 8192u
#define TYPE_INPUT 1u
#define TYPE_VIDEO 3u
#define TYPE_AUDIO 4u
#define T(name) f1x_aasdk_proto_messages_##name
#define D(name) f1x_aasdk_proto_messages_##name##_fields
enum { ACTION_NONE=0, ACTION_DISCOVERY=1, ACTION_OPEN=2, ACTION_SETUP=3,
       ACTION_BIND=4, ACTION_ACK=5, ACTION_SHUTDOWN=6 };
struct channel {
    uint8_t offered,type,ack_pending,focus_pending;
    int state;
    int32_t session;
    uint32_t config_count,selected,key_count,keys[64];
};
struct output {
    uint32_t token;
    uint8_t channel,flags,action,success;
    size_t bytes;
    uint8_t data[SLOT_BYTES];
};
struct control {
    uint32_t magic,session,next_token;
    int error,busy,discovery_pending,discovered,closed,shutdown_pending;
    aa_control_provider provider;
    void *provider_arg;
    uint32_t head,count;
    size_t discovery_n;
    uint8_t discovery[SLOT_BYTES-2];
    struct channel channels[9];
    struct output queue[QCOUNT];
};
static void zero(void *p,size_t n){volatile uint8_t *b=p;while(n--)*b++=0;}
static int valid(struct control *c,uint32_t s){
    if(!c||c->magic!=MAGIC)return AA_CONTROL_E_ARGUMENT;
    if(c->session!=s)return AA_CONTROL_E_SESSION;
    if(c->busy)return AA_CONTROL_E_REENTRANT;
    if(c->error)return c->error;
    if(c->closed)return AA_CONTROL_E_STATE;
    return 0;
}
static int fail(struct control *c,int error){
    zero(c->queue,sizeof(c->queue));c->count=0;c->error=error;return error;
}
static int decode(const pb_msgdesc_t *d,void *out,const uint8_t *p,size_t n){
    pb_istream_t in=pb_istream_from_buffer(p,n);
    return pb_decode(&in,d,out)&&in.bytes_left==0;
}
static int emit(struct control *c,uint8_t ch,uint8_t flags,uint16_t id,
                const pb_msgdesc_t *d,const void *data,uint8_t action,int success){
    struct output *q;pb_ostream_t out;
    if(c->count==QCOUNT)return AA_CONTROL_PAUSED;
    if(c->next_token==UINT32_MAX)return fail(c,AA_CONTROL_E_STATE);
    q=&c->queue[(c->head+c->count)%QCOUNT];memset(q,0,sizeof(*q));
    q->data[0]=(uint8_t)(id>>8);q->data[1]=(uint8_t)id;
    out=pb_ostream_from_buffer(q->data+2,sizeof(q->data)-2);
    if(!pb_encode(&out,d,data))return fail(c,AA_CONTROL_E_PROTOBUF);
    q->bytes=out.bytes_written+2;q->channel=ch;q->flags=flags;
    q->token=++c->next_token;q->action=action;q->success=(uint8_t)!!success;
    c->count++;return 0;
}
static int discovery(struct control *c){
    struct output *q;
    if(c->count==QCOUNT)return AA_CONTROL_PAUSED;
    if(c->next_token==UINT32_MAX)return fail(c,AA_CONTROL_E_STATE);
    q=&c->queue[(c->head+c->count)%QCOUNT];memset(q,0,sizeof(*q));
    q->data[0]=0;q->data[1]=6;memcpy(q->data+2,c->discovery,c->discovery_n);
    q->bytes=c->discovery_n+2;q->channel=0;q->flags=AA_MESSAGE_ENCRYPTED;
    q->token=++c->next_token;q->action=ACTION_DISCOVERY;q->success=1;
    c->count++;c->discovery_pending=1;return 0;
}
static int provide(struct control *c,uint8_t ch,uint32_t event,int32_t session,
                   uint32_t config,uint64_t timestamp,const uint8_t *p,size_t n){
    int r;c->busy=1;r=c->provider(c->provider_arg,ch,event,session,config,timestamp,p,n);
    c->busy=0;return r;
}
uint32_t aa_control_context_bytes(void){return sizeof(struct control);}
int aa_control_init(void *v,uint32_t s,const T(ServiceDiscoveryResponse) *profile,
                    aa_control_provider provider,void *arg){
    struct control *c=v;pb_ostream_t out;size_t i,j;uint32_t id,type;
    if(!c||!s||!profile||!provider||!profile->channels_count||
       profile->channels_count>sizeof(profile->channels)/sizeof(profile->channels[0]))
        return AA_CONTROL_E_ARGUMENT;
    memset(c,0,sizeof(*c));
    for(i=0;i<profile->channels_count;i++){
        const f1x_aasdk_proto_data_ChannelDescriptor *p=&profile->channels[i];
        id=p->channel_id;type=0;
        if(id>8||id==0||id==2||id==7||id==8||c->channels[id].offered||
           p->has_sensor_channel||p->has_av_input_channel||p->has_bluetooth_channel||
           p->has_navigation_channel||p->has_vendor_extension_channel||
           p->has_av_channel==p->has_input_channel)return AA_CONTROL_E_ARGUMENT;
        if(p->has_input_channel){
            if(id!=1||p->input_channel.supported_keycodes_count>64||
               p->input_channel.has_touch_pad_config)return AA_CONTROL_E_ARGUMENT;
            if(p->input_channel.has_touch_screen_config&&
              (!p->input_channel.touch_screen_config.width||!p->input_channel.touch_screen_config.height))
                return AA_CONTROL_E_ARGUMENT;
            type=TYPE_INPUT;
            c->channels[id].key_count=p->input_channel.supported_keycodes_count;
            for(j=0;j<p->input_channel.supported_keycodes_count;j++)
                c->channels[id].keys[j]=p->input_channel.supported_keycodes[j];
        }else{
            const f1x_aasdk_proto_data_AVChannel *a=&p->av_channel;
            if(a->stream_type==3){
                if(id!=3||!a->video_configs_count||a->audio_configs_count||
                   a->video_configs_count>sizeof(a->video_configs)/sizeof(a->video_configs[0]))
                    return AA_CONTROL_E_ARGUMENT;
                for(j=0;j<a->video_configs_count;j++)
                    if(a->video_configs[j].video_resolution<1||a->video_configs[j].video_resolution>3||
                       a->video_configs[j].video_fps<1||a->video_configs[j].video_fps>2)
                        return AA_CONTROL_E_ARGUMENT;
                type=TYPE_VIDEO;c->channels[id].config_count=a->video_configs_count;
            }else if(a->stream_type==1){
                if(id<4||id>6||a->audio_type!=(id==4?3:id==5?1:2)||
                   !a->audio_configs_count||a->video_configs_count||
                   a->audio_configs_count>sizeof(a->audio_configs)/sizeof(a->audio_configs[0]))
                    return AA_CONTROL_E_ARGUMENT;
                for(j=0;j<a->audio_configs_count;j++){
                    const f1x_aasdk_proto_data_AudioConfig *audi=&a->audio_configs[j];
                    if(audi->bit_depth!=16||audi->sample_rate!=(id==4?48000u:16000u)||
                       audi->channel_count!=(id==4?2u:1u))return AA_CONTROL_E_ARGUMENT;
                }
                type=TYPE_AUDIO;c->channels[id].config_count=a->audio_configs_count;
            }else return AA_CONTROL_E_ARGUMENT;
        }
        c->channels[id].offered=1;c->channels[id].type=(uint8_t)type;
        c->channels[id].session=-1;
    }
    out=pb_ostream_from_buffer(c->discovery,sizeof(c->discovery));
    if(!pb_encode(&out,D(ServiceDiscoveryResponse),profile))return AA_CONTROL_E_CAPACITY;
    c->discovery_n=out.bytes_written;c->provider=provider;c->provider_arg=arg;
    c->magic=MAGIC;c->session=s;return 0;
}
static int global(struct control *c,uint16_t id,const uint8_t *p,size_t n){
    if(id==5){
        T(ServiceDiscoveryRequest) request={0};
        if(!decode(D(ServiceDiscoveryRequest),&request,p,n))return fail(c,AA_CONTROL_E_PROTOBUF);
        if(c->discovered||c->discovery_pending)return fail(c,AA_CONTROL_E_STATE);
        return discovery(c);
    }
    if(id==11||id==12){
        T(PingRequest) request={0};T(PingResponse) response={0};
        if(!decode(D(PingRequest),&request,p,n))return fail(c,AA_CONTROL_E_PROTOBUF);
        if(id==12)return 0; /* unsolicited ping-response is only parsed */
        response.timestamp=request.timestamp;
        return emit(c,0,0,12,D(PingResponse),&response,ACTION_NONE,1);
    }
    if(id==15){
        T(ShutdownRequest) request={0};T(ShutdownResponse) response={0};
        if(!decode(D(ShutdownRequest),&request,p,n))return fail(c,AA_CONTROL_E_PROTOBUF);
        int r=emit(c,0,AA_MESSAGE_ENCRYPTED,16,D(ShutdownResponse),&response,ACTION_SHUTDOWN,1);
        if(!r)c->shutdown_pending=1;
        return r;
    }
    /* Audio focus needs the real policy backend; never promise focus solely
     * because the peer requested it. Unknown focus values fail explicitly. */
    if(id==18){
        T(AudioFocusRequest) request={0};T(AudioFocusResponse) response={0};int r;
        if(!decode(D(AudioFocusRequest),&request,p,n))return fail(c,AA_CONTROL_E_PROTOBUF);
        if(request.audio_focus_type<1||request.audio_focus_type>4)return fail(c,AA_CONTROL_E_PROTOCOL);
        r=provide(c,0,AA_CONTROL_AUDIO_FOCUS_EVENT,0,(uint32_t)request.audio_focus_type,0,0,0);
        if(r==AA_CONTROL_PAUSED)return r;
        if(r)return fail(c,AA_CONTROL_E_PROVIDER);
        response.audio_focus_state=request.audio_focus_type==4?3:
            request.audio_focus_type==3?7:request.audio_focus_type==2?2:1;
        return emit(c,0,AA_MESSAGE_ENCRYPTED,19,D(AudioFocusResponse),&response,ACTION_NONE,1);
    }
    return fail(c,AA_CONTROL_E_PROTOCOL);
}
static int service(struct control *c,uint8_t id,uint16_t message,const uint8_t *p,size_t n){
    struct channel *ch=&c->channels[id];int r,success;size_t i,j;
    if(!c->discovered||!ch->offered)return fail(c,AA_CONTROL_E_STATE);
    if(message==7){
        T(ChannelOpenRequest) request={0};T(ChannelOpenResponse) response={0};
        if(ch->state!=AA_CONTROL_OFFERED)return fail(c,AA_CONTROL_E_STATE);
        if(!decode(D(ChannelOpenRequest),&request,p,n))return fail(c,AA_CONTROL_E_PROTOBUF);
        /* Proto3 absent channel_id is zero. Legacy handler ignores it; accept
         * zero or the actual outer channel, reject a conflicting nonzero ID. */
        if(request.channel_id!=0&&request.channel_id!=id)return fail(c,AA_CONTROL_E_PROTOCOL);
        r=provide(c,id,AA_CONTROL_OPEN_EVENT,-1,0,0,p,n);
        if(r==AA_CONTROL_PAUSED)return r;
        success=r==0;response.status=success?0:1;
        r=emit(c,id,AA_MESSAGE_CONTROL|AA_MESSAGE_ENCRYPTED,8,D(ChannelOpenResponse),&response,ACTION_OPEN,success);
        if(!r)ch->state=AA_CONTROL_OPEN_PENDING;
        return r;
    }
    if(ch->type==TYPE_INPUT){
        if(message==0x8002){
            T(BindingRequest) request={0};T(BindingResponse) response={0};
            if(ch->state!=AA_CONTROL_OPEN)return fail(c,AA_CONTROL_E_STATE);
            if(!decode(D(BindingRequest),&request,p,n))return fail(c,AA_CONTROL_E_PROTOBUF);
            success=1;
            for(i=0;i<request.scan_codes_count;i++){
                for(j=0;j<ch->key_count;j++)if(request.scan_codes[i]>=0&&
                    (uint32_t)request.scan_codes[i]==ch->keys[j])break;
                if(j==ch->key_count){success=0;break;}
            }
            if(success){
                r=provide(c,id,AA_CONTROL_BIND_EVENT,-1,0,0,p,n);
                if(r==AA_CONTROL_PAUSED)return r;
                success=r==0;
            }
            response.status=success?0:1;
            r=emit(c,id,AA_MESSAGE_ENCRYPTED,0x8003,D(BindingResponse),&response,ACTION_BIND,success);
            if(!r)ch->state=AA_CONTROL_BIND_PENDING;
            return r;
        }
        return fail(c,AA_CONTROL_E_PROTOCOL);
    }
    if(message==0x8000){
        T(AVChannelSetupRequest) request={0};T(AVChannelSetupResponse) response={0};
        if(ch->state!=AA_CONTROL_OPEN)return fail(c,AA_CONTROL_E_STATE);
        if(!decode(D(AVChannelSetupRequest),&request,p,n))return fail(c,AA_CONTROL_E_PROTOBUF);
        success=request.config_index<ch->config_count;
        if(success){
            r=provide(c,id,AA_CONTROL_SETUP_EVENT,-1,request.config_index,0,0,0);
            if(r==AA_CONTROL_PAUSED)return r;
            success=r==0;
        }
        response.media_status=success?2:1;response.max_unacked=1;
        if(success){response.configs_count=1;response.configs[0]=request.config_index;}
        r=emit(c,id,AA_MESSAGE_ENCRYPTED,0x8003,D(AVChannelSetupResponse),&response,ACTION_SETUP,success);
        if(!r){ch->state=AA_CONTROL_SETUP_PENDING;ch->selected=request.config_index;}
        return r;
    }
    if(message==0x8001){
        T(AVChannelStartIndication) request={0};
        if(ch->state!=AA_CONTROL_SETUP)return fail(c,AA_CONTROL_E_STATE);
        if(!decode(D(AVChannelStartIndication),&request,p,n))return fail(c,AA_CONTROL_E_PROTOBUF);
        if(request.config!=ch->selected)return fail(c,AA_CONTROL_E_PROTOCOL);
        r=provide(c,id,AA_CONTROL_START_EVENT,request.session,request.config,0,0,0);
        if(r==AA_CONTROL_PAUSED)return r;
        if(r)return fail(c,AA_CONTROL_E_PROVIDER);
        ch->session=request.session;ch->state=AA_CONTROL_STREAMING;return 0;
    }
    if(message==0x8002){
        T(AVChannelStopIndication) request={0};
        if(ch->state!=AA_CONTROL_STREAMING)return fail(c,AA_CONTROL_E_STATE);
        if(ch->ack_pending)return AA_CONTROL_PAUSED;
        if(!decode(D(AVChannelStopIndication),&request,p,n))return fail(c,AA_CONTROL_E_PROTOBUF);
        r=provide(c,id,AA_CONTROL_STOP_EVENT,ch->session,ch->selected,0,0,0);
        if(r==AA_CONTROL_PAUSED)return r;
        if(r)return fail(c,AA_CONTROL_E_PROVIDER);
        ch->session=-1;ch->state=AA_CONTROL_SETUP;return 0;
    }
    if(message==0x8007&&ch->type==TYPE_VIDEO){
        T(VideoFocusRequest) request={0};T(VideoFocusIndication) response={0};
        if(ch->state!=AA_CONTROL_SETUP&&ch->state!=AA_CONTROL_STREAMING)return fail(c,AA_CONTROL_E_STATE);
        if(!decode(D(VideoFocusRequest),&request,p,n))return fail(c,AA_CONTROL_E_PROTOBUF);
        if(request.disp_index!=0||request.focus_mode<1||request.focus_mode>2)return fail(c,AA_CONTROL_E_PROTOCOL);
        r=provide(c,id,AA_CONTROL_VIDEO_FOCUS_EVENT,ch->session,(uint32_t)request.focus_mode,0,0,0);
        if(r==AA_CONTROL_PAUSED)return r;
        if(r)return fail(c,AA_CONTROL_E_PROVIDER);
        response.focus_mode=request.focus_mode;response.unrequested=false;
        r=emit(c,id,AA_MESSAGE_ENCRYPTED,0x8008,D(VideoFocusIndication),&response,ACTION_NONE,1);
        if(!r)ch->focus_pending=0; /* explicit newer request supersedes setup default */
        return r;
    }
    if(message==0||message==1){
        T(AVMediaAckIndication) ack={0};uint64_t timestamp=0;
        if(ch->state!=AA_CONTROL_STREAMING)return fail(c,AA_CONTROL_E_STATE);
        if(ch->ack_pending)return AA_CONTROL_PAUSED;
        if(message==0){
            if(n<8)return fail(c,AA_CONTROL_E_PROTOCOL);
            for(i=0;i<8;i++)timestamp=(timestamp<<8)|p[i];
            p+=8;n-=8;
        }
        if(!n)return fail(c,AA_CONTROL_E_PROTOCOL);
        r=provide(c,id,AA_CONTROL_MEDIA_EVENT,ch->session,ch->selected,timestamp,p,n);
        if(r==AA_CONTROL_PAUSED)return r;
        if(r)return fail(c,AA_CONTROL_E_PROVIDER);
        ack.session=ch->session;ack.value=1;
        r=emit(c,id,AA_MESSAGE_ENCRYPTED,0x8004,D(AVMediaAckIndication),&ack,ACTION_ACK,1);
        if(!r)ch->ack_pending=1;
        return r;
    }
    return fail(c,AA_CONTROL_E_PROTOCOL);
}
int aa_control_receive(void *v,uint32_t s,const struct aa_message_view *view){
    struct control *c=v;uint16_t id;int r=valid(c,s);
    if(r)return r;
    if(c->shutdown_pending)return AA_CONTROL_PAUSED;
    if(!view||!view->payload||view->bytes<2||view->channel>8||
       (view->flags&~(AA_MESSAGE_CONTROL|AA_MESSAGE_ENCRYPTED)))return fail(c,AA_CONTROL_E_PROTOCOL);
    id=((uint16_t)view->payload[0]<<8)|view->payload[1];
    if(!(view->flags&AA_MESSAGE_ENCRYPTED)&&!(view->channel==0&&(id==11||id==12)))
        return fail(c,AA_CONTROL_E_PROTOCOL);
    if((view->flags&AA_MESSAGE_CONTROL)!=(id==7?AA_MESSAGE_CONTROL:0))
        return fail(c,AA_CONTROL_E_PROTOCOL);
    /* Reserve reply capacity BEFORE invoking a provider with side effects. */
    if(c->count==QCOUNT)return AA_CONTROL_PAUSED;
    if(c->next_token==UINT32_MAX)return fail(c,AA_CONTROL_E_STATE);
    return view->channel?service(c,view->channel,id,view->payload+2,view->bytes-2):
                         global(c,id,view->payload+2,view->bytes-2);
}
int aa_control_message_callback(void *v,const struct aa_message_view *view){
    struct control *c=v;if(!c||c->magic!=MAGIC)return AA_CONTROL_E_ARGUMENT;
    return aa_control_receive(v,c->session,view);
}
int aa_control_step(void *v,uint32_t s){
    struct control *c=v;uint8_t id;int r=valid(c,s);
    if(r)return r;
    if(c->shutdown_pending)return AA_CONTROL_PAUSED;
    for(id=1;id<=8;id++)if(c->channels[id].focus_pending){
        T(VideoFocusIndication) response={0};
        if(c->count==QCOUNT)return AA_CONTROL_PAUSED;
        if(c->next_token==UINT32_MAX)return fail(c,AA_CONTROL_E_STATE);
        r=provide(c,id,AA_CONTROL_VIDEO_FOCUS_EVENT,c->channels[id].session,1,0,0,0);
        if(r==AA_CONTROL_PAUSED)return r;
        if(r)return fail(c,AA_CONTROL_E_PROVIDER);
        response.focus_mode=1;response.unrequested=false;
        r=emit(c,id,AA_MESSAGE_ENCRYPTED,0x8008,D(VideoFocusIndication),&response,ACTION_NONE,1);
        if(!r)c->channels[id].focus_pending=0;
        return r;
    }
    return 0;
}
int aa_control_tx_peek(void *v,uint32_t s,struct aa_message_view *view,uint32_t *token){
    struct control *c=v;struct output *q;int r=valid(c,s);
    if(!view||!token)return AA_CONTROL_E_ARGUMENT;
    memset(view,0,sizeof(*view));*token=0;if(r)return r;
    if(!c->count)return 0;
    q=&c->queue[c->head];view->channel=q->channel;view->flags=q->flags;
    view->fragments=1;view->bytes=q->bytes;view->payload=q->data;*token=q->token;return 0;
}
int aa_control_tx_commit(void *v,uint32_t s,uint32_t token,int transport_status){
    struct control *c=v;struct output *q;struct channel *ch;int r=valid(c,s);
    if(r)return r;
    if(!c->count)return AA_CONTROL_E_STATE;
    q=&c->queue[c->head];if(token!=q->token)return AA_CONTROL_E_STATE;
    if(transport_status)return fail(c,AA_CONTROL_E_TRANSPORT);
    ch=&c->channels[q->channel];
    switch(q->action){
    case ACTION_DISCOVERY:c->discovered=1;c->discovery_pending=0;break;
    case ACTION_OPEN:ch->state=q->success?AA_CONTROL_OPEN:AA_CONTROL_OFFERED;break;
    case ACTION_SETUP:
        ch->state=q->success?AA_CONTROL_SETUP:AA_CONTROL_OPEN;
        if(q->success&&ch->type==TYPE_VIDEO)ch->focus_pending=1;
        break;
    case ACTION_BIND:ch->state=q->success?AA_CONTROL_BOUND:AA_CONTROL_OPEN;break;
    case ACTION_ACK:ch->ack_pending=0;break;
    case ACTION_SHUTDOWN:c->closed=1;break;
    default:break;
    }
    zero(q,sizeof(*q));c->head=(c->head+1)%QCOUNT;c->count--;return 0;
}
int aa_control_channel_status(void *v,uint32_t s,uint8_t id){
    struct control *c=v;int r=valid(c,s);if(r)return r;
    if(id>8||!c->channels[id].offered)return AA_CONTROL_E_ARGUMENT;
    return c->channels[id].state;
}
int aa_control_pending(void *v,uint32_t s){struct control *c=v;int r=valid(c,s);return r?r:(int)c->count;}
int aa_control_status(void *v,uint32_t s){return valid(v,s);}
int aa_control_stop(void *v,uint32_t s){
    struct control *c=v;
    if(!c||c->magic!=MAGIC)return AA_CONTROL_E_ARGUMENT;
    if(c->session!=s)return AA_CONTROL_E_SESSION;
    if(c->busy)return AA_CONTROL_E_REENTRANT;
    zero(c->queue,sizeof(c->queue));zero(c->discovery,sizeof(c->discovery));
    zero(c->channels,sizeof(c->channels));c->count=c->discovery_n=0;c->closed=1;c->error=0;return 0;
}
