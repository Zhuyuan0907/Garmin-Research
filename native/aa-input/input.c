/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "input.h"
#include "InputEventIndicationMessage.pb.h"
#include <string.h>
#define MAGIC 0x41494e31u
#define SLOTS 8u
#define BYTES 256u
#define T(name) f1x_aasdk_proto_messages_##name
#define D(name) f1x_aasdk_proto_messages_##name##_fields
struct slot {uint32_t token;size_t bytes;uint8_t data[BYTES];};
struct input {
 uint32_t magic,session,head,count,next_token,key_count,keys[64],touch_width,touch_height;
 struct aa_input_viewport viewport;
 void *control;
 uint64_t bound_keys,held_keys,timestamp;
 uint32_t last_x,last_y;
 int error,closed,busy,opened,has_timestamp,touch_down;
 struct slot slots[SLOTS];
};
static void zero(void *p,size_t n){volatile uint8_t *b=p;while(n--)*b++=0;}
static int valid(struct input *p,uint32_t s){
 if(!p||p->magic!=MAGIC)return AA_INPUT_E_ARGUMENT;
 if(p->session!=s)return AA_INPUT_E_SESSION;
 if(p->busy)return AA_INPUT_E_REENTRANT;
 if(p->error)return p->error;
 return p->closed?AA_INPUT_E_STATE:0;
}
static int ready(struct input *p,uint32_t s,uint64_t timestamp){
 int r=valid(p,s);if(r)return r;
 p->busy=1;r=aa_control_channel_status(p->control,s,1);p->busy=0;
 if(r!=AA_CONTROL_BOUND)return AA_INPUT_E_STATE;
 if(p->has_timestamp&&timestamp<p->timestamp)return AA_INPUT_E_ARGUMENT;
 return 0;
}
static int key_index(struct input *p,uint32_t key){
 uint32_t i;for(i=0;i<p->key_count;i++)if(p->keys[i]==key)return (int)i;
 return -1;
}
static int emit(struct input *p,const T(InputEventIndication) *event){
 struct slot *q;pb_ostream_t out;
 if(p->count==SLOTS)return AA_INPUT_PAUSED;
 if(p->next_token==UINT32_MAX)return AA_INPUT_E_CAPACITY;
 q=&p->slots[(p->head+p->count)%SLOTS];memset(q,0,sizeof(*q));q->data[0]=0x80;q->data[1]=1;
 out=pb_ostream_from_buffer(q->data+2,BYTES-2);
 if(!pb_encode(&out,D(InputEventIndication),event)){zero(q,sizeof(*q));return AA_INPUT_E_CAPACITY;}
 q->token=++p->next_token;q->bytes=out.bytes_written+2;p->count++;
 p->timestamp=event->timestamp;p->has_timestamp=1;return 0;
}
uint32_t aa_input_context_bytes(void){return sizeof(struct input);}
int aa_input_init(void *v,uint32_t session,void *control,const T(ServiceDiscoveryResponse) *profile,
                  const struct aa_input_viewport *view){
 struct input *p=v;const f1x_aasdk_proto_data_InputChannel *c=0;uint32_t i,j;
 if(!p||!session||!control||!profile||!view||!view->surface_width||!view->surface_height||
    view->surface_width>4096||view->surface_height>4096||!view->width||!view->height||
    view->x>=view->surface_width||view->y>=view->surface_height||
    view->width>view->surface_width-view->x||view->height>view->surface_height-view->y||
    profile->channels_count>8)return AA_INPUT_E_ARGUMENT;
 for(i=0;i<profile->channels_count;i++)if(profile->channels[i].channel_id==1){
  if(c||!profile->channels[i].has_input_channel)return AA_INPUT_E_ARGUMENT;
  c=&profile->channels[i].input_channel;
 }
 if(!c||c->supported_keycodes_count>64||c->has_touch_pad_config||
    (c->has_touch_screen_config&&(!c->touch_screen_config.width||!c->touch_screen_config.height||
     c->touch_screen_config.width>4096||c->touch_screen_config.height>4096)))return AA_INPUT_E_ARGUMENT;
 for(i=0;i<c->supported_keycodes_count;i++){
  if(c->supported_keycodes[i]>INT32_MAX)return AA_INPUT_E_ARGUMENT;
  for(j=0;j<i;j++)if(c->supported_keycodes[j]==c->supported_keycodes[i])return AA_INPUT_E_ARGUMENT;
 }
 memset(p,0,sizeof(*p));p->magic=MAGIC;p->session=session;p->control=control;p->viewport=*view;
 p->key_count=c->supported_keycodes_count;
 for(i=0;i<p->key_count;i++)p->keys[i]=c->supported_keycodes[i];
 if(c->has_touch_screen_config){p->touch_width=c->touch_screen_config.width;p->touch_height=c->touch_screen_config.height;}
 return 0;
}
int aa_input_control_provider(void *v,uint8_t channel,uint32_t event,int32_t media_session,
 uint32_t config,uint64_t timestamp,const uint8_t *data,size_t n){
 struct input *p=v;T(BindingRequest) request={0};pb_istream_t in;uint64_t bound=0;int idx,r=valid(p,p?p->session:0);size_t i;
 (void)media_session;(void)timestamp;
 if(r)return r;
 if(channel!=1||config!=0)return AA_INPUT_E_PROTOCOL;
 if(event==AA_CONTROL_OPEN_EVENT){if(p->opened)return AA_INPUT_E_STATE;p->opened=1;return 0;}
 if(event!=AA_CONTROL_BIND_EVENT||!p->opened||(!data&&n)||p->count||p->held_keys||p->touch_down)return AA_INPUT_E_STATE;
 in=pb_istream_from_buffer(data,n);
 if(!pb_decode(&in,D(BindingRequest),&request)||in.bytes_left)return AA_INPUT_E_PROTOCOL;
 for(i=0;i<request.scan_codes_count;i++){
  if(request.scan_codes[i]<0)return AA_INPUT_E_PROTOCOL;
  idx=key_index(p,(uint32_t)request.scan_codes[i]);if(idx<0)return AA_INPUT_E_PROTOCOL;
  bound|=(uint64_t)1<<idx;
 }
 p->bound_keys=bound;return 0;
}
static int touch_at(struct input *p,uint64_t timestamp,uint32_t action,uint32_t x,uint32_t y){
 T(InputEventIndication) event={0};int r;
 event.timestamp=timestamp;event.has_touch_event=true;event.touch_event.touch_location_count=1;
 event.touch_event.touch_action=(f1x_aasdk_proto_enums_TouchAction_Enum)action;
 event.touch_event.touch_location[0].x=x;event.touch_event.touch_location[0].y=y;
 r=emit(p,&event);if(r)return r;
 p->touch_down=action!=AA_INPUT_RELEASE;p->last_x=x;p->last_y=y;return 0;
}
int aa_input_touch(void *v,uint32_t s,uint64_t timestamp,uint32_t action,int32_t x,int32_t y){
 struct input *p=v;int r=ready(p,s,timestamp);int64_t lx,ly;uint32_t tx,ty;
 if(r)return r;
 if(!p->touch_width||action>AA_INPUT_DRAG)return AA_INPUT_E_ARGUMENT;
 if((action==AA_INPUT_PRESS&&p->touch_down)||(action!=AA_INPUT_PRESS&&!p->touch_down))return AA_INPUT_E_STATE;
 lx=(int64_t)x-p->viewport.x;ly=(int64_t)y-p->viewport.y;
 if(action==AA_INPUT_PRESS&&(lx<0||ly<0||lx>=p->viewport.width||ly>=p->viewport.height))return AA_INPUT_E_ARGUMENT;
 if(lx<0)lx=0;
 if(ly<0)ly=0;
 if(lx>=p->viewport.width)lx=p->viewport.width-1;
 if(ly>=p->viewport.height)ly=p->viewport.height-1;
 tx=(uint32_t)((uint64_t)lx*p->touch_width/p->viewport.width);
 ty=(uint32_t)((uint64_t)ly*p->touch_height/p->viewport.height);
 return touch_at(p,timestamp,action,tx,ty);
}
int aa_input_release_touch(void *v,uint32_t s,uint64_t timestamp){
 struct input *p=v;int r=ready(p,s,timestamp);if(r)return r;
 if(!p->touch_down)return AA_INPUT_E_STATE;
 return touch_at(p,timestamp,AA_INPUT_RELEASE,p->last_x,p->last_y);
}
int aa_input_button(void *v,uint32_t s,uint64_t timestamp,uint32_t key,int pressed,int long_press){
 struct input *p=v;T(InputEventIndication) event={0};uint64_t bit;int idx,r=ready(p,s,timestamp);
 if(r)return r;
 if((pressed!=0&&pressed!=1)||(long_press!=0&&long_press!=1)||key==65536)return AA_INPUT_E_ARGUMENT;
 idx=key_index(p,key);if(idx<0)return AA_INPUT_E_PROTOCOL;bit=(uint64_t)1<<idx;
 if(!(p->bound_keys&bit))return AA_INPUT_E_PROTOCOL;
 if(long_press){if(!pressed||!(p->held_keys&bit))return AA_INPUT_E_STATE;}
 else if(!!(p->held_keys&bit)==!!pressed)return AA_INPUT_E_STATE;
 event.timestamp=timestamp;event.has_button_event=true;event.button_event.button_events_count=1;
 event.button_event.button_events[0].scan_code=key;event.button_event.button_events[0].is_pressed=!!pressed;
 event.button_event.button_events[0].long_press=!!long_press;r=emit(p,&event);if(r)return r;
 if(pressed)p->held_keys|=bit;else p->held_keys&=~bit;return 0;
}
int aa_input_scroll(void *v,uint32_t s,uint64_t timestamp,int32_t delta){
 struct input *p=v;T(InputEventIndication) event={0};int idx,r=ready(p,s,timestamp);if(r)return r;
 idx=key_index(p,65536);if(idx<0||!(p->bound_keys&((uint64_t)1<<idx)))return AA_INPUT_E_PROTOCOL;
 if(!delta)return AA_INPUT_E_ARGUMENT;
 event.timestamp=timestamp;event.has_relative_input_event=true;
 event.relative_input_event.relative_input_events_count=1;
 event.relative_input_event.relative_input_events[0].scan_code=65536;
 event.relative_input_event.relative_input_events[0].delta=delta;return emit(p,&event);
}
int aa_input_tx_peek(void *v,uint32_t s,struct aa_message_view *out,uint32_t *token){
 struct input *p=v;struct slot *q;int r=valid(p,s);
 if(!out||!token)return AA_INPUT_E_ARGUMENT;
 memset(out,0,sizeof(*out));*token=0;if(r)return r;
 if(!p->count)return 0;
 q=&p->slots[p->head];out->channel=1;out->flags=AA_MESSAGE_ENCRYPTED;
 out->fragments=1;out->bytes=q->bytes;out->payload=q->data;*token=q->token;return 0;
}
int aa_input_tx_commit(void *v,uint32_t s,uint32_t token,int status){
 struct input *p=v;struct slot *q;int r=valid(p,s);if(r)return r;
 if(!p->count||p->slots[p->head].token!=token)return AA_INPUT_E_STATE;
 if(status){zero(p->slots,sizeof(p->slots));p->count=0;p->error=AA_INPUT_E_TRANSPORT;return p->error;}
 q=&p->slots[p->head];zero(q,sizeof(*q));p->head=(p->head+1)%SLOTS;p->count--;return 0;
}
int aa_input_pending(void *v,uint32_t s){struct input *p=v;int r=valid(p,s);return r?r:(int)p->count;}
int aa_input_status(void *v,uint32_t s){return valid(v,s);}
int aa_input_stop(void *v,uint32_t s){
 struct input *p=v;int r=valid(p,s);if(r&&r!=AA_INPUT_E_TRANSPORT)return r;
 zero(p->slots,sizeof(p->slots));p->count=0;p->held_keys=p->bound_keys=0;p->touch_down=0;p->closed=1;return 0;
}
