/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Own Linux C tests with an explicitly synthetic control-completion gate.
 * Payloads are copied before commit and independently decoded by Python. */
#include "input.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { SESSION=0x41672u, SLOT_BYTES=256, QUEUE_SLOTS=8 };
enum category { GATE, TOUCH, CAPTURE, KEYS, CLOCK, QUEUE, TRANSPORT, REENTRY, STOP, INIT, CATEGORIES };
static const char *names[CATEGORIES]={"synthetic_bound_completion_gate","viewport_touch_sequences",
 "letterbox_capture_loss_release","bound_key_subset_longpress_signed_wheel","timestamp_extremes_regression",
 "eight_slot_capacity_pause_retry_stability","token_and_transport_failure","control_dependency_reentry",
 "stale_owner_shutdown","initialization_geometry_profile_guards"};
static unsigned checks,counts[CATEGORIES],category,records;
#define CHECK(x) do{++checks;++counts[category];if(!(x)){fprintf(stderr,"category=%s %s:%d %s\n",names[category],__FILE__,__LINE__,#x);exit(1);}}while(0)
struct gate {void *input;uint32_t session;int state,reenter;unsigned calls;};
struct fixture {uint8_t *allocation;void *input;size_t bytes;struct gate control;};
int aa_control_channel_status(void *v,uint32_t session,uint8_t channel){
 struct gate *g=v;uint8_t dummy=0;struct aa_message_view view;uint32_t token=0;
 ++g->calls;CHECK(channel==1);CHECK(session==g->session);
 if(g->reenter){g->reenter=0;
  CHECK(aa_input_status(g->input,session)==AA_INPUT_E_REENTRANT);
  CHECK(aa_input_pending(g->input,session)==AA_INPUT_E_REENTRANT);
  CHECK(aa_input_touch(g->input,session,9,AA_INPUT_PRESS,0,0)==AA_INPUT_E_REENTRANT);
  CHECK(aa_input_release_touch(g->input,session,9)==AA_INPUT_E_REENTRANT);
  CHECK(aa_input_button(g->input,session,9,4,1,0)==AA_INPUT_E_REENTRANT);
  CHECK(aa_input_scroll(g->input,session,9,-1)==AA_INPUT_E_REENTRANT);
  CHECK(aa_input_control_provider(g->input,1,AA_CONTROL_BIND_EVENT,0,0,0,&dummy,1)==AA_INPUT_E_REENTRANT);
  CHECK(aa_input_tx_peek(g->input,session,&view,&token)==AA_INPUT_E_REENTRANT);
  CHECK(view.payload==NULL&&view.bytes==0&&token==0);
  CHECK(aa_input_tx_commit(g->input,session,1,0)==AA_INPUT_E_REENTRANT);
  CHECK(aa_input_stop(g->input,session)==AA_INPUT_E_REENTRANT);
 }
 return g->state;
}
static f1x_aasdk_proto_messages_ServiceDiscoveryResponse profile(void){
 f1x_aasdk_proto_messages_ServiceDiscoveryResponse p={0};
 p.channels_count=1;p.channels[0].channel_id=1;p.channels[0].has_input_channel=true;
 p.channels[0].input_channel.supported_keycodes_count=4;
 p.channels[0].input_channel.supported_keycodes[0]=4;
 p.channels[0].input_channel.supported_keycodes[1]=23;
 p.channels[0].input_channel.supported_keycodes[2]=85;
 p.channels[0].input_channel.supported_keycodes[3]=65536;
 p.channels[0].input_channel.has_touch_screen_config=true;
 p.channels[0].input_channel.touch_screen_config.width=800;
 p.channels[0].input_channel.touch_screen_config.height=480;return p;
}
static void init(struct fixture *f,struct aa_input_viewport viewport){
 f1x_aasdk_proto_messages_ServiceDiscoveryResponse p=profile();
 memset(f,0,sizeof(*f));f->bytes=aa_input_context_bytes();f->allocation=malloc(f->bytes+16);
 CHECK(f->allocation!=NULL);memset(f->allocation,0xb3,f->bytes+16);f->input=f->allocation+8;
 f->control.input=f->input;f->control.session=SESSION;f->control.state=AA_CONTROL_OPEN;
 CHECK(aa_input_init(f->input,SESSION,&f->control,&p,&viewport)==0);
 memset(&p,0xee,sizeof(p)); /* Retaining the profile pointer would be wrong. */
}
static int bind(struct fixture *f){
 /* proto3 packed int32 scan_codes: BACK4, ENTER23, SCROLL65536. */
 uint8_t data[]={0x0a,5,4,23,0x80,0x80,4};
 int r=aa_input_control_provider(f->input,1,AA_CONTROL_BIND_EVENT,0,0,0,data,sizeof(data));
 memset(data,0x99,sizeof(data));return r;
}
static void open_bound(struct fixture *f){
 CHECK(aa_input_control_provider(f->input,1,AA_CONTROL_OPEN_EVENT,0,0,0,NULL,0)==0);
 CHECK(bind(f)==0);f->control.state=AA_CONTROL_BOUND;
}
static void finish(struct fixture *f){
 if(aa_input_status(f->input,SESSION)!=AA_INPUT_E_STATE)CHECK(aa_input_stop(f->input,SESSION)==0);
 for(size_t i=0;i<8;++i){CHECK(f->allocation[i]==0xb3);CHECK(f->allocation[f->bytes+8+i]==0xb3);}free(f->allocation);
}
static void take(struct fixture *f,const char *label){
 struct aa_message_view v;uint32_t token;uint8_t owned[SLOT_BYTES];size_t n;
 CHECK(aa_input_tx_peek(f->input,SESSION,&v,&token)==0);CHECK(token!=0);
 CHECK(v.channel==1&&v.flags==AA_MESSAGE_ENCRYPTED&&v.fragments==1);
 CHECK(v.bytes>=2&&v.bytes<=SLOT_BYTES);n=v.bytes;memcpy(owned,v.payload,n);
 CHECK(owned[0]==0x80&&owned[1]==1);
 /* No access to v.payload after this successful commit. */
 CHECK(aa_input_tx_commit(f->input,SESSION,token,0)==0);
 printf("{\"event\":\"%s\",\"channel\":1,\"flags\":8,\"token\":%u,\"hex\":\"",label,token);
 for(size_t i=0;i<n;++i)printf("%02x",owned[i]);
 printf("\"}\n");++records;
}
static void completion_gate(void){
 struct fixture f;struct aa_input_viewport v={480,272,0,0,480,272};
 category=GATE;init(&f,v);CHECK(bind(&f)==AA_INPUT_E_STATE);
 CHECK(aa_input_control_provider(f.input,1,AA_CONTROL_OPEN_EVENT,0,0,0,NULL,0)==0);
 CHECK(aa_input_touch(f.input,SESSION,0,AA_INPUT_PRESS,0,0)==AA_INPUT_E_STATE);
 CHECK(bind(&f)==0);f.control.state=AA_CONTROL_BIND_PENDING;
 CHECK(aa_input_touch(f.input,SESSION,0,AA_INPUT_PRESS,0,0)==AA_INPUT_E_STATE);
 CHECK(aa_input_button(f.input,SESSION,0,4,1,0)==AA_INPUT_E_STATE);
 CHECK(aa_input_pending(f.input,SESSION)==0);f.control.state=AA_CONTROL_BOUND;
 CHECK(aa_input_touch(f.input,SESSION,0,AA_INPUT_PRESS,0,0)==0);take(&f,"origin_press_zero");
 CHECK(aa_input_release_touch(f.input,SESSION,1)==0);take(&f,"origin_release");finish(&f);
}
static void touches(void){
 struct fixture f;category=TOUCH;init(&f,(struct aa_input_viewport){480,272,0,0,480,272});open_bound(&f);
 CHECK(aa_input_touch(f.input,SESSION,0,AA_INPUT_DRAG,0,0)==AA_INPUT_E_STATE);
 CHECK(aa_input_touch(f.input,SESSION,0,AA_INPUT_RELEASE,0,0)==AA_INPUT_E_STATE);
 CHECK(aa_input_touch(f.input,SESSION,0,AA_INPUT_PRESS,-1,0)==AA_INPUT_E_ARGUMENT);
 CHECK(aa_input_touch(f.input,SESSION,0,AA_INPUT_PRESS,480,272)==AA_INPUT_E_ARGUMENT);
 CHECK(aa_input_touch(f.input,SESSION,0,3,0,0)==AA_INPUT_E_ARGUMENT);
 CHECK(aa_input_pending(f.input,SESSION)==0);
 CHECK(aa_input_touch(f.input,SESSION,0,AA_INPUT_PRESS,240,136)==0);take(&f,"center_press");
 CHECK(aa_input_touch(f.input,SESSION,1,AA_INPUT_PRESS,2,2)==AA_INPUT_E_STATE);
 CHECK(aa_input_touch(f.input,SESSION,2,AA_INPUT_DRAG,479,271)==0);take(&f,"edge_drag");
 CHECK(aa_input_release_touch(f.input,SESSION,3)==0);take(&f,"edge_capture_release");
 CHECK(aa_input_release_touch(f.input,SESSION,4)==AA_INPUT_E_STATE);finish(&f);
 category=CAPTURE;init(&f,(struct aa_input_viewport){480,272,0,16,480,240});open_bound(&f);
 CHECK(aa_input_touch(f.input,SESSION,0,AA_INPUT_PRESS,0,15)==AA_INPUT_E_ARGUMENT);
 CHECK(aa_input_touch(f.input,SESSION,0,AA_INPUT_PRESS,0,256)==AA_INPUT_E_ARGUMENT);
 CHECK(aa_input_touch(f.input,SESSION,10,AA_INPUT_PRESS,240,136)==0);take(&f,"letterbox_center");
 CHECK(aa_input_touch(f.input,SESSION,11,AA_INPUT_DRAG,INT32_MIN,INT32_MAX)==0);take(&f,"clamp_bottom_left");
 CHECK(aa_input_touch(f.input,SESSION,12,AA_INPUT_DRAG,INT32_MAX,INT32_MIN)==0);take(&f,"clamp_top_right");
 CHECK(aa_input_release_touch(f.input,SESSION,13)==0);take(&f,"capture_loss_release");finish(&f);
}
static void keys(void){
 struct fixture f;category=KEYS;init(&f,(struct aa_input_viewport){480,272,0,0,480,272});open_bound(&f);
 CHECK(aa_input_button(f.input,SESSION,0,85,1,0)==AA_INPUT_E_PROTOCOL);
 CHECK(aa_input_button(f.input,SESSION,0,99,1,0)==AA_INPUT_E_PROTOCOL);
 CHECK(aa_input_button(f.input,SESSION,0,65536,1,0)==AA_INPUT_E_ARGUMENT);
 CHECK(aa_input_button(f.input,SESSION,0,4,0,0)==AA_INPUT_E_STATE);
 CHECK(aa_input_button(f.input,SESSION,0,4,1,1)==AA_INPUT_E_STATE);
 CHECK(aa_input_button(f.input,SESSION,0,4,2,0)==AA_INPUT_E_ARGUMENT);
 CHECK(aa_input_scroll(f.input,SESSION,0,0)==AA_INPUT_E_ARGUMENT);
 CHECK(aa_input_button(f.input,SESSION,0,4,1,0)==0);take(&f,"back_press");
 CHECK(aa_input_button(f.input,SESSION,1,4,1,0)==AA_INPUT_E_STATE);
 CHECK(aa_input_button(f.input,SESSION,1,4,0,1)==AA_INPUT_E_STATE);
 CHECK(aa_input_button(f.input,SESSION,2,4,1,1)==0);take(&f,"back_longpress");
 CHECK(aa_input_button(f.input,SESSION,3,4,0,0)==0);take(&f,"back_release");
 CHECK(aa_input_scroll(f.input,SESSION,4,-1)==0);take(&f,"wheel_minus_one");
 CHECK(aa_input_scroll(f.input,SESSION,5,INT32_MIN)==0);take(&f,"wheel_int32_min");
 CHECK(aa_input_scroll(f.input,SESSION,6,INT32_MAX)==0);take(&f,"wheel_int32_max");finish(&f);
}
static void clock_values(void){
 struct fixture f;category=CLOCK;init(&f,(struct aa_input_viewport){480,272,0,0,480,272});open_bound(&f);
 CHECK(aa_input_touch(f.input,SESSION,0,AA_INPUT_PRESS,1,1)==0);take(&f,"clock_zero");
 CHECK(aa_input_release_touch(f.input,SESSION,UINT64_MAX)==0);take(&f,"clock_max");
 CHECK(aa_input_button(f.input,SESSION,UINT64_MAX-1,4,1,0)==AA_INPUT_E_ARGUMENT);
 CHECK(aa_input_pending(f.input,SESSION)==0);
 CHECK(aa_input_button(f.input,SESSION,UINT64_MAX,4,1,0)==0);take(&f,"clock_max_key_press");
 CHECK(aa_input_button(f.input,SESSION,UINT64_MAX,4,0,0)==0);take(&f,"clock_max_key_release");finish(&f);
}
static void queue(void){
 struct fixture f;struct aa_message_view a,b;uint32_t at,bt;uint8_t saved[SLOT_BYTES];size_t n;
 category=QUEUE;init(&f,(struct aa_input_viewport){480,272,0,0,480,272});open_bound(&f);
 CHECK(aa_input_touch(f.input,SESSION,0,AA_INPUT_PRESS,0,0)==0);
 for(uint64_t i=1;i<QUEUE_SLOTS;++i)CHECK(aa_input_touch(f.input,SESSION,i,AA_INPUT_DRAG,(int32_t)i,0)==0);
 CHECK(aa_input_pending(f.input,SESSION)==8);CHECK(aa_input_tx_peek(f.input,SESSION,&a,&at)==0);
 n=a.bytes;memcpy(saved,a.payload,n);
 CHECK(aa_input_release_touch(f.input,SESSION,1000)==AA_INPUT_PAUSED);
 CHECK(aa_input_scroll(f.input,SESSION,1000,-1)==AA_INPUT_PAUSED);
 CHECK(aa_input_button(f.input,SESSION,1000,4,1,0)==AA_INPUT_PAUSED);
 CHECK(aa_input_pending(f.input,SESSION)==8);CHECK(aa_input_tx_peek(f.input,SESSION,&b,&bt)==0);
 CHECK(at==bt&&a.payload==b.payload&&n==b.bytes&&!memcmp(saved,b.payload,n));
 CHECK(aa_input_tx_commit(f.input,SESSION,at+1,0)==AA_INPUT_E_STATE);
 CHECK(aa_input_tx_commit(f.input,SESSION,0,0)==AA_INPUT_E_STATE);
 CHECK(aa_input_tx_peek(f.input,SESSION,&b,&bt)==0);CHECK(at==bt&&!memcmp(saved,b.payload,n));
 /* take() owns a copy before commit; borrowed a/b payloads are never used again. */
 take(&f,"full_queue_origin");
 CHECK(aa_input_release_touch(f.input,SESSION,100)==0); /* failed1000 must not advance timestamp/state */
 for(unsigned i=1;i<8;++i){char label[40];snprintf(label,sizeof(label),"queued_drag_%u",i);take(&f,label);}
 take(&f,"full_queue_release_retry");CHECK(aa_input_pending(f.input,SESSION)==0);
 CHECK(aa_input_release_touch(f.input,SESSION,101)==AA_INPUT_E_STATE);
 CHECK(aa_input_button(f.input,SESSION,101,4,1,0)==0);take(&f,"full_queue_key_retry");
 CHECK(aa_input_button(f.input,SESSION,102,4,0,0)==0);take(&f,"full_queue_key_release");finish(&f);
}
static void transport(void){
 struct fixture f;struct aa_message_view view;uint32_t token;
 category=TRANSPORT;init(&f,(struct aa_input_viewport){480,272,0,0,480,272});open_bound(&f);
 CHECK(aa_input_scroll(f.input,SESSION,1,-1)==0);CHECK(aa_input_scroll(f.input,SESSION,2,1)==0);
 CHECK(aa_input_tx_peek(f.input,SESSION,&view,&token)==0);CHECK(token!=0);
 CHECK(aa_input_tx_commit(f.input,SESSION,token,-99)==AA_INPUT_E_TRANSPORT);
 /* view.payload now invalid: do not inspect it. */
 CHECK(aa_input_status(f.input,SESSION)==AA_INPUT_E_TRANSPORT);
 CHECK(aa_input_pending(f.input,SESSION)==AA_INPUT_E_TRANSPORT);
 CHECK(aa_input_tx_peek(f.input,SESSION,&view,&token)==AA_INPUT_E_TRANSPORT);
 CHECK(view.payload==NULL&&view.bytes==0&&token==0);
 CHECK(aa_input_touch(f.input,SESSION,3,AA_INPUT_PRESS,0,0)==AA_INPUT_E_TRANSPORT);finish(&f);
}
static void reentrancy_shutdown(void){
 struct fixture f;struct aa_message_view view;uint32_t token;unsigned calls;
 category=REENTRY;init(&f,(struct aa_input_viewport){480,272,0,0,480,272});open_bound(&f);
 f.control.reenter=1;CHECK(aa_input_touch(f.input,SESSION,0,AA_INPUT_PRESS,0,0)==0);take(&f,"reentry_guard_press");
 CHECK(aa_input_release_touch(f.input,SESSION,1)==0);take(&f,"reentry_guard_release");
 category=STOP;calls=f.control.calls;
 CHECK(aa_input_touch(f.input,SESSION+1,2,AA_INPUT_PRESS,0,0)==AA_INPUT_E_SESSION);
 CHECK(aa_input_pending(f.input,SESSION+1)==AA_INPUT_E_SESSION);
 CHECK(aa_input_stop(f.input,SESSION+1)==AA_INPUT_E_SESSION);CHECK(f.control.calls==calls);
 CHECK(aa_input_touch(f.input,SESSION,2,AA_INPUT_PRESS,0,0)==0);
 CHECK(aa_input_button(f.input,SESSION,3,4,1,0)==0);CHECK(aa_input_pending(f.input,SESSION)==2);
 CHECK(aa_input_stop(f.input,SESSION)==0);
 CHECK(aa_input_pending(f.input,SESSION)==AA_INPUT_E_STATE);
 CHECK(aa_input_tx_peek(f.input,SESSION,&view,&token)==AA_INPUT_E_STATE);
 CHECK(view.payload==NULL&&view.bytes==0&&token==0);
 CHECK(aa_input_release_touch(f.input,SESSION,4)==AA_INPUT_E_STATE);finish(&f);
}
static void initialization(void){
 struct fixture f;f1x_aasdk_proto_messages_ServiceDiscoveryResponse p;struct aa_input_viewport v={480,272,0,0,480,272};
 uint8_t bad[]={0x0a,1,99};category=INIT;init(&f,v);p=profile();
 CHECK(aa_input_init(f.input,0,&f.control,&p,&v)==AA_INPUT_E_ARGUMENT);
 v.width=481;CHECK(aa_input_init(f.input,SESSION,&f.control,&p,&v)==AA_INPUT_E_ARGUMENT);v.width=480;
 v.surface_width=4097;CHECK(aa_input_init(f.input,SESSION,&f.control,&p,&v)==AA_INPUT_E_ARGUMENT);v.surface_width=480;
 p.channels[0].input_channel.supported_keycodes[1]=4;
 CHECK(aa_input_init(f.input,SESSION,&f.control,&p,&v)==AA_INPUT_E_ARGUMENT);p=profile();
 p.channels[0].input_channel.has_touch_pad_config=true;
 CHECK(aa_input_init(f.input,SESSION,&f.control,&p,&v)==AA_INPUT_E_ARGUMENT);p=profile();
 p.channels[0].input_channel.touch_screen_config.width=4097;
 CHECK(aa_input_init(f.input,SESSION,&f.control,&p,&v)==AA_INPUT_E_ARGUMENT);p=profile();
 p.channels_count=2;p.channels[1]=p.channels[0];
 CHECK(aa_input_init(f.input,SESSION,&f.control,&p,&v)==AA_INPUT_E_ARGUMENT);
 CHECK(aa_input_control_provider(f.input,1,AA_CONTROL_OPEN_EVENT,0,0,0,NULL,0)==0);
 CHECK(aa_input_control_provider(f.input,1,AA_CONTROL_BIND_EVENT,0,0,0,bad,sizeof(bad))==AA_INPUT_E_PROTOCOL);
 CHECK(aa_input_control_provider(f.input,3,AA_CONTROL_BIND_EVENT,0,0,0,NULL,0)==AA_INPUT_E_PROTOCOL);
 CHECK(aa_input_control_provider(f.input,1,AA_CONTROL_BIND_EVENT,0,1,0,NULL,0)==AA_INPUT_E_PROTOCOL);
 CHECK(bind(&f)==0);f.control.state=AA_CONTROL_BOUND;
 CHECK(aa_input_scroll(f.input,SESSION,0,-1)==0);take(&f,"binding_error_did_not_poison");finish(&f);
}
int main(void){
 completion_gate();touches();keys();clock_values();queue();transport();reentrancy_shutdown();initialization();
 printf("{\"summary\":true,\"pass\":true,\"assertions\":%u,\"events\":%u,\"categories\":[",checks,records);
 for(unsigned i=0;i<CATEGORIES;++i)printf("%s{\"name\":\"%s\",\"assertions\":%u}",i?",":"",names[i],counts[i]);
 printf("],\"control_gate\":\"synthetic_C_stub\"}\n");return 0;
}
