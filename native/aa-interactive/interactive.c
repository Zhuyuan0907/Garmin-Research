/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "interactive.h"
#include "control.h"
#include "input.h"
#include "video.h"
#include "audio.h"
#include "sender.h"
#include <string.h>
#define MAGIC 0x41495831u
struct bridge {
 uint32_t magic,session,owner,token,last_owner;
 void *control,*input,*video,*audio,*sender;
 int busy,provider_busy,error,detail,closed,shutdown_reply;
};
static int valid(struct bridge *b,uint32_t s){
 if(!b||b->magic!=MAGIC)return AA_INTERACTIVE_E_ARGUMENT;
 if(b->session!=s)return AA_INTERACTIVE_E_SESSION;
 if(b->busy||b->provider_busy)return AA_INTERACTIVE_E_REENTRANT;
 if(b->error)return b->error;
 return b->closed?AA_INTERACTIVE_E_STATE:0;
}
static int fail(struct bridge *b,int detail){b->detail=detail;b->error=AA_INTERACTIVE_E_DEPENDENCY;return b->error;}
uint32_t aa_interactive_context_bytes(void){return sizeof(struct bridge);}
int aa_interactive_init(void *v,uint32_t s,void *tls,void *control,void *input,
 void *video,void *audio,void *sender,size_t sender_bytes){
 struct bridge *b=v;int r;
 if(!b||!s||!tls||!control||!input||!video||!audio||!sender||
    ((uintptr_t)b&7)||((uintptr_t)sender&7)||sender_bytes<aa_sender_context_bytes())return AA_INTERACTIVE_E_ARGUMENT;
 memset(b,0,sizeof(*b));b->magic=MAGIC;b->session=s;b->control=control;b->input=input;
 b->video=video;b->audio=audio;b->sender=sender;b->last_owner=AA_INTERACTIVE_INPUT_OWNER;
 b->busy=1;r=aa_sender_init(sender,tls,s);b->busy=0;
 return r?fail(b,r):0;
}
int aa_interactive_control_provider(void *v,uint8_t ch,uint32_t event,int32_t media_session,
 uint32_t config,uint64_t timestamp,const uint8_t *data,size_t n){
 struct bridge *b=v;int r=valid(b,b?b->session:0);if(r)return r;
 b->provider_busy=1;
 if(ch==1)r=aa_input_control_provider(b->input,ch,event,media_session,config,timestamp,data,n);
 else if(ch==3)r=aa_video_control_provider(b->video,ch,event,media_session,config,timestamp,data,n);
 else if(ch==0||(ch>=4&&ch<=6))r=aa_audio_control_provider(b->audio,ch,event,media_session,config,timestamp,data,n);
 else r=AA_INTERACTIVE_E_ARGUMENT;
 b->provider_busy=0;return r;
}
static int finish_source(struct bridge *b){
 uint32_t token=0;int r=aa_sender_token(b->sender,b->session,&token);
 if(r||token!=b->token)return fail(b,r?r:AA_INTERACTIVE_E_STATE);
 r=b->owner==AA_INTERACTIVE_CONTROL_OWNER?
  aa_control_tx_commit(b->control,b->session,b->token,0):aa_input_tx_commit(b->input,b->session,b->token,0);
 if(r)return fail(b,r);
 r=aa_sender_release(b->sender,b->session,b->token);if(r)return fail(b,r);
 b->last_owner=b->owner;b->owner=b->token=0;
 if(b->shutdown_reply){b->closed=1;return AA_INTERACTIVE_CLOSED;}
 return AA_INTERACTIVE_COMPLETED;
}
int aa_interactive_step(void *v,uint32_t s){
 struct bridge *b=v;struct aa_message_view view;uint32_t token;int r,control,input;
 r=valid(b,s);if(r)return r;b->busy=1;
 if(b->owner){
  r=aa_sender_step(b->sender,s);
  if(r==AA_SENDER_DONE)r=finish_source(b);
  else if(r<0)r=fail(b,r);
  else r=r==AA_SENDER_PAUSED?AA_INTERACTIVE_PAUSED:AA_INTERACTIVE_PROGRESS;
  b->busy=0;return r;
 }
 control=aa_control_pending(b->control,s);input=aa_input_pending(b->input,s);
 if(control<0||input<0){b->busy=0;return fail(b,control<0?control:input);}
 if(!control&&!input){b->busy=0;return AA_INTERACTIVE_OK;}
 b->owner=control&&input?(b->last_owner==AA_INTERACTIVE_CONTROL_OWNER?
  AA_INTERACTIVE_INPUT_OWNER:AA_INTERACTIVE_CONTROL_OWNER):control?AA_INTERACTIVE_CONTROL_OWNER:AA_INTERACTIVE_INPUT_OWNER;
 r=b->owner==AA_INTERACTIVE_CONTROL_OWNER?aa_control_tx_peek(b->control,s,&view,&token):aa_input_tx_peek(b->input,s,&view,&token);
 if(r||!token||!view.payload||view.bytes<2){b->busy=0;return fail(b,r?r:AA_INTERACTIVE_E_STATE);}
 b->token=token;b->shutdown_reply=b->owner==AA_INTERACTIVE_CONTROL_OWNER&&view.channel==0&&
  view.payload[0]==0&&view.payload[1]==16;
 r=aa_sender_submit(b->sender,s,&view,token);
 if(r){b->busy=0;return fail(b,r);}
 r=aa_sender_step(b->sender,s);
 if(r==AA_SENDER_DONE)r=finish_source(b);
 else if(r<0)r=fail(b,r);
 else r=r==AA_SENDER_PAUSED?AA_INTERACTIVE_PAUSED:AA_INTERACTIVE_PROGRESS;
 b->busy=0;return r;
}
int aa_interactive_tx_peek(void *v,uint32_t s,const uint8_t **data,size_t *n){
 struct bridge *b=v;int r=valid(b,s);
 if(!data||!n)return AA_INTERACTIVE_E_ARGUMENT;
 *data=0;*n=0;if(r)return r;if(!b->owner)return 0;
 b->busy=1;r=aa_sender_tx_peek(b->sender,s,data,n);b->busy=0;
 return r<0?fail(b,r):r;
}
int aa_interactive_tx_commit(void *v,uint32_t s,size_t n,int status){
 struct bridge *b=v;int r=valid(b,s);if(r)return r;
 if(!b->owner)return AA_INTERACTIVE_E_STATE;
 b->busy=1;r=aa_sender_tx_commit(b->sender,s,n,status);b->busy=0;
 return r<0?fail(b,r):r;
}
int aa_interactive_owner(void *v,uint32_t s,uint32_t *owner,uint32_t *token){
 struct bridge *b=v;int r=valid(b,s);
 if(!owner||!token)return AA_INTERACTIVE_E_ARGUMENT;
 *owner=*token=0;if(r)return r;*owner=b->owner;*token=b->token;return 0;
}
int aa_interactive_status(void *v,uint32_t s){return valid(v,s);}
int aa_interactive_detail(void *v,uint32_t s){
 struct bridge *b=v;if(!b||b->magic!=MAGIC)return AA_INTERACTIVE_E_ARGUMENT;
 if(b->session!=s)return AA_INTERACTIVE_E_SESSION;
 return b->detail;
}
int aa_interactive_stop(void *v,uint32_t s){
 struct bridge *b=v;int r;
 if(!b||b->magic!=MAGIC)return AA_INTERACTIVE_E_ARGUMENT;
 if(b->session!=s)return AA_INTERACTIVE_E_SESSION;
 if(b->busy||b->provider_busy)return AA_INTERACTIVE_E_REENTRANT;
 b->busy=1;r=aa_sender_stop(b->sender,s);b->busy=0;
 b->owner=b->token=0;b->closed=1;return r?fail(b,r):0;
}
