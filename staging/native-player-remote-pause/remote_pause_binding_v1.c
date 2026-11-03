/* HWID1352/SW8.00 ONLY. Resident, one stream per boot, VM-only prototype.
 * Native command gates hold the AVDTP mutex. Native callbacks do not. Scope
 * IDs are nested command IDs; accepted configuration epochs are separate.
 * Suspend closes incoming admission and requests Source pause (silent retained
 * PCM). Full accepted Start and first valid F1 request Source resume. Disconnect
 * retires this instance. Reconnect/STOP_DONE/unload/warm ownership are absent.
 */
#include "remote_binding_v1.h"
#include "source_imports_v1.h"
#include "../../native/avdtp-policy/policy.h"
typedef int32_t (*mutex_fn)(uint32_t);
typedef int32_t (*ingress_fn)(uint32_t,uint32_t,const void *,const uint8_t *,uint32_t);
typedef int32_t (*command_fn)(uint32_t);
struct remote_binding {
 uint32_t epoch,accepted,admitting,retired,context,channel,lcid,local_mtu;
 uint32_t callback,configuration_command,start_command,config_witness,start_witness;
 uint32_t inflight,callbacks,media,accepted_media,rejected_media,retirements;
 uint32_t start_notifications,early_start_admissions,stop_requests;
 int32_t last_ingress,last_stop;
 uint8_t peer[6];uint8_t reserved[2];
 struct music_config config;
 struct music_guard policy;
 uint32_t paused,pause_requests,resume_requests;int32_t last_playback;
};
volatile struct remote_binding nsg;
static struct music_config staged;
static uint32_t staged_context,staged_command,staged_valid;
static volatile uint8_t *sep(uint32_t i){return (volatile uint8_t *)(0x03a88ef0u+32u*i);}
static volatile uint8_t *channel(uint32_t i){return (volatile uint8_t *)(0x03a88f50u+8u*i);}
static volatile uint8_t *context(uint32_t i){return (volatile uint8_t *)(0x03a88eb8u+28u*i);}
static int acquire(void){return ((mutex_fn)0x5523dfu)(0xf50098u);}
static void release(void){(void)((mutex_fn)0x5523fdu)(0xf50098u);}
static int identity(void)
{
 if(!nsg.accepted || nsg.context>=2u || !nsg.config.local_seid || nsg.config.local_seid>3u)return 0;
 volatile uint8_t *s=sep(nsg.config.local_seid-1u),*c=context(nsg.context);
 if(*(volatile uint32_t *)s!=nsg.callback || nsg.callback!=(uint32_t)(uintptr_t)nsg_native_callback ||
    s[0x11]!=nsg.context || s[0x10]!=nsg.config.remote_seid ||
    *(volatile uint32_t *)(s+0x14)!=nsg.config.codec_word)return 0;
 for(uint32_t i=0;i<6u;i++)if(c[0x16u+i]!=nsg.peer[i])return 0;
 return 1;
}
static int view(struct music_native_view *v)
{
 if(!identity())return -90;
 volatile uint8_t *s=sep(nsg.config.local_seid-1u);
 uint32_t i=s[0xf];if(i>=12u)return -90;
 volatile uint8_t *c=channel(i);
 v->state=s[0x12];v->pending=s[0x13];v->local_seid=nsg.config.local_seid;
 v->remote_seid=s[0x10];v->channel_index=i;v->sep_channel_index=i;
 v->lcid=*(volatile uint16_t *)c;v->type=c[4];v->owner_sep=c[6];v->flags=c[5];
 v->codec_word=*(volatile uint32_t *)(s+0x14);v->local_receive_mtu=nsg.local_mtu;
 return 0;
}
int nsg_config_begin(uint32_t ctx,uint32_t tx,const uint8_t *body,uint32_t length,uint32_t command)
{
 (void)tx;staged_valid=0;
 if(ctx>=2u || !command || nsg.accepted || nsg.retired || nsg.inflight || nsg.epoch==UINT32_MAX)return -90;
 if(music_validate_configuration(body,length,body[0]>>2,&staged))return 0;
 if(*(volatile uint32_t *)sep(staged.local_seid-1u)!=(uint32_t)(uintptr_t)nsg_native_callback)return -90;
 staged_context=ctx;staged_command=command;staged_valid=1;
 nsg.configuration_command=command;nsg.config_witness=0;return 0;
}
void nsg_reply_witness(uint32_t signal,uint32_t command)
{
 if(signal==3u && staged_valid && staged_command==command)nsg.config_witness=command;
 if(signal==7u && nsg.start_command==command)nsg.start_witness=command;
}
void nsg_config_end(int32_t result)
{
 if(staged_valid && !result && nsg.config_witness==staged_command){
  volatile uint8_t *s=sep(staged.local_seid-1u),*c=context(staged_context);
  if(s[0x12]==2u && !s[0x13] && s[0x11]==staged_context && s[0x10]==staged.remote_seid &&
     *(volatile uint32_t *)s==(uint32_t)(uintptr_t)nsg_native_callback &&
     *(volatile uint32_t *)(s+0x14)==staged.codec_word){
   nsg.epoch++;nsg.context=staged_context;nsg.local_mtu=*(volatile uint16_t *)(s+0xc);
   nsg.callback=(uint32_t)(uintptr_t)nsg_native_callback;
   nsg.config=staged;for(uint32_t i=0;i<6u;i++)nsg.peer[i]=c[0x16u+i];
   if(!music_guard_bind((struct music_guard *)&nsg.policy,nsg.epoch,(const struct music_config *)&nsg.config))nsg.accepted=1;
  }
 }
 staged_valid=0;
}
int nsg_start_begin(uint32_t ctx,uint32_t seid,uint32_t signal,uint32_t command)
{
 if(!identity() || ctx!=nsg.context || seid!=nsg.config.local_seid || nsg.retired || nsg.inflight)return -90;
 if(signal==7u){
  struct music_native_view v;
  if(view(&v) || v.state!=4u || v.pending || v.channel_index>=12u ||
     v.lcid<0x40u || v.type!=255u || v.flags!=0x10u || v.owner_sep+1u!=seid)return -90;
  nsg.channel=v.channel_index;nsg.lcid=v.lcid;nsg.start_command=command;nsg.start_witness=0;
 }
 return 0;
}
void nsg_start_end(int32_t result)
{
 struct music_native_view v;
 if(!result && !nsg.retired && nsg.start_command && nsg.start_witness==nsg.start_command &&
    !view(&v) && v.channel_index==nsg.channel && v.lcid==nsg.lcid &&
    !music_guard_packet((const struct music_guard *)&nsg.policy,nsg.epoch,&v,1u))nsg.admitting=1;
}
/* Complete RTP/SBC framing checked against accepted codec before queue copy.
 * Decoder owns CRC. Fragmentation, reorder, jitter and retransmit not added.
 */
static int framing(const uint8_t *p,uint32_t length)
{
 if(!p || length<13u || length>4096u || (uintptr_t)p>UINT32_MAX-length || p[0]>>6!=2u)return -90;
 uint32_t end=length,off=12u+4u*(p[0]&15u);
 if(p[0]&0x20u){uint32_t pad=p[length-1u];if(!pad || pad>length-12u)return -90;end-=pad;}
 if(off>=end)return -90;
 if(p[0]&0x10u){
  if(end-off<4u)return -90;
  uint32_t ext=4u+4u*((uint32_t)p[off+2u]*256u+p[off+3u]);
  if(ext>=end-off)return -90;
  off+=ext;
 }
 uint32_t header=p[off++],frames=header&15u;
 if(header&0xf0u || !frames)return -90;
 for(uint32_t i=0;i<frames;i++){
  int size=music_guard_frame((const struct music_guard *)&nsg.policy,nsg.epoch,p+off,end-off);
  if(size<=0)return -90;
  off+=(uint32_t)size;
 }
 return off==end?0:-90;
}
static void retire(void)
{
 if(acquire()<0)return;
 uint32_t request=nsg.accepted && !nsg.retired;
 nsg.admitting=0;nsg.retired=1;nsg.retirements++;
 if(nsg.policy.active)(void)music_guard_unbind((struct music_guard *)&nsg.policy,nsg.epoch);
 release();
 /* AV mutex released before Source POST and possible native preemption. */
 if(request){nsg.stop_requests++;nsg.last_stop=((command_fn)NSG_SOURCE_COMMAND)(5u);}
}
static void pause_remote(void)
{
 if(acquire()<0)return;
 uint32_t request=nsg.accepted && !nsg.retired && !nsg.inflight;
 if(request){nsg.admitting=0;nsg.paused=1;nsg.start_witness=0;}
 release();
 if(request){nsg.pause_requests++;nsg.last_playback=((command_fn)NSG_SOURCE_COMMAND)(8u);}
}
int nsg_native_callback(uint32_t event,uint32_t status,const void *handle,const uint8_t *packet,uint32_t length)
{
 nsg.callbacks++;
 if(event==17u){nsg.start_notifications++;if(nsg.admitting)nsg.early_start_admissions++;return 0;}
 if(event==19u){pause_remote();return 0;}
 if(event==0xf2u){retire();return 0;}
 if(event!=0xf1u)return 0;
 nsg.media++;
 if(acquire()<0){nsg.rejected_media++;return -90;}
 struct music_native_view v;const uint8_t *h=handle;
 int r=-90;
 if(!status && nsg.admitting && !nsg.retired && !nsg.inflight && h &&
    (uintptr_t)h<=UINT32_MAX-12u && !view(&v) && v.channel_index==nsg.channel && v.lcid==nsg.lcid &&
    h[4]==nsg.config.local_seid && h[5]==nsg.config.remote_seid &&
    !music_guard_packet((const struct music_guard *)&nsg.policy,nsg.epoch,&v,length)){
  uint32_t match=1;for(uint32_t i=0;i<6u;i++)if(h[6u+i]!=nsg.peer[i])match=0;
  if(match && !framing(packet,length)){nsg.inflight=1;r=0;}
 }
 release();
 if(!r){
  if(nsg.paused){
   nsg.resume_requests++;nsg.last_playback=((command_fn)NSG_SOURCE_COMMAND)(9u);
   r=nsg.last_playback;
   if(!r)nsg.paused=0;
  }
  if(!r)r=((ingress_fn)NSG_SOURCE_INGRESS)(event,status,handle,packet,length);
  /* Existing ingress owns a full copy and ends its typed leases before POST.
   * This resident module remains pinned until this whole callback returns. */
  if(acquire()<0)return -91;
  nsg.inflight=0;nsg.last_ingress=r;
  if(!r)nsg.accepted_media++;else nsg.rejected_media++;
  release();
 }else nsg.rejected_media++;
 return r;
}
