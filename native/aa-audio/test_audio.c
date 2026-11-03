/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "audio.h"
#include "control.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { ++checks; if(!(x)){fprintf(stderr,"check %s:%d: %s\n",__FILE__,__LINE__,#x);exit(2);} }while(0)
static unsigned checks,cases;
struct sink {
    void *context;
    uint32_t token;
    uint8_t bytes[3][131072];
    size_t lengths[3],calls;
    int mode,reentry,block_media;
    size_t limit;
    const uint8_t *paused_pointer[3];
    size_t paused_bytes[3];
    uint8_t paused_copy[3][4096];
    uint64_t last_frame[3],last_ts;
    uint32_t last_focus;
    int32_t last_session;
};
/* Modes: 0 accept, 1 pause0, 2 partial OK, 3 partial PAUSED,
 * 4 unaligned, 5 oversized, 6 invalid status, 7 OK0, 8 alternating pause. */
static int backend(void *arg,const struct aa_audio_pcm_view *v,size_t *consumed){
    struct sink *s=arg;unsigned i=v->channel-4;size_t block=i?2:4,n=v->bytes;int mode=s->mode;
    CHECK(i<3 && v->bytes && v->bytes%block==0);
    CHECK(v->sample_rate==(i?16000U:48000U) && v->channels==(i?1U:2U) && v->bit_depth==16);
    CHECK(v->frames==v->bytes/block && v->frame_offset==s->last_frame[i]);
    if(s->paused_pointer[i]){
        CHECK(s->paused_pointer[i]==v->data && s->paused_bytes[i]==v->bytes);
        CHECK(!memcmp(s->paused_copy[i],v->data,v->bytes));s->paused_pointer[i]=NULL;
    }
    ++s->calls;s->last_ts=v->timestamp;s->last_focus=v->focus_type;s->last_session=v->media_session;
    if(s->reentry){
        struct aa_audio_stats stats;
        CHECK(aa_audio_step(s->context,s->token)==AA_AUDIO_E_REENTRANT);
        CHECK(aa_audio_finish(s->context,s->token,4)==AA_AUDIO_E_REENTRANT);
        CHECK(aa_audio_stop(s->context,s->token)==AA_AUDIO_E_REENTRANT);
        CHECK(aa_audio_stats_get(s->context,s->token,4,&stats)==AA_AUDIO_E_REENTRANT);
        CHECK(aa_audio_control_provider(s->context,0,AA_CONTROL_AUDIO_FOCUS_EVENT,0,1,0,NULL,0)==AA_AUDIO_E_REENTRANT);
    }
    if(s->block_media && !i)mode=1;
    if(mode==8)mode=s->calls%2?1:2;
    if(mode==1 || mode==7){
        s->paused_pointer[i]=v->data;s->paused_bytes[i]=v->bytes;memcpy(s->paused_copy[i],v->data,v->bytes);
        *consumed=0;return mode==1?AA_AUDIO_PAUSED:AA_AUDIO_OK;
    }
    if(mode==4){*consumed=1;return AA_AUDIO_OK;}
    if(mode==5){*consumed=v->bytes+block;return AA_AUDIO_OK;}
    if(mode==6){*consumed=0;return -1;}
    if((mode==2 || mode==3) && n>s->limit)n=s->limit;
    CHECK(n%block==0 && s->lengths[i]+n<=sizeof(s->bytes[i]));
    memcpy(s->bytes[i]+s->lengths[i],v->data,n);s->lengths[i]+=n;
    s->last_frame[i]+=n/block;*consumed=n;
    return mode==3?AA_AUDIO_PAUSED:AA_AUDIO_OK;
}
struct fixture {uint8_t *raw;void *context;struct sink *sink;};
static struct fixture fresh(unsigned mask,unsigned policy,unsigned packet,unsigned output){
    struct fixture f;struct aa_audio_config cfg={mask,packet,output,policy,30};size_t n=aa_audio_context_bytes();
    f.raw=calloc(1,n+16);f.sink=calloc(1,sizeof(*f.sink));CHECK(f.raw && f.sink);
    memset(f.raw,0xA5,8);memset(f.raw+8+n,0x5A,8);f.context=f.raw+8;
    f.sink->context=f.context;f.sink->token=77;f.sink->limit=4;
    CHECK(aa_audio_init(f.context,77,&cfg,backend,f.sink)==AA_AUDIO_OK);return f;
}
static void release(struct fixture *f){
    size_t i,n=aa_audio_context_bytes();for(i=0;i<8;++i)CHECK(f->raw[i]==0xA5 && f->raw[n+8+i]==0x5A);
    free(f->raw);free(f->sink);
}
static int event(struct fixture *f,unsigned ch,unsigned ev,int32_t session,const uint8_t *p,size_t n){
    return aa_audio_control_provider(f->context,(uint8_t)ch,ev,session,0,100,p,n);
}
static void start(struct fixture *f,unsigned ch){
    CHECK(event(f,ch,AA_CONTROL_OPEN_EVENT,0,NULL,0)==0);
    CHECK(event(f,ch,AA_CONTROL_SETUP_EVENT,0,NULL,0)==0);
    CHECK(event(f,ch,AA_CONTROL_START_EVENT,23,NULL,0)==0);
}
static void focus(struct fixture *f,unsigned type){
    CHECK(aa_audio_control_provider(f->context,0,AA_CONTROL_AUDIO_FOCUS_EVENT,0,type,0,NULL,0)==0);
}
static struct aa_audio_stats stats(struct fixture *f,unsigned channel){
    struct aa_audio_stats s;CHECK(aa_audio_stats_get(f->context,77,(uint8_t)channel,&s)==0);return s;
}
static void drain(struct fixture *f,unsigned ch){
    unsigned k;int rc=aa_audio_finish(f->context,77,(uint8_t)ch);
    CHECK(rc==AA_AUDIO_FINISHED || rc==AA_AUDIO_PAUSED);
    for(k=0;k<200000 && !stats(f,ch).finished;++k){
        rc=aa_audio_step(f->context,77);CHECK(rc>=0);
    }
    CHECK(k<200000 && stats(f,ch).finished);
}
static void selftest(void){
    uint8_t data[16384];unsigned i,j;struct fixture f;struct aa_audio_stats s;
    for(i=0;i<sizeof(data);++i)data[i]=(uint8_t)(i*7+3);
    ++cases;f=fresh(7,0,16384,4096);
    CHECK(aa_audio_step(f.context,78)==AA_AUDIO_E_SESSION);
    CHECK(aa_audio_step((uint8_t*)f.context+1,77)==AA_AUDIO_E_ARGUMENT);
    CHECK(aa_audio_init(f.context,78,&(struct aa_audio_config){7,16384,4096,0,30},backend,f.sink)==AA_AUDIO_E_STATE);
    CHECK(event(&f,4,AA_CONTROL_MEDIA_EVENT,23,data,4)==AA_AUDIO_E_STATE);
    CHECK(event(&f,4,AA_CONTROL_SETUP_EVENT,0,NULL,0)==AA_AUDIO_E_STATE);
    CHECK(event(&f,4,AA_CONTROL_START_EVENT,-1,NULL,0)==AA_AUDIO_E_STATE);
    CHECK(event(&f,7,AA_CONTROL_OPEN_EVENT,0,NULL,0)==AA_AUDIO_E_PROTOCOL);
    CHECK(event(&f,4,99,0,NULL,0)==AA_AUDIO_E_PROTOCOL);
    start(&f,4);CHECK(event(&f,4,AA_CONTROL_START_EVENT,23,NULL,0)==AA_AUDIO_E_STATE);
    CHECK(event(&f,4,AA_CONTROL_MEDIA_EVENT,22,data,4)==AA_AUDIO_E_SESSION);
    CHECK(event(&f,4,AA_CONTROL_MEDIA_EVENT,23,NULL,4)==AA_AUDIO_E_PROTOCOL);
    CHECK(event(&f,4,AA_CONTROL_MEDIA_EVENT,23,data,0)==AA_AUDIO_E_PROTOCOL);
    CHECK(aa_audio_control_provider(f.context,4,AA_CONTROL_MEDIA_EVENT,23,1,0,data,4)==AA_AUDIO_E_STATE);
    CHECK(aa_audio_stats_get(f.context,77,4,NULL)==AA_AUDIO_E_ARGUMENT);
    CHECK(aa_audio_finish(f.context,77,5)==AA_AUDIO_E_STATE);release(&f);
    ++cases;f=fresh(1,0,8,4);start(&f,4);
    CHECK(event(&f,5,AA_CONTROL_OPEN_EVENT,0,NULL,0)==AA_AUDIO_E_PROTOCOL);
    CHECK(event(&f,4,AA_CONTROL_MEDIA_EVENT,23,data,9)==AA_AUDIO_E_CAPACITY);
    CHECK(!stats(&f,4).accepted_packets);release(&f);
    ++cases;f=fresh(7,0,16384,4096);start(&f,4);
    CHECK(event(&f,4,AA_CONTROL_MEDIA_EVENT,23,data,8)==0);
    CHECK(event(&f,4,AA_CONTROL_MEDIA_EVENT,23,data+8,8)==0);
    s=stats(&f,4);CHECK(s.queued_packets==2 && s.queued_bytes==16 && !f.sink->calls);
    CHECK(event(&f,4,AA_CONTROL_MEDIA_EVENT,23,data+16,4)==AA_AUDIO_PAUSED);
    CHECK(stats(&f,4).accepted_bytes==16 && stats(&f,4).accepted_packets==2);
    memset(data,0xDD,16);CHECK(aa_audio_step(f.context,77)==AA_AUDIO_PROGRESS);
    for(i=0;i<16;++i)CHECK(f.sink->bytes[0][i]==(uint8_t)(i*7+3));
    CHECK(event(&f,4,AA_CONTROL_MEDIA_EVENT,23,data+16,4)==0);drain(&f,4);release(&f);
    for(i=0;i<sizeof(data);++i)data[i]=(uint8_t)(i*7+3);
    ++cases;f=fresh(7,0,16384,4096);start(&f,4);
    CHECK(event(&f,4,AA_CONTROL_MEDIA_EVENT,23,data,1)==0);CHECK(aa_audio_step(f.context,77)==0);
    CHECK(stats(&f,4).carry_bytes==1 && !f.sink->calls);
    CHECK(aa_audio_control_provider(f.context,4,AA_CONTROL_MEDIA_EVENT,23,0,200,data+1,2)==0);
    CHECK(aa_audio_step(f.context,77)==0);CHECK(stats(&f,4).carry_bytes==3);
    CHECK(aa_audio_control_provider(f.context,4,AA_CONTROL_MEDIA_EVENT,23,0,300,data+3,5)==0);
    CHECK(aa_audio_step(f.context,77)==AA_AUDIO_PROGRESS);
    CHECK(f.sink->last_ts==100 && f.sink->lengths[0]==8 && !memcmp(f.sink->bytes[0],data,8));
    CHECK(stats(&f,4).assembled_bytes==8);drain(&f,4);
    start(&f,5);CHECK(event(&f,5,AA_CONTROL_MEDIA_EVENT,23,data,2)==0);
    CHECK(aa_audio_step(f.context,77)==AA_AUDIO_PROGRESS && f.sink->lengths[1]==2);release(&f);
    for(j=1;j<=7;++j){
        if(j==4 || j==5 || j==6)continue;
        ++cases;f=fresh(1,0,16384,8);start(&f,4);f.sink->mode=(int)j;f.sink->reentry=1;
        CHECK(event(&f,4,AA_CONTROL_MEDIA_EVENT,23,data,12)==0);
        CHECK(aa_audio_step(f.context,77)==(j==2?AA_AUDIO_PROGRESS:AA_AUDIO_PAUSED));
        s=stats(&f,4);CHECK(s.pending_bytes==(j==2 || j==3?4:8));
        f.sink->mode=0;CHECK(aa_audio_retry(f.context,77)==AA_AUDIO_PROGRESS);
        drain(&f,4);CHECK(f.sink->lengths[0]==12 && !memcmp(f.sink->bytes[0],data,12));release(&f);
    }
    for(j=4;j<=6;++j){
        ++cases;f=fresh(1,0,16384,4096);start(&f,4);f.sink->mode=(int)j;
        CHECK(event(&f,4,AA_CONTROL_MEDIA_EVENT,23,data,8)==0);
        CHECK(aa_audio_step(f.context,77)==AA_AUDIO_E_BACKEND && aa_audio_status(f.context,77)==AA_AUDIO_E_BACKEND);
        CHECK(event(&f,4,AA_CONTROL_MEDIA_EVENT,23,data,4)==AA_AUDIO_E_BACKEND);
        CHECK(event(&f,4,AA_CONTROL_STOP_EVENT,23,NULL,0)==0);CHECK(!aa_audio_status(f.context,77));release(&f);
    }
    for(j=1;j<=3;++j){
        ++cases;f=fresh(1,0,16384,4096);start(&f,4);
        CHECK(event(&f,4,AA_CONTROL_MEDIA_EVENT,23,data,4+j)==0);CHECK(aa_audio_finish(f.context,77,4)==AA_AUDIO_PAUSED);
        CHECK(aa_audio_step(f.context,77)==AA_AUDIO_E_TRUNCATED);
        CHECK(stats(&f,4).backend_bytes==4 && stats(&f,4).carry_bytes==j && stats(&f,4).error==AA_AUDIO_E_TRUNCATED);
        CHECK(aa_audio_finish(f.context,77,4)==AA_AUDIO_E_TRUNCATED);release(&f);
    }
    ++cases;f=fresh(2,0,16384,4096);start(&f,5);CHECK(event(&f,5,AA_CONTROL_MEDIA_EVENT,23,data,1)==0);
    CHECK(aa_audio_finish(f.context,77,5)==AA_AUDIO_PAUSED);CHECK(aa_audio_step(f.context,77)==AA_AUDIO_E_TRUNCATED);release(&f);
    ++cases;f=fresh(7,1,16384,4096);for(i=4;i<=6;++i)start(&f,i);
    for(i=4;i<=6;++i)CHECK(event(&f,i,AA_CONTROL_MEDIA_EVENT,23,data,4)==0);
    CHECK(aa_audio_step(f.context,77)==AA_AUDIO_PAUSED && !f.sink->calls);
    focus(&f,2);CHECK(aa_audio_step(f.context,77)==AA_AUDIO_PROGRESS);
    CHECK(f.sink->lengths[0]==0 && f.sink->lengths[1]==4 && f.sink->last_focus==2);
    CHECK(aa_audio_step(f.context,77)==AA_AUDIO_PROGRESS && f.sink->lengths[2]==4);
    focus(&f,3);CHECK(aa_audio_step(f.context,77)==AA_AUDIO_PAUSED);
    focus(&f,1);CHECK(aa_audio_step(f.context,77)==AA_AUDIO_PROGRESS && f.sink->lengths[0]==4);
    focus(&f,4);CHECK(event(&f,4,AA_CONTROL_MEDIA_EVENT,23,data,4)==0);
    CHECK(aa_audio_step(f.context,77)==AA_AUDIO_PAUSED);focus(&f,1);drain(&f,4);release(&f);
    ++cases;f=fresh(1,0,16384,4096);start(&f,4);
    CHECK(aa_audio_control_provider(f.context,0,AA_CONTROL_AUDIO_FOCUS_EVENT,0,0,0,NULL,0)==AA_AUDIO_E_PROTOCOL);
    CHECK(aa_audio_control_provider(f.context,0,AA_CONTROL_AUDIO_FOCUS_EVENT,0,5,0,NULL,0)==AA_AUDIO_E_PROTOCOL);
    CHECK(event(&f,0,AA_CONTROL_MEDIA_EVENT,0,data,4)==AA_AUDIO_E_PROTOCOL);focus(&f,4);
    CHECK(event(&f,4,AA_CONTROL_MEDIA_EVENT,23,data,4)==0);drain(&f,4);
    CHECK(f.sink->last_focus==4 && f.sink->lengths[0]==4);release(&f);
    ++cases;f=fresh(7,0,16384,4096);for(i=4;i<=6;++i)start(&f,i);f.sink->block_media=1;
    for(i=4;i<=6;++i)CHECK(event(&f,i,AA_CONTROL_MEDIA_EVENT,23,data,4)==0);
    CHECK(aa_audio_step(f.context,77)==AA_AUDIO_PROGRESS);
    CHECK(aa_audio_step(f.context,77)==AA_AUDIO_PROGRESS);
    CHECK(!f.sink->lengths[0] && f.sink->lengths[1]==4 && f.sink->lengths[2]==4);
    f.sink->block_media=0;drain(&f,4);release(&f);
    ++cases;f=fresh(1,0,16384,4096);start(&f,4);f.sink->mode=1;
    CHECK(event(&f,4,AA_CONTROL_MEDIA_EVENT,23,data,11)==0);CHECK(aa_audio_step(f.context,77)==AA_AUDIO_PAUSED);
    CHECK(stats(&f,4).pending_bytes==8 && stats(&f,4).carry_bytes==3);
    CHECK(event(&f,4,AA_CONTROL_STOP_EVENT,22,NULL,0)==AA_AUDIO_E_SESSION);
    CHECK(event(&f,4,AA_CONTROL_STOP_EVENT,23,NULL,0)==0);CHECK(stats(&f,4).discarded_bytes==11);
    CHECK(event(&f,4,AA_CONTROL_MEDIA_EVENT,23,data,4)==AA_AUDIO_E_STATE);
    CHECK(event(&f,4,AA_CONTROL_START_EVENT,24,NULL,0)==0);f.sink->mode=0;memset(f.sink->paused_pointer,0,sizeof(f.sink->paused_pointer));
    CHECK(event(&f,4,AA_CONTROL_MEDIA_EVENT,23,data,4)==AA_AUDIO_E_SESSION);
    CHECK(event(&f,4,AA_CONTROL_MEDIA_EVENT,24,data+12,4)==0);drain(&f,4);
    CHECK(f.sink->lengths[0]==4 && !memcmp(f.sink->bytes[0],data+12,4));release(&f);
    ++cases;f=fresh(7,0,16384,4096);start(&f,4);CHECK(event(&f,4,AA_CONTROL_MEDIA_EVENT,23,data,16384)==0);
    CHECK(aa_audio_step(f.context,77)==AA_AUDIO_PROGRESS);s=stats(&f,4);
    CHECK(s.queued_packets==1 && s.queued_bytes==12288 && s.backend_bytes==4096);
    drain(&f,4);CHECK(f.sink->lengths[0]==16384 && !memcmp(f.sink->bytes[0],data,16384));release(&f);
    ++cases;f=fresh(1,0,16384,4096);start(&f,4);CHECK(event(&f,4,AA_CONTROL_MEDIA_EVENT,23,data,7)==0);
    CHECK(aa_audio_stop(f.context,77)==0);CHECK(aa_audio_step(f.context,77)==AA_AUDIO_E_STATE);
    CHECK(event(&f,4,AA_CONTROL_MEDIA_EVENT,23,data,4)==AA_AUDIO_E_STATE);CHECK(!f.sink->calls);
    CHECK(aa_audio_init(f.context,78,&(struct aa_audio_config){1,16384,4096,0,30},backend,f.sink)==0);
    CHECK(aa_audio_step(f.context,77)==AA_AUDIO_E_SESSION);CHECK(aa_audio_step(f.context,78)==0);release(&f);
    ++cases;f=fresh(1,0,16384,4096);CHECK(aa_audio_stop(f.context,77)==0);
    CHECK(aa_audio_init(f.context,77,&(struct aa_audio_config){1,16384,4096,0,2},backend,f.sink)==0);
    CHECK(aa_audio_control_provider(f.context,0,AA_CONTROL_AUDIO_FOCUS_EVENT,0,2,0,NULL,0)==AA_AUDIO_E_FOCUS);
    CHECK(stats(&f,4).focus_type==0);focus(&f,1);release(&f);
    ++cases;f=fresh(1,1,16384,4096);start(&f,4);focus(&f,1);f.sink->mode=1;
    CHECK(event(&f,4,AA_CONTROL_MEDIA_EVENT,23,data,8)==0);
    CHECK(aa_audio_step(f.context,77)==AA_AUDIO_PAUSED);i=(unsigned)f.sink->calls;
    focus(&f,3);CHECK(aa_audio_step(f.context,77)==AA_AUDIO_PAUSED && f.sink->calls==i);
    CHECK(stats(&f,4).pending_bytes==8);focus(&f,1);f.sink->mode=0;drain(&f,4);
    CHECK(f.sink->last_focus==1 && f.sink->lengths[0]==8 && !memcmp(f.sink->bytes[0],data,8));release(&f);
    ++cases;f=fresh(7,0,16384,4096);start(&f,4);start(&f,5);
    CHECK(aa_audio_finish(f.context,77,4)==AA_AUDIO_FINISHED);
    CHECK(aa_audio_finish(f.context,77,4)==AA_AUDIO_FINISHED);
    CHECK(event(&f,4,AA_CONTROL_MEDIA_EVENT,23,data,4)==AA_AUDIO_E_STATE);
    CHECK(event(&f,5,AA_CONTROL_MEDIA_EVENT,23,data,4)==0);
    CHECK(aa_audio_step(f.context,77)==AA_AUDIO_PROGRESS && f.sink->lengths[1]==4);release(&f);
    ++cases;{
        struct aa_audio_config invalid[]={{0,1,4,0,30},{8,1,4,0,30},{1,0,4,0,30},
          {1,16385,4,0,30},{1,1,0,0,30},{1,1,4097,0,30},{1,1,6,0,30},
          {1,1,4,2,30},{1,1,4,0,31}};
        f=fresh(1,0,16384,4096);CHECK(aa_audio_stop(f.context,77)==0);
        for(i=0;i<sizeof(invalid)/sizeof(invalid[0]);++i)
            CHECK(aa_audio_init(f.context,77,&invalid[i],backend,f.sink)==AA_AUDIO_E_ARGUMENT);
        CHECK(aa_audio_init(f.context,0,&(struct aa_audio_config){1,1,4,0,30},backend,f.sink)==AA_AUDIO_E_ARGUMENT);
        CHECK(aa_audio_init(f.context,77,&(struct aa_audio_config){1,1,4,0,30},NULL,f.sink)==AA_AUDIO_E_ARGUMENT);
        release(&f);
    }
    ++cases;{
        int32_t sessions[]={INT32_MIN,-1,0,INT32_MAX};uint8_t open[]={8,4,16,3};
        f=fresh(1,0,16384,4096);
        CHECK(event(&f,4,AA_CONTROL_OPEN_EVENT,-1,NULL,1)==AA_AUDIO_E_PROTOCOL);
        CHECK(event(&f,4,AA_CONTROL_OPEN_EVENT,-1,open,sizeof(open))==0);memset(open,0xDD,sizeof(open));
        CHECK(event(&f,4,AA_CONTROL_SETUP_EVENT,-1,NULL,0)==0);
        for(i=0;i<4;++i){
            CHECK(event(&f,4,AA_CONTROL_START_EVENT,sessions[i],NULL,0)==0);
            CHECK(stats(&f,4).streaming && stats(&f,4).media_session==sessions[i]);
            CHECK(event(&f,4,AA_CONTROL_MEDIA_EVENT,sessions[i],data,4)==0);
            CHECK(aa_audio_step(f.context,77)==AA_AUDIO_PROGRESS);
            CHECK(f.sink->last_session==sessions[i]);
            CHECK(event(&f,4,AA_CONTROL_STOP_EVENT,sessions[i],NULL,0)==0);
            f.sink->last_frame[0]=0;
        }
        CHECK(f.sink->lengths[0]==16);release(&f);
    }
    printf("{\"case_count\":%u,\"assertions\":%u}\n",cases,checks);
}
static void roundtrip(const char *input,const char *output,unsigned channel,unsigned chunk,int mode){
    struct fixture f=fresh(7,0,16384,4096);FILE *in,*out;uint8_t data[16384];size_t n;unsigned k;int rc;
    CHECK(channel>=4 && channel<=6 && chunk && chunk<=16384);start(&f,channel);f.sink->mode=mode;
    f.sink->limit=channel==4?4:2;in=fopen(input,"rb");CHECK(in!=NULL);
    while((n=fread(data,1,chunk,in))){
        for(k=0;k<200000;++k){
            rc=event(&f,channel,AA_CONTROL_MEDIA_EVENT,23,data,n);
            if(rc==AA_AUDIO_OK)break;
            CHECK(rc==AA_AUDIO_PAUSED);CHECK(aa_audio_step(f.context,77)>=0);
        }
        CHECK(k<200000);memset(data,0xEE,n);CHECK(aa_audio_step(f.context,77)>=0);
    }
    CHECK(!ferror(in));CHECK(fclose(in)==0);drain(&f,channel);
    out=fopen(output,"wb");CHECK(out!=NULL);
    CHECK(fwrite(f.sink->bytes[channel-4],1,f.sink->lengths[channel-4],out)==f.sink->lengths[channel-4]);
    CHECK(fclose(out)==0);printf("{\"bytes\":%zu,\"backend_calls\":%zu,\"assertions\":%u}\n",f.sink->lengths[channel-4],f.sink->calls,checks);release(&f);
}
int main(int argc,char **argv){
    if(argc==1){selftest();return 0;}
    if(argc!=7)return 2;
    roundtrip(argv[1],argv[2],(unsigned)strtoul(argv[3],NULL,10),(unsigned)strtoul(argv[4],NULL,10),(int)strtol(argv[5],NULL,10));
    /* Final argument is an explicit host-only fixture label. */
    return strcmp(argv[6],"host-pcm")?2:0;
}
