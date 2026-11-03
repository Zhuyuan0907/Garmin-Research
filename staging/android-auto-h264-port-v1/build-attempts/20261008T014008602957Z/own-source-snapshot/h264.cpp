/* SPDX-License-Identifier: BSD-2-Clause */
#include "h264.h"
#include "codec_api.h"
#include <cstring>
#include <new>
#include <limits>

struct sps_info { bool valid; uint32_t frame_bits,poc_type,poc_bits,width,height,mbs; bool delta_zero; };
struct pps_info { bool valid,bottom_poc; uint32_t sps; };
struct picture_key { uint32_t pps,frame_num,idr_id,poc; int32_t delta0,delta1; bool idr,reference; };
struct bits {
    const uint8_t *p; size_t size,pos; unsigned bit;
    bool good;
    bits(const uint8_t *a,size_t n):p(a),size(n),pos(0),bit(0),good(true){}
    uint32_t get(unsigned count) {
        uint32_t x=0;
        if(count>32){good=false;return 0;}
        while(count--){if(pos>=size){good=false;return 0;}x=(x<<1)|((p[pos]>>(7-bit))&1);if(++bit==8){bit=0;++pos;}}
        return x;
    }
    uint32_t ue(){unsigned z=0;while(good && !get(1)){if(++z>31){good=false;return 0;}}uint32_t low=get(z);if(!good)return 0;return ((uint32_t(1)<<z)-1)+low;}
    int32_t se(){uint32_t n=ue();if(n==UINT32_MAX){good=false;return 0;}return n&1?int32_t((n+1)/2):-int32_t(n/2);}
};
struct aa_h264 {
    aa_h264_config cfg;
    uint8_t *nal,*rbsp,*au,*pixels;
    size_t nal_n,au_n;
    unsigned zeroes;
    bool in_nal,nal_pending,au_vcl,pending,busy,eof,eos,finished;
    uint64_t nal_ts,au_ts,frame_index;
    uint32_t last_mb;
    int error;
    ISVCDecoder *codec;
    sps_info sps[32]; pps_info pps[256]; picture_key key;
    aa_h264_frame frame;
};
static bool valid_config(const aa_h264_config *c){return c && c->callback && c->max_width && c->max_height &&
    c->max_width<=800 && c->max_height<=480 && !(c->max_width&1) && !(c->max_height&1) &&
    c->max_nal_bytes>=32 && c->max_nal_bytes<=1048576 && c->max_au_bytes>=c->max_nal_bytes+4 && c->max_au_bytes<=4194304;}
extern "C" size_t aa_h264_context_size(void){return sizeof(aa_h264);}
extern "C" size_t aa_h264_context_align(void){return alignof(aa_h264);}
extern "C" size_t aa_h264_workspace_size(const aa_h264_config *c){if(!valid_config(c))return 0;
    return c->max_nal_bytes+4+c->max_nal_bytes+c->max_au_bytes+size_t(c->max_width)*c->max_height*3/2;}
static int fail(aa_h264 *d,int err){d->error=err;return err;}
static int emit(aa_h264 *d){
    if(!d->pending)return AA_H264_OK;
    int r=d->cfg.callback(d->cfg.user,&d->frame);
    if(r==AA_H264_PAUSED)return r;
    if(r!=AA_H264_OK)return fail(d,AA_H264_CALLBACK);
    d->pending=false;return AA_H264_OK;
}
static int copy_frame(aa_h264 *d,uint8_t **p,const SBufferInfo &b){
    if(!b.iBufferStatus)return AA_H264_OK;
    const SSysMEMBuffer &m=b.UsrData.sSystemBuffer;
    if(b.iBufferStatus!=1 || m.iWidth<=0 || m.iHeight<=0 || (m.iWidth&1) || (m.iHeight&1) ||
       uint32_t(m.iWidth)>d->cfg.max_width || uint32_t(m.iHeight)>d->cfg.max_height ||
       m.iFormat!=videoFormatI420 || m.iStride[0]<m.iWidth || m.iStride[1]<m.iWidth/2 || !p[0] || !p[1] || !p[2])
        return fail(d,AA_H264_CODEC);
    size_t off=0;
    for(unsigned plane=0;plane<3;++plane){size_t w=size_t(m.iWidth)>>(plane?1:0),h=size_t(m.iHeight)>>(plane?1:0);
        d->frame.planes[plane]=d->pixels+off;d->frame.strides[plane]=w;
        for(size_t row=0;row<h;++row)std::memcpy(d->pixels+off+row*w,p[plane]+row*size_t(m.iStride[plane?1:0]),w);
        off+=w*h;
    }
    d->frame.width=uint32_t(m.iWidth);d->frame.height=uint32_t(m.iHeight);
    d->frame.timestamp=b.uiOutYuvTimeStamp;d->frame.index=d->frame_index++;d->pending=true;
    return emit(d);
}
static int decode_au(aa_h264 *d){
    if(!d->au_n)return AA_H264_OK;
    if(!d->au_vcl){d->au_n=0;return AA_H264_OK;} /* parameter-only suffix never allocates a picture */
    uint8_t *p[3]={};SBufferInfo b={};b.uiInBsTimeStamp=d->au_ts;
    DECODING_STATE r=d->codec->DecodeFrameNoDelay(d->au,int(d->au_n),p,&b);
    d->au_n=0;d->au_vcl=false;
    if(r!=dsErrorFree)return fail(d,AA_H264_CODEC); /* EC disabled: never publish concealed error output */
    return copy_frame(d,p,b);
}
static int unescape(aa_h264 *d,size_t &n){
    n=0;unsigned z=0;
    for(size_t i=1;i<d->nal_n;++i){uint8_t c=d->nal[i];
        if(z==2 && c==3){if(i+1>=d->nal_n || d->nal[i+1]>3)return fail(d,AA_H264_MALFORMED);z=0;continue;}
        if(z==2 && c<3)return fail(d,AA_H264_MALFORMED);
        d->rbsp[n++]=c;z=c==0?z+1:0;if(z>2)z=2;
    }
    return AA_H264_OK;
}
static bool high_profile(uint32_t profile){return profile==100 || profile==110 || profile==122 || profile==244 ||
    profile==44 || profile==83 || profile==86 || profile==118 || profile==128 || profile==138 || profile==139 || profile==134 || profile==135;}
static int parse_sps(aa_h264 *d,size_t n){
    bits b(d->rbsp,n);uint32_t profile=b.get(8);b.get(8);b.get(8);uint32_t id=b.ue();
    if(!b.good || id>=32)return fail(d,AA_H264_MALFORMED);
    if(profile!=66 && profile!=77 && profile!=100)return fail(d,AA_H264_UNSUPPORTED);
    if(high_profile(profile)){
        uint32_t chroma=b.ue();if(chroma!=1)return fail(d,AA_H264_UNSUPPORTED);
        if(b.ue()!=0 || b.ue()!=0)return fail(d,AA_H264_UNSUPPORTED);
        b.get(1);
        if(b.get(1)){for(unsigned i=0;i<8 && b.good;++i)if(b.get(1)){
            int last=8,next=8;unsigned count=i<6?16:64;
            for(unsigned j=0;j<count && b.good;++j){if(next){int delta=b.se();if(delta < -128 || delta>127)return fail(d,AA_H264_MALFORMED);next=(last+delta+256)%256;}if(next)last=next;}
        }}
    }
    sps_info s={};uint32_t f=b.ue();if(f>12)return fail(d,AA_H264_MALFORMED);s.frame_bits=f+4;
    s.poc_type=b.ue();if(s.poc_type==0){uint32_t p=b.ue();if(p>12)return fail(d,AA_H264_MALFORMED);s.poc_bits=p+4;}
    else if(s.poc_type==1){s.delta_zero=b.get(1)!=0;b.se();b.se();uint32_t k=b.ue();if(k>255)return fail(d,AA_H264_MALFORMED);for(uint32_t i=0;i<k && b.good;++i)b.se();}
    else if(s.poc_type!=2)return fail(d,AA_H264_MALFORMED);
    uint32_t refs=b.ue();if(refs>16)return fail(d,AA_H264_CAPACITY);b.get(1);
    uint32_t wm=b.ue(),hm=b.ue();bool frame_only=b.get(1)!=0;
    if(!frame_only)return fail(d,AA_H264_UNSUPPORTED);
    b.get(1);uint32_t left=0,right=0,top=0,bottom=0;
    if(b.get(1)){left=b.ue();right=b.ue();top=b.ue();bottom=b.ue();}
    if(!b.good)return fail(d,AA_H264_MALFORMED);
    uint64_t cw=(uint64_t(wm)+1)*16,ch=(uint64_t(hm)+1)*16;
    if(cw>d->cfg.max_width || ch>d->cfg.max_height || (uint64_t(left)+right)*2>=cw || (uint64_t(top)+bottom)*2>=ch)
        return fail(d,AA_H264_CAPACITY);
    s.width=uint32_t(cw-2*(uint64_t(left)+right));s.height=uint32_t(ch-2*(uint64_t(top)+bottom));
    s.mbs=uint32_t((cw/16)*(ch/16));s.valid=true;d->sps[id]=s;return AA_H264_OK;
}
static int parse_pps(aa_h264 *d,size_t n){
    bits b(d->rbsp,n);uint32_t id=b.ue(),sid=b.ue();if(id>=256 || sid>=32 || !d->sps[sid].valid)return fail(d,AA_H264_MALFORMED);
    b.get(1);bool bottom=b.get(1)!=0;if(b.ue()!=0)return fail(d,AA_H264_UNSUPPORTED); /* FMO */
    if(b.ue()>15 || b.ue()>15)return fail(d,AA_H264_CAPACITY);
    b.get(1);b.get(2);b.se();b.se();b.se();b.get(1);b.get(1);b.get(1);
    if(!b.good)return fail(d,AA_H264_MALFORMED);
    d->pps[id]={true,bottom,sid};return AA_H264_OK;
}
static int slice_key(aa_h264 *d,size_t n,picture_key &key,uint32_t &first){
    bits b(d->rbsp,n);first=b.ue();uint32_t type=b.ue(),pid=b.ue();
    if(!b.good || type>9 || pid>=256 || !d->pps[pid].valid)return fail(d,AA_H264_MALFORMED);
    const pps_info &p=d->pps[pid];const sps_info &s=d->sps[p.sps];
    if(first>=s.mbs)return fail(d,AA_H264_MALFORMED);
    key={};key.pps=pid;key.frame_num=b.get(s.frame_bits);key.idr=(d->nal[0]&31)==5;key.reference=(d->nal[0]&0x60)!=0;
    if(key.idr){key.idr_id=b.ue();if(key.idr_id>65535)return fail(d,AA_H264_MALFORMED);}
    if(s.poc_type==0){key.poc=b.get(s.poc_bits);if(p.bottom_poc)key.delta1=b.se();}
    if(s.poc_type==1 && !s.delta_zero){key.delta0=b.se();if(p.bottom_poc)key.delta1=b.se();}
    if(!b.good)return fail(d,AA_H264_MALFORMED);
    return AA_H264_OK;
}
static bool same_picture(const picture_key &a,const picture_key &b){return a.pps==b.pps && a.frame_num==b.frame_num &&
    a.idr==b.idr && a.reference==b.reference && a.idr_id==b.idr_id && a.poc==b.poc && a.delta0==b.delta0 && a.delta1==b.delta1;}
static int process_nal(aa_h264 *d){
    if(!d->nal_n)return fail(d,AA_H264_MALFORMED);
    if(d->nal_n>d->cfg.max_nal_bytes)return fail(d,AA_H264_CAPACITY);
    if(d->nal[0]&0x80)return fail(d,AA_H264_MALFORMED);
    unsigned type=d->nal[0]&31;
    if(type!=1 && type!=5 && type!=6 && type!=7 && type!=8 && type!=9 && type!=10 && type!=11 && type!=12)
        return fail(d,AA_H264_UNSUPPORTED);
    size_t n=0;int r=unescape(d,n);if(r)return r;
    picture_key key={};uint32_t first=0;
    if(type==1 || type==5){r=slice_key(d,n,key,first);if(r)return r;}
    bool boundary=d->au_vcl && ((type==1 || type==5)?!same_picture(key,d->key):(type!=12));
    if(boundary){r=decode_au(d);if(r)return r;}
    if(type==7){r=parse_sps(d,n);if(r)return r;}
    if(type==8){r=parse_pps(d,n);if(r)return r;}
    if(type==1 || type==5){
        if(!d->au_vcl){if(first!=0)return fail(d,AA_H264_UNSUPPORTED);d->key=key;d->au_ts=d->nal_ts;d->last_mb=first;}
        else {if(first<=d->last_mb)return fail(d,AA_H264_MALFORMED);d->last_mb=first;}
        d->au_vcl=true;
    }
    if(type==10 || type==11)return AA_H264_OK; /* explicit stream end marker; caller still owns EOF */
    if(d->nal_n+4>d->cfg.max_au_bytes-d->au_n)return fail(d,AA_H264_CAPACITY);
    static const uint8_t start[]={0,0,0,1};std::memcpy(d->au+d->au_n,start,4);d->au_n+=4;
    std::memcpy(d->au+d->au_n,d->nal,d->nal_n);d->au_n+=d->nal_n;return AA_H264_OK;
}
static int resume_nal(aa_h264 *d){if(!d->nal_pending)return AA_H264_OK;int r=process_nal(d);
    if(r)return r;
    d->nal_pending=false;d->nal_n=0;d->zeroes=0;return AA_H264_OK;}
static int drain(aa_h264 *d){
    int r=resume_nal(d);if(r)return r;
    if(!d->eof)return AA_H264_OK;
    r=decode_au(d);if(r)return r;
    if(!d->eos){int one=1;if(d->codec->SetOption(DECODER_OPTION_END_OF_STREAM,&one))return fail(d,AA_H264_CODEC);d->eos=true;}
    for(unsigned loops=0;loops<33;++loops){int before=0;
        if(d->codec->GetOption(DECODER_OPTION_NUM_OF_FRAMES_REMAINING_IN_BUFFER,&before) || before<0 || before>32)return fail(d,AA_H264_CODEC);
        if(!before){d->finished=true;return AA_H264_FINISHED;}
        uint8_t *p[3]={};SBufferInfo b={};DECODING_STATE s=d->codec->FlushFrame(p,&b);int after=0;
        if(s!=dsErrorFree || d->codec->GetOption(DECODER_OPTION_NUM_OF_FRAMES_REMAINING_IN_BUFFER,&after) || after>=before || after<0 || b.iBufferStatus!=1)
            return fail(d,AA_H264_CODEC);
        r=copy_frame(d,p,b);if(r)return r;
    }
    return fail(d,AA_H264_CODEC);
}
extern "C" int aa_h264_init(void *ctx,size_t cn,void *ws,size_t wn,const aa_h264_config *c,aa_h264 **out){
    if(out)*out=nullptr;
    size_t need=aa_h264_workspace_size(c);
    if(!out || !ctx || cn<sizeof(aa_h264) || reinterpret_cast<uintptr_t>(ctx)%alignof(aa_h264) || !ws || !need || wn<need)return AA_H264_ARGUMENT;
    aa_h264 *d=new(ctx) aa_h264{};d->cfg=*c;d->nal=static_cast<uint8_t*>(ws);d->rbsp=d->nal+c->max_nal_bytes+4;
    d->au=d->rbsp+c->max_nal_bytes;d->pixels=d->au+c->max_au_bytes;*out=d;return AA_H264_OK;
}
static int stop_inner(aa_h264 *d){if(d->codec){d->codec->Uninitialize();WelsDestroyDecoder(d->codec);d->codec=nullptr;}
    d->nal_n=d->au_n=0;d->pending=d->nal_pending=false;return AA_H264_OK;}
extern "C" int aa_h264_start(aa_h264 *d){
    if(!d)return AA_H264_ARGUMENT;
    if(d->busy)return AA_H264_REENTRANT;
    d->busy=true;stop_inner(d);
    d->error=0;d->in_nal=d->au_vcl=d->eof=d->eos=d->finished=false;d->zeroes=0;d->frame_index=0;
    std::memset(d->sps,0,sizeof(d->sps));std::memset(d->pps,0,sizeof(d->pps));
    if(WelsCreateDecoder(&d->codec) || !d->codec){d->busy=false;return fail(d,AA_H264_CODEC);}
    int threads=0,trace=0;d->codec->SetOption(DECODER_OPTION_TRACE_LEVEL,&trace);
    SDecodingParam p={};p.eEcActiveIdc=ERROR_CON_DISABLE;p.sVideoProperty.eVideoBsType=VIDEO_BITSTREAM_AVC;
    int r=d->codec->SetOption(DECODER_OPTION_NUM_OF_THREADS,&threads);
    if(!r)r=int(d->codec->Initialize(&p));
    d->busy=false;
    if(r){stop_inner(d);return fail(d,AA_H264_CODEC);}return AA_H264_OK;
}
extern "C" int aa_h264_reset(aa_h264 *d){return aa_h264_start(d);}
extern "C" int aa_h264_feed(aa_h264 *d,const uint8_t *data,size_t n,uint64_t ts,size_t *consumed){
    if(consumed)*consumed=0;
    if(!d || !consumed || (!data && n))return AA_H264_ARGUMENT;
    if(d->busy)return AA_H264_REENTRANT;
    if(d->error)return d->error;
    if(!d->codec)return AA_H264_STOPPED;
    if(d->pending)return AA_H264_PAUSED;
    if(d->eof)return AA_H264_FINISHED;
    d->busy=true;
    int r=resume_nal(d);if(r){d->busy=false;return r;}
    for(size_t i=0;i<n;++i){uint8_t c=data[i];++*consumed;
        if(!d->in_nal){if(c==0){if(d->zeroes<3)++d->zeroes;continue;}
            if(c==1 && d->zeroes>=2){d->in_nal=true;d->zeroes=0;continue;}
            r=fail(d,AA_H264_MALFORMED);break;
        }
        if(d->nal_n>=d->cfg.max_nal_bytes+4){r=fail(d,AA_H264_CAPACITY);break;}
        if(!d->nal_n)d->nal_ts=ts;
        d->nal[d->nal_n++]=c;
        if(c==1 && d->zeroes>=2){d->nal_n-=size_t(d->zeroes)+1;d->nal_pending=true;d->zeroes=0;
            r=resume_nal(d);if(r)break;
        }else {d->zeroes=c==0?d->zeroes+1:0;}
    }
    d->busy=false;return r;
}
extern "C" int aa_h264_retry(aa_h264 *d){
    if(!d)return AA_H264_ARGUMENT;
    if(d->busy)return AA_H264_REENTRANT;
    if(d->error)return d->error;
    if(!d->codec)return AA_H264_STOPPED;
    d->busy=true;int r=emit(d);if(!r)r=drain(d);d->busy=false;return r;
}
extern "C" int aa_h264_finish(aa_h264 *d){
    if(!d)return AA_H264_ARGUMENT;
    if(d->busy)return AA_H264_REENTRANT;
    if(d->error)return d->error;
    if(!d->codec)return AA_H264_STOPPED;
    if(d->pending)return AA_H264_PAUSED;
    if(d->finished)return AA_H264_FINISHED;
    d->busy=true;
    if(!d->eof){if(!d->in_nal || !d->nal_n){d->busy=false;return fail(d,AA_H264_TRUNCATED);}
        while(d->nal_n && d->nal[d->nal_n-1]==0)--d->nal_n;
        d->nal_pending=true;d->eof=true;}
    int r=drain(d);d->busy=false;return r;
}
extern "C" int aa_h264_stop(aa_h264 *d){if(!d)return AA_H264_ARGUMENT;
    if(d->busy)return AA_H264_REENTRANT;
    d->busy=true;
    stop_inner(d);d->error=0;d->busy=false;return AA_H264_OK;}
extern "C" int aa_h264_status(const aa_h264 *d){if(!d)return AA_H264_ARGUMENT;if(d->error)return d->error;
    if(!d->codec)return AA_H264_STOPPED;
    if(d->pending)return AA_H264_PAUSED;
    return d->finished?AA_H264_FINISHED:AA_H264_OK;}
extern "C" void aa_h264_destroy(aa_h264 *d){if(d && !d->busy){aa_h264_stop(d);d->~aa_h264();}}
