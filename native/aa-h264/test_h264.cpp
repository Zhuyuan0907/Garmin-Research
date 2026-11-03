/* SPDX-License-Identifier: BSD-2-Clause */
#include "h264.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <algorithm>
#include <fstream>
#include <iterator>
static unsigned checks;
#define CHECK(x) do{++checks;if(!(x)){std::fprintf(stderr,"FAIL:%d:%s\n",__LINE__,#x);std::exit(2);}}while(0)
struct sink {
    aa_h264 *decoder;
    FILE *out;
    bool pause,waiting;
    uint64_t frames,attempts,index;
    unsigned width,height;
    const uint8_t *address;
    std::vector<uint8_t> held;
};
static std::vector<uint8_t> copy(const aa_h264_frame *f){
    std::vector<uint8_t> v;
    for(unsigned p=0;p<3;++p){size_t w=f->width>>(p?1:0),h=f->height>>(p?1:0);
        CHECK(f->strides[p]==w);
        for(size_t y=0;y<h;++y)v.insert(v.end(),f->planes[p]+y*f->strides[p],f->planes[p]+y*f->strides[p]+w);
    }
    return v;
}
static int callback(void *u,const aa_h264_frame *f){
    sink &s=*static_cast<sink*>(u);++s.attempts;
    size_t consumed=123;
    CHECK(aa_h264_feed(s.decoder,nullptr,0,0,&consumed)==AA_H264_REENTRANT && consumed==0);
    CHECK(aa_h264_retry(s.decoder)==AA_H264_REENTRANT);
    CHECK(aa_h264_finish(s.decoder)==AA_H264_REENTRANT);
    CHECK(aa_h264_start(s.decoder)==AA_H264_REENTRANT);
    CHECK(aa_h264_stop(s.decoder)==AA_H264_REENTRANT);
    std::vector<uint8_t> bytes=copy(f);
    if(s.pause && !s.waiting){s.held=bytes;s.address=f->planes[0];s.index=f->index;s.waiting=true;return AA_H264_PAUSED;}
    if(s.waiting){CHECK(s.address==f->planes[0] && s.index==f->index && s.held==bytes);s.waiting=false;}
    CHECK(f->index==s.frames);s.width=f->width;s.height=f->height;
    if(s.out)CHECK(std::fwrite(bytes.data(),1,bytes.size(),s.out)==bytes.size());
    ++s.frames;return AA_H264_OK;
}
struct instance {
    std::vector<uint64_t> context;
    std::vector<uint8_t> workspace;
    sink output;
    aa_h264 *decoder;
    instance(bool pause,unsigned width=800,unsigned height=480,size_t nc=262144,size_t ac=524288):output{},decoder(nullptr){
        output.pause=pause;
        aa_h264_config cfg={width,height,nc,ac,callback,&output};
        CHECK(aa_h264_context_align()<=alignof(uint64_t));
        context.resize((aa_h264_context_size()+7)/8);
        size_t need=aa_h264_workspace_size(&cfg);CHECK(need>0);workspace.resize(need+2,0xa5);
        CHECK(aa_h264_init(context.data(),context.size()*8,workspace.data()+1,need,&cfg,&decoder)==AA_H264_OK);
        output.decoder=decoder;CHECK(aa_h264_status(decoder)==AA_H264_STOPPED);
        CHECK(aa_h264_start(decoder)==AA_H264_OK);
    }
    ~instance(){aa_h264_destroy(decoder);CHECK(workspace.front()==0xa5 && workspace.back()==0xa5);}
};
static int deliver(instance &d,const std::vector<uint8_t> &src,size_t chunk,bool stop_pending=false){
    size_t offset=0;unsigned round=0;int result=0;
    while(offset<src.size()){
        size_t amount=chunk?chunk:size_t((round*7919U)%2048U)+1;
        amount=std::min(amount,src.size()-offset);
        std::vector<uint8_t> buffer(src.begin()+offset,src.begin()+offset+amount);
        size_t consumed=999;result=aa_h264_feed(d.decoder,buffer.data(),buffer.size(),round++,&consumed);
        CHECK(consumed<=amount);offset+=consumed;std::fill(buffer.begin(),buffer.end(),0xee);
        if(result==AA_H264_PAUSED){
            size_t n=999;CHECK(aa_h264_feed(d.decoder,nullptr,0,0,&n)==AA_H264_PAUSED && n==0);
            CHECK(aa_h264_status(d.decoder)==AA_H264_PAUSED);
            if(stop_pending){CHECK(aa_h264_stop(d.decoder)==0);d.output.waiting=false;return AA_H264_STOPPED;}
            result=aa_h264_retry(d.decoder);CHECK(result==0);
        }
        if(result<0)return result;
        CHECK(consumed>0);
    }
    result=aa_h264_finish(d.decoder);
    while(result==AA_H264_PAUSED){result=aa_h264_retry(d.decoder);}
    CHECK(aa_h264_status(d.decoder)==result);
    return result;
}
static std::vector<uint8_t> read(const char *path){std::ifstream f(path,std::ios::binary);CHECK(f.good());return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),std::istreambuf_iterator<char>());}
static void guards(){
    instance d(false);
    size_t n=9;CHECK(aa_h264_feed(d.decoder,nullptr,1,0,&n)==AA_H264_ARGUMENT && n==0);
    uint8_t junk[]={0x12};CHECK(aa_h264_feed(d.decoder,junk,1,0,&n)==AA_H264_MALFORMED && n==1);
    CHECK(aa_h264_finish(d.decoder)==AA_H264_MALFORMED);
    CHECK(aa_h264_retry(d.decoder)==AA_H264_MALFORMED);
    CHECK(aa_h264_reset(d.decoder)==0);
    uint8_t partial[]={0,0};CHECK(aa_h264_feed(d.decoder,partial,2,0,&n)==0 && n==2);
    CHECK(aa_h264_finish(d.decoder)==AA_H264_TRUNCATED);
    CHECK(aa_h264_reset(d.decoder)==0);CHECK(aa_h264_stop(d.decoder)==0);CHECK(aa_h264_stop(d.decoder)==0);
    CHECK(aa_h264_feed(d.decoder,junk,1,0,&n)==AA_H264_STOPPED && n==0);
    aa_h264_config bad={802,480,32,64,callback,&d.output};CHECK(aa_h264_workspace_size(&bad)==0);
    bad.max_width=800;bad.max_height=479;CHECK(aa_h264_workspace_size(&bad)==0);
    bad.max_height=480;bad.max_nal_bytes=SIZE_MAX;CHECK(aa_h264_workspace_size(&bad)==0);
    bad.max_nal_bytes=32;bad.max_au_bytes=35;CHECK(aa_h264_workspace_size(&bad)==0);
    bad.max_au_bytes=64;aa_h264 *out=reinterpret_cast<aa_h264*>(1);
    CHECK(aa_h264_init(d.context.data(),1,d.workspace.data(),d.workspace.size(),&bad,&out)==AA_H264_ARGUMENT && !out);
    CHECK(aa_h264_init(reinterpret_cast<uint8_t*>(d.context.data())+1,d.context.size()*8-1,d.workspace.data(),d.workspace.size(),&bad,&out)==AA_H264_ARGUMENT);
    std::printf("{\"pass\":true,\"checks\":%u}\n",checks);
}
int main(int argc,char **argv){
    if(argc==2 && !std::strcmp(argv[1],"guards")){guards();return 0;}
    if(argc<6 || std::strcmp(argv[1],"decode"))return 3;
    std::vector<uint8_t> input=read(argv[2]);size_t chunk=std::strtoull(argv[4],nullptr,10);bool pause=std::atoi(argv[5])!=0;
    unsigned width=argc>6?unsigned(std::atoi(argv[6])):800,height=argc>7?unsigned(std::atoi(argv[7])):480;
    size_t nc=argc>8?std::strtoull(argv[8],nullptr,10):262144,ac=argc>9?std::strtoull(argv[9],nullptr,10):524288;
    instance d(pause,width,height,nc,ac);d.output.out=std::fopen(argv[3],"wb");CHECK(d.output.out);
    int result=deliver(d,input,chunk);std::fclose(d.output.out);d.output.out=nullptr;
    if(result<0){size_t n=3;CHECK(aa_h264_feed(d.decoder,nullptr,0,0,&n)==result && n==0);CHECK(aa_h264_retry(d.decoder)==result);}
    CHECK(aa_h264_stop(d.decoder)==0);CHECK(aa_h264_status(d.decoder)==AA_H264_STOPPED);
    if(result==AA_H264_FINISHED){
        CHECK(aa_h264_start(d.decoder)==0);d.output.frames=d.output.attempts=0;d.output.waiting=false;
        CHECK(deliver(d,input,chunk)==AA_H264_FINISHED); /* reset fresh codec including SPS/PPS/DPB */
    }
    std::printf("{\"status\":%d,\"frames\":%llu,\"callback_attempts\":%llu,\"width\":%u,\"height\":%u,\"checks\":%u}\n",
        result,(unsigned long long)d.output.frames,(unsigned long long)d.output.attempts,d.output.width,d.output.height,checks);
    return 0;
}
