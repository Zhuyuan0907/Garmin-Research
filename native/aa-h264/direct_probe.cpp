/* SPDX-License-Identifier: BSD-2-Clause */
/* Diagnostic independent AU control: packet offsets provided by ffprobe,
 * no own Annex-B/AU parser and no own wrapper used. */
#include "codec_api.h"
#include <cstdio>
#include <vector>
#include <fstream>
#include <iterator>
static void output(FILE *f,unsigned char **p,SBufferInfo &b){if(b.iBufferStatus!=1)return;
 for(unsigned plane=0;plane<3;++plane){int w=b.UsrData.sSystemBuffer.iWidth>>(plane?1:0),h=b.UsrData.sSystemBuffer.iHeight>>(plane?1:0);
  for(int y=0;y<h;++y)std::fwrite(p[plane]+y*b.UsrData.sSystemBuffer.iStride[plane?1:0],1,w,f);}}
int main(int argc,char **argv){if(argc!=4)return 3;
 std::ifstream src(argv[1],std::ios::binary);std::vector<unsigned char> data((std::istreambuf_iterator<char>(src)),std::istreambuf_iterator<char>());
 std::ifstream packets(argv[2]);FILE *out=std::fopen(argv[3],"wb");ISVCDecoder *d=nullptr;if(!out || WelsCreateDecoder(&d))return 2;
 int zero=0;d->SetOption(DECODER_OPTION_NUM_OF_THREADS,&zero);d->SetOption(DECODER_OPTION_TRACE_LEVEL,&zero);
 SDecodingParam param={};param.eEcActiveIdc=ERROR_CON_DISABLE;param.sVideoProperty.eVideoBsType=VIDEO_BITSTREAM_AVC;if(d->Initialize(&param))return 2;
 size_t pos,n;while(packets>>pos>>n){if(pos+n>data.size())return 2;unsigned char *p[3]={};SBufferInfo b={};
  if(d->DecodeFrameNoDelay(data.data()+pos,int(n),p,&b))return 2;output(out,p,b);}
 int one=1;d->SetOption(DECODER_OPTION_END_OF_STREAM,&one);for(int i=0;i<32;++i){int left=0;d->GetOption(DECODER_OPTION_NUM_OF_FRAMES_REMAINING_IN_BUFFER,&left);if(!left)break;
  unsigned char *p[3]={};SBufferInfo b={};if(d->FlushFrame(p,&b))return 2;output(out,p,b);}
 d->Uninitialize();WelsDestroyDecoder(d);std::fclose(out);return 0;}
