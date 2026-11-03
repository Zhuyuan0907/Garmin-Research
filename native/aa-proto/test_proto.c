/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "proto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#ifdef PB_ENABLE_MALLOC
#error "This bounded layer must not enable malloc"
#endif
static unsigned assertions,categories;
#define CHECK(x) do{++assertions;if(!(x)){fprintf(stderr,"FAIL:%d:%s\n",__LINE__,#x);exit(2);}}while(0)
#define CATEGORY(n) do{++categories;printf("PASS %s\n",n);}while(0)
union messages {
 f1x_aasdk_proto_messages_ServiceDiscoveryRequest ServiceDiscoveryRequest;
 f1x_aasdk_proto_messages_ServiceDiscoveryResponse ServiceDiscoveryResponse;
 f1x_aasdk_proto_messages_ChannelOpenRequest ChannelOpenRequest;
 f1x_aasdk_proto_messages_ChannelOpenResponse ChannelOpenResponse;
 f1x_aasdk_proto_messages_PingRequest PingRequest;
 f1x_aasdk_proto_messages_PingResponse PingResponse;
 f1x_aasdk_proto_messages_AVChannelSetupRequest AVChannelSetupRequest;
 f1x_aasdk_proto_messages_AVChannelSetupResponse AVChannelSetupResponse;
 f1x_aasdk_proto_messages_AVChannelStartIndication AVChannelStartIndication;
 f1x_aasdk_proto_messages_AVChannelStopIndication AVChannelStopIndication;
 f1x_aasdk_proto_messages_AVMediaAckIndication AVMediaAckIndication;
 f1x_aasdk_proto_messages_BindingRequest BindingRequest;
 f1x_aasdk_proto_messages_BindingResponse BindingResponse;
 f1x_aasdk_proto_messages_VideoFocusRequest VideoFocusRequest;
 f1x_aasdk_proto_messages_VideoFocusIndication VideoFocusIndication;
 f1x_aasdk_proto_messages_AudioFocusRequest AudioFocusRequest;
 f1x_aasdk_proto_messages_AudioFocusResponse AudioFocusResponse;
 f1x_aasdk_proto_messages_ShutdownRequest ShutdownRequest;
 f1x_aasdk_proto_messages_ShutdownResponse ShutdownResponse;
};
struct entry {const char *name;const pb_msgdesc_t *fields;size_t bytes;};
static const struct entry entries[]={
 {"ServiceDiscoveryRequest",f1x_aasdk_proto_messages_ServiceDiscoveryRequest_fields,sizeof(f1x_aasdk_proto_messages_ServiceDiscoveryRequest)},
 {"ServiceDiscoveryResponse",f1x_aasdk_proto_messages_ServiceDiscoveryResponse_fields,sizeof(f1x_aasdk_proto_messages_ServiceDiscoveryResponse)},
 {"ChannelOpenRequest",f1x_aasdk_proto_messages_ChannelOpenRequest_fields,sizeof(f1x_aasdk_proto_messages_ChannelOpenRequest)},
 {"ChannelOpenResponse",f1x_aasdk_proto_messages_ChannelOpenResponse_fields,sizeof(f1x_aasdk_proto_messages_ChannelOpenResponse)},
 {"PingRequest",f1x_aasdk_proto_messages_PingRequest_fields,sizeof(f1x_aasdk_proto_messages_PingRequest)},
 {"PingResponse",f1x_aasdk_proto_messages_PingResponse_fields,sizeof(f1x_aasdk_proto_messages_PingResponse)},
 {"AVChannelSetupRequest",f1x_aasdk_proto_messages_AVChannelSetupRequest_fields,sizeof(f1x_aasdk_proto_messages_AVChannelSetupRequest)},
 {"AVChannelSetupResponse",f1x_aasdk_proto_messages_AVChannelSetupResponse_fields,sizeof(f1x_aasdk_proto_messages_AVChannelSetupResponse)},
 {"AVChannelStartIndication",f1x_aasdk_proto_messages_AVChannelStartIndication_fields,sizeof(f1x_aasdk_proto_messages_AVChannelStartIndication)},
 {"AVChannelStopIndication",f1x_aasdk_proto_messages_AVChannelStopIndication_fields,sizeof(f1x_aasdk_proto_messages_AVChannelStopIndication)},
 {"AVMediaAckIndication",f1x_aasdk_proto_messages_AVMediaAckIndication_fields,sizeof(f1x_aasdk_proto_messages_AVMediaAckIndication)},
 {"BindingRequest",f1x_aasdk_proto_messages_BindingRequest_fields,sizeof(f1x_aasdk_proto_messages_BindingRequest)},
 {"BindingResponse",f1x_aasdk_proto_messages_BindingResponse_fields,sizeof(f1x_aasdk_proto_messages_BindingResponse)},
 {"VideoFocusRequest",f1x_aasdk_proto_messages_VideoFocusRequest_fields,sizeof(f1x_aasdk_proto_messages_VideoFocusRequest)},
 {"VideoFocusIndication",f1x_aasdk_proto_messages_VideoFocusIndication_fields,sizeof(f1x_aasdk_proto_messages_VideoFocusIndication)},
 {"AudioFocusRequest",f1x_aasdk_proto_messages_AudioFocusRequest_fields,sizeof(f1x_aasdk_proto_messages_AudioFocusRequest)},
 {"AudioFocusResponse",f1x_aasdk_proto_messages_AudioFocusResponse_fields,sizeof(f1x_aasdk_proto_messages_AudioFocusResponse)},
 {"ShutdownRequest",f1x_aasdk_proto_messages_ShutdownRequest_fields,sizeof(f1x_aasdk_proto_messages_ShutdownRequest)},
 {"ShutdownResponse",f1x_aasdk_proto_messages_ShutdownResponse_fields,sizeof(f1x_aasdk_proto_messages_ShutdownResponse)},
};

static bool decode(const pb_msgdesc_t *fields,void *out,const uint8_t *data,size_t n)
{pb_istream_t s=pb_istream_from_buffer(data,n);return pb_decode(&s,fields,out);}
static bool encode(const pb_msgdesc_t *fields,const void *src,uint8_t *data,size_t cap,size_t *n)
{pb_ostream_t s=pb_ostream_from_buffer(data,cap);bool ok=pb_encode(&s,fields,src);*n=s.bytes_written;return ok;}
static void output(const pb_msgdesc_t *fields,const void *src)
{
 uint8_t out[16384];size_t n,i;
 if(!encode(fields,src,out,sizeof(out),&n)){puts("{\"decoded\":true,\"encoded\":false}");return;}
 printf("{\"decoded\":true,\"encoded\":true,\"hex\":\"");
 for(i=0;i<n;++i)printf("%02x",out[i]);
 printf("\",\"bytes\":%zu}\n",n);
}
static void selftest(void)
{
 uint8_t raw[2048],out[2048];size_t n;pb_istream_t in;pb_ostream_t os;uint64_t v;
 const uint8_t vmax[]={255,255,255,255,255,255,255,255,255,1};
 os=pb_ostream_from_buffer(out,sizeof(out));CHECK(pb_encode_varint(&os,UINT64_MAX));
 CHECK(os.bytes_written==10);CHECK(memcmp(out,vmax,10)==0);
 in=pb_istream_from_buffer(vmax,sizeof(vmax));CHECK(pb_decode_varint(&in,&v));CHECK(v==UINT64_MAX);
 CATEGORY("unsigned-64-varint-literal-maximum");
 const uint8_t vover[]={255,255,255,255,255,255,255,255,255,2};
 in=pb_istream_from_buffer(vover,sizeof(vover));CHECK(!pb_decode_varint(&in,&v));CATEGORY("uint64-overflow-rejected");
 const uint8_t vtrunc[]={128};in=pb_istream_from_buffer(vtrunc,1);CHECK(!pb_decode_varint(&in,&v));CATEGORY("truncated-varint");
 f1x_aasdk_proto_messages_ChannelOpenResponse req=f1x_aasdk_proto_messages_ChannelOpenResponse_init_zero;
 CHECK(!decode(f1x_aasdk_proto_messages_ChannelOpenResponse_fields,&req,NULL,0));
 const uint8_t ok[]={8,0};CHECK(decode(f1x_aasdk_proto_messages_ChannelOpenResponse_fields,&req,ok,2));
 CHECK(req.status==0);CHECK(encode(f1x_aasdk_proto_messages_ChannelOpenResponse_fields,&req,out,2,&n));
 CHECK(n==2 && memcmp(out,ok,2)==0);CATEGORY("required-zero-present-not-omitted");
 memset(out,0xa5,sizeof(out));CHECK(!encode(f1x_aasdk_proto_messages_ChannelOpenResponse_fields,&req,out+1,1,&n));
 CHECK(out[0]==0xa5 && out[2]==0xa5);CATEGORY("encode-output-capacity-rejection");
 const uint8_t unknown[]={8,0,0xa0,6,1};
 CHECK(decode(f1x_aasdk_proto_messages_ChannelOpenResponse_fields,&req,unknown,sizeof(unknown)));
 CHECK(encode(f1x_aasdk_proto_messages_ChannelOpenResponse_fields,&req,out,sizeof(out),&n));
 CHECK(n==2 && memcmp(out,ok,2)==0);CATEGORY("unknown-field-skipped-on-reencode");
 const uint8_t zero[]={0};CHECK(!decode(f1x_aasdk_proto_messages_ChannelOpenResponse_fields,&req,zero,1));
 const uint8_t badwire[]={14,0};CHECK(!decode(f1x_aasdk_proto_messages_ChannelOpenResponse_fields,&req,badwire,2));
 CATEGORY("illegal-zero-tag-and-wire-type");
 const uint8_t truncated[]={8,128};CHECK(!decode(f1x_aasdk_proto_messages_ChannelOpenResponse_fields,&req,truncated,2));CATEGORY("required-varint-truncated");
 f1x_aasdk_proto_messages_ServiceDiscoveryRequest request=f1x_aasdk_proto_messages_ServiceDiscoveryRequest_init_zero;
 raw[0]=0x22;raw[1]=63;memset(raw+2,'a',63);
 CHECK(decode(f1x_aasdk_proto_messages_ServiceDiscoveryRequest_fields,&request,raw,65));CHECK(strlen(request.device_name)==63);
 raw[1]=64;raw[65]='a';CHECK(!decode(f1x_aasdk_proto_messages_ServiceDiscoveryRequest_fields,&request,raw,66));
 CATEGORY("static-string-63-byte-bound");
 const uint8_t invalidutf[]={0x22,2,0xc0,0xaf};
 CHECK(!decode(f1x_aasdk_proto_messages_ServiceDiscoveryRequest_fields,&request,invalidutf,4));CATEGORY("UTF8-validation");
 memset(&request,0,sizeof(request));memset(request.device_name,'a',64);
 CHECK(!encode(f1x_aasdk_proto_messages_ServiceDiscoveryRequest_fields,&request,out,sizeof(out),&n));CATEGORY("unterminated-C-string-encode-rejected");
 struct guarded {uint64_t before;f1x_aasdk_proto_messages_BindingRequest data;uint64_t after;} binding;
 binding.before=UINT64_C(0xDEADFACEDEADFACE);binding.after=UINT64_C(0xBADDCAFEBADDCAFE);
 raw[0]=10;raw[1]=128;raw[2]=1;memset(raw+3,1,128);
 CHECK(decode(f1x_aasdk_proto_messages_BindingRequest_fields,&binding.data,raw,131));CHECK(binding.data.scan_codes_count==128);
 raw[1]=129;raw[131]=1;CHECK(!decode(f1x_aasdk_proto_messages_BindingRequest_fields,&binding.data,raw,132));
 CHECK(binding.before==UINT64_C(0xDEADFACEDEADFACE));CHECK(binding.after==UINT64_C(0xBADDCAFEBADDCAFE));
 CATEGORY("static-repeated-128-elements-and-guard");
 memset(&binding.data,0,sizeof(binding.data));binding.data.scan_codes_count=129;
 CHECK(!encode(f1x_aasdk_proto_messages_BindingRequest_fields,&binding.data,out,sizeof(out),&n));CATEGORY("invalid-repeated-count-encode-rejected");
 f1x_aasdk_proto_messages_AVMediaAckIndication ack=f1x_aasdk_proto_messages_AVMediaAckIndication_init_zero;
 CHECK(!decode(f1x_aasdk_proto_messages_AVMediaAckIndication_fields,&ack,ok,2));
 const uint8_t ackboth[]={8,0,16,0};CHECK(decode(f1x_aasdk_proto_messages_AVMediaAckIndication_fields,&ack,ackboth,4));
 CHECK(encode(f1x_aasdk_proto_messages_AVMediaAckIndication_fields,&ack,out,sizeof(out),&n));CHECK(n==4 && memcmp(out,ackboth,4)==0);
 CATEGORY("multiple-required-zero-fields");
 f1x_aasdk_proto_messages_AVChannelSetupResponse setup=f1x_aasdk_proto_messages_AVChannelSetupResponse_init_zero;
 const uint8_t setupraw[]={8,2,16,1,24,0};CHECK(decode(f1x_aasdk_proto_messages_AVChannelSetupResponse_fields,&setup,setupraw,6));
 CHECK(setup.media_status==2 && setup.max_unacked==1 && setup.configs_count==1 && setup.configs[0]==0);
 CATEGORY("proto2-setup-repeated-unpacked");
 printf("RESULT {\"categories\":%u,\"assertions\":%u,\"service_response_struct_bytes\":%zu,\"service_response_max_encoded\":%u,\"success\":true}\n",categories,assertions,sizeof(f1x_aasdk_proto_messages_ServiceDiscoveryResponse),(unsigned)f1x_aasdk_proto_messages_ServiceDiscoveryResponse_size);
}
static void emit_service(void)
{
 f1x_aasdk_proto_messages_ServiceDiscoveryResponse s=f1x_aasdk_proto_messages_ServiceDiscoveryResponse_init_zero;
 strcpy(s.head_unit_name,"Garmin research host");strcpy(s.sw_version,"host-only");s.channels_count=3;
 s.channels[0].channel_id=1;s.channels[0].has_input_channel=true;
 s.channels[0].input_channel.has_touch_screen_config=true;s.channels[0].input_channel.touch_screen_config.width=800;s.channels[0].input_channel.touch_screen_config.height=480;
 s.channels[0].input_channel.supported_keycodes_count=2;s.channels[0].input_channel.supported_keycodes[0]=4;s.channels[0].input_channel.supported_keycodes[1]=85;
 s.channels[1].channel_id=3;s.channels[1].has_av_channel=true;s.channels[1].av_channel.stream_type=f1x_aasdk_proto_enums_AVStreamType_Enum_VIDEO;
 s.channels[1].av_channel.video_configs_count=1;s.channels[1].av_channel.video_configs[0].video_resolution=f1x_aasdk_proto_enums_VideoResolution_Enum__480p;
 s.channels[1].av_channel.video_configs[0].video_fps=f1x_aasdk_proto_enums_VideoFPS_Enum__30;
 s.channels[2].channel_id=4;s.channels[2].has_av_channel=true;s.channels[2].av_channel.stream_type=f1x_aasdk_proto_enums_AVStreamType_Enum_AUDIO;
 s.channels[2].av_channel.audio_type=f1x_aasdk_proto_enums_AudioType_Enum_MEDIA;s.channels[2].av_channel.audio_configs_count=1;
 s.channels[2].av_channel.audio_configs[0].sample_rate=48000;s.channels[2].av_channel.audio_configs[0].bit_depth=16;s.channels[2].av_channel.audio_configs[0].channel_count=2;
 output(f1x_aasdk_proto_messages_ServiceDiscoveryResponse_fields,&s);
}
static int nibble(char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;}
int main(int argc,char **argv)
{
 size_t i,n;uint8_t data[16384];union messages msg;const struct entry *e=NULL;pb_istream_t stream;
 if(argc==2 && !strcmp(argv[1],"selftest")){selftest();return 0;}
 if(argc==2 && !strcmp(argv[1],"emit-service")){emit_service();return 0;}
 if(argc!=3)return 3;
 for(i=0;i<sizeof(entries)/sizeof(entries[0]);++i)if(!strcmp(argv[1],entries[i].name)){e=entries+i;break;}
 if(!e)return 3;
 n=strlen(argv[2]);if(n%2 || n/2>sizeof(data))return 3;
 for(i=0;i<n/2;++i){int a=nibble(argv[2][i*2]),b=nibble(argv[2][i*2+1]);if(a<0||b<0)return 3;data[i]=(uint8_t)(a*16+b);}
 memset(&msg,0,sizeof(msg));stream=pb_istream_from_buffer(data,n/2);
 if(!pb_decode(&stream,e->fields,&msg)){printf("{\"decoded\":false,\"error\":\"%s\"}\n",PB_GET_ERROR(&stream));return 0;}
 output(e->fields,&msg);return 0;
}
