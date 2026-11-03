/* Test adapter, actual nanopb profile decoding. */
#include "input.h"
int aa_test_interactive_input_init(void *p,uint32_t s,void *control,
 const uint8_t *bytes,size_t n,const struct aa_input_viewport *viewport){
 f1x_aasdk_proto_messages_ServiceDiscoveryResponse profile={0};
 pb_istream_t in=pb_istream_from_buffer(bytes,n);
 if(!pb_decode(&in,f1x_aasdk_proto_messages_ServiceDiscoveryResponse_fields,&profile)||in.bytes_left)return -700004;
 return aa_input_init(p,s,control,&profile,viewport);
}
