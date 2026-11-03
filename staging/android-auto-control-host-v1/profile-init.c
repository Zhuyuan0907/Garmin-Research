/* Host test adapter; profiles decoded by real nanopb. */
#include "control.h"
int aa_test_control_init(void *ctx,uint32_t session,const unsigned char *p,
                         size_t n,aa_control_provider cb,void *arg){
    f1x_aasdk_proto_messages_ServiceDiscoveryResponse value={0};
    pb_istream_t in=pb_istream_from_buffer(p,n);
    if(!pb_decode(&in,f1x_aasdk_proto_messages_ServiceDiscoveryResponse_fields,&value))
        return AA_CONTROL_E_PROTOBUF;
    return aa_control_init(ctx,session,&value,cb,arg);
}
