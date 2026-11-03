#ifndef REMOTE_BINDING_V1_H
#define REMOTE_BINDING_V1_H
#include <stdint.h>
int nsg_config_begin(uint32_t,uint32_t,const uint8_t *,uint32_t,uint32_t);
void nsg_config_end(int32_t);
int nsg_start_begin(uint32_t,uint32_t,uint32_t,uint32_t);
void nsg_start_end(int32_t);
void nsg_reply_witness(uint32_t,uint32_t);
int nsg_native_callback(uint32_t,uint32_t,const void *,const uint8_t *,uint32_t);
#endif
