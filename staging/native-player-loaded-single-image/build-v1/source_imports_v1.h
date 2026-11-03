#include <stdint.h>
extern int aas_media_ingress(uint32_t,uint32_t,const void *,const uint8_t *,uint32_t);
extern int mh_request_command(uint32_t);
#define NSG_SOURCE_INGRESS ((uintptr_t)&aas_media_ingress)
#define NSG_SOURCE_COMMAND ((uintptr_t)&mh_request_command)
