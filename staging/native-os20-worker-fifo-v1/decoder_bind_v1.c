/* Compile-time calls into the sealed decoder ELF; no host decode hook. */
#include "../../native/sbc-prototype/decoder.h"
#include "worker_fifo_v1.h"
int garmin_sbc_reset(void){return ((int (*)(void))0x0800223cu)();}
int garmin_sbc_decode_frame(const uint8_t *p,uint32_t n,uint8_t *out,uint32_t cap,
                           struct decoder_result *result){
    uint32_t index=fifo_observations_v1.decoder_calls++;
    if(index<4)fifo_observations_v1.decoder_actors[index]=((uint32_t (*)(void))0x358d25u)();
    int status=((int (*)(const uint8_t *,uint32_t,uint8_t *,uint32_t,struct decoder_result *))
               0x08002284u)(p,n,out,cap,result);
    fifo_observations_v1.decoder_returns++;return status;
}
