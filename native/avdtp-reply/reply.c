/* HWID1352/8.00 private ABI, offline-only prototype. */
#include <stdint.h>

typedef int32_t (*send_fn)(uint32_t,uint32_t,uint8_t *,uint16_t *);
extern int32_t stock_reply_relocated(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t);

int32_t music_reply_dispatch(uint32_t channel,uint32_t transaction,uint32_t signal,
                             uint32_t category,uint32_t error)
{
    /* Preserve all known-signal and other-error paths through original code. */
    if (error != 1 || (signal >= 1 && signal <= 10))
        return stock_reply_relocated(channel,transaction,signal,category,error);
    if (channel >= 12 || transaction > 15 || signal > 63)
        return -41;
    uint8_t packet[6] = {0,0,0,0,(uint8_t)((transaction << 4) | 1),(uint8_t)signal};
    uint16_t written = 0;
    volatile const uint16_t *lcid = (volatile const uint16_t *)(0x03a88f50 + channel * 8);
    return ((send_fn)0x005a7795)(*lcid,sizeof(packet),packet,&written);
}
