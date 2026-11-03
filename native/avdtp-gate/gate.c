/* Candidate configuration dispatcher. Never modifies stock instructions or
 * tables. An installer/loader and actual dispatch binding are not provided.
 */
#include "gate.h"
#include "../avdtp-policy/policy.h"

struct gate_binding {uint32_t callback;};
volatile struct gate_binding music_gate_bindings[3];
_Static_assert(sizeof(music_gate_bindings)==12,"Binding ABI");
_Static_assert(sizeof(uintptr_t)==4,"Exact32-bit firmware ABI");
typedef int (*stock_handler)(uint32_t,uint32_t,uint32_t,const uint8_t *,uint32_t);
typedef int (*stock_reply)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t);
static volatile uint8_t *sep(uint32_t index){return (volatile uint8_t *)(0x03a88ef0u+index*32u);}
static volatile uint8_t *descriptor(uint32_t index){return (volatile uint8_t *)(0x03a89058u+index*12u);}
uint32_t music_gate_binding_bytes(void){return sizeof(music_gate_bindings);}

static const volatile uint8_t *capabilities(uint32_t index)
{
    volatile uint8_t *d=descriptor(index);
    if(d[4]!=4u || d[5] || d[6] || d[8]!=1u)return 0;
    uint32_t address=*(volatile uint32_t *)d;
    if(!address || address>UINT32_MAX-4u)return 0;
    const volatile uint8_t *c=(const volatile uint8_t *)address;
    if(!(c[0]&0x30u) || !(c[0]&15u) || !(c[1]&0xf0u) || !(c[1]&12u) ||
        !(c[1]&3u) || c[2]<2u || c[3]>53u || c[2]>c[3])return 0;
    return c;
}
int music_gate_claim(uint32_t seid,uint32_t callback)
{
    if(!seid || seid>3u || !callback)return -20;
    uint32_t index=seid-1u;volatile uint8_t *s=sep(index);
    if(music_gate_bindings[index].callback || *(volatile uint32_t *)s!=callback ||
        s[0x12]!=1u || s[0x13] || !capabilities(index))return -21;
    music_gate_bindings[index].callback=callback;return 0;
}
int music_gate_release(uint32_t seid,uint32_t callback)
{
    if(!seid || seid>3u || !callback || music_gate_bindings[seid-1u].callback!=callback)return -20;
    volatile uint8_t *s=sep(seid-1u);
    /* Actual owner changes or module retirement require a separate quiescence
     *protocol; fail closed rather than silently clearing a stale claim.
     */
    if(*(volatile uint32_t *)s!=callback || s[0x12]!=1u || s[0x13])return -21;
    music_gate_bindings[seid-1u].callback=0;return 0;
}
static int rejection(uint32_t channel,uint32_t signal,uint32_t transaction,uint32_t category,uint32_t error)
{return ((stock_reply)0x005756adu)(channel,transaction,signal,category,error);}

int music_configuration_gate(uint32_t context,uint32_t signal,uint32_t transaction,
    const uint8_t *p,uint32_t n)
{
    if(context>=2u || (signal!=3u && signal!=5u) || transaction>15u)return -20;
    volatile uint8_t *ctx=(volatile uint8_t *)(0x03a88eb8u+context*28u);
    uint32_t channel=ctx[0x13];if(channel>=12u)return -20;
    volatile uint8_t *ch=(volatile uint8_t *)(0x03a88f50u+channel*8u);
    if(*(volatile uint16_t *)ch<0x40u || ch[4] || ch[6]!=context || ch[5]!=0x10u)return -20;
    uintptr_t pointer=(uintptr_t)p;
    if(!pointer || !n || n>128u || pointer>UINT32_MAX-n)
        return rejection(channel,signal,transaction,0,0x11);
    uint32_t seid=p[0]>>2;
    if(!seid || seid>3u)return rejection(channel,signal,transaction,0,0x12);
    uint32_t index=seid-1u,owner=music_gate_bindings[index].callback;
    if(!owner)return ((stock_handler)0x00574acdu)(context,signal,transaction,p,n);
    volatile uint8_t *s=sep(index);
    if(*(volatile uint32_t *)s!=owner)return -22;
    const volatile uint8_t *caps=capabilities(index);if(!caps)return -22;
    /* Reconfiguration is deliberately unsupported for a claimed music SEP.
     *Other SEPs retain the original handler; selected bitpool variation inside
     *the negotiated range does not require replacing the configuration.
     */
    if(signal==5u)return rejection(channel,signal,transaction,7,0x29);
    if(n<2u)return rejection(channel,signal,transaction,0,0x11);
    if((p[0]&3u) || (p[1]&3u))return rejection(channel,signal,transaction,0,1);
    if(!(p[1]>>2) || p[1]>>2>62u)return rejection(channel,signal,transaction,0,0x18);
    uint32_t position=2u,seen=0;
    while(position<n) {
        uint32_t category=p[position];
        if(n-position<2u)return rejection(channel,signal,transaction,category,0x11);
        uint32_t length=p[position+1u];position+=2u;
        if(length>n-position)return rejection(channel,signal,transaction,category,0x11);
        if(category==1u) {
            if(seen&1u)return rejection(channel,signal,transaction,1,0x17);
            if(length)return rejection(channel,signal,transaction,1,0x23);
            seen|=1u;
        } else if(category==7u) {
            if(seen&2u)return rejection(channel,signal,transaction,7,0x17);
            if(length!=6u)return rejection(channel,signal,transaction,7,0x11);
            seen|=2u;
        } else return rejection(channel,signal,transaction,category,category>=2u && category<=8u?0x29:0x17);
        position+=length;
    }
    if(!(seen&1u))return rejection(channel,signal,transaction,1,0x29);
    if(!(seen&2u))return rejection(channel,signal,transaction,7,0x29);
    struct music_config config;
    int result=music_validate_configuration(p,n,seid,&config);
    if(result)return rejection(channel,signal,transaction,7,0x29);
    uint32_t a=config.codec_word&255u,b=config.codec_word>>8&255u;
    if((a&caps[0])!=a || (b&caps[1])!=b || (config.codec_word>>16&255u)<caps[2] ||
        config.codec_word>>24>caps[3])return rejection(channel,signal,transaction,7,0x29);
    return ((stock_handler)0x00574acdu)(context,signal,transaction,p,n);
}
