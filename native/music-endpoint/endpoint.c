/* Custom endpoint provider, not a recovered original registration API. Uses
 * original lock/SDP primitives and exact-image SEP/descriptor ABI. No installer.
 */
#include "endpoint.h"
#include "../avdtp-gate/gate.h"
typedef int (*mutex_operation)(volatile uint32_t *);
typedef int (*sdp_operation)(uint32_t);
typedef int (*cap_handler)(uint32_t,uint32_t,uint32_t,const uint8_t *,uint32_t);
typedef int (*cap_serializer)(uint32_t,uint32_t,uint32_t,const uint8_t *,uint32_t,uint32_t);
typedef int (*reply_handler)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t);
volatile uint32_t music_endpoint_owners[3];
volatile uint32_t music_endpoint_publication;
static const uint8_t music_endpoint_sbc_caps[4]={0x3f,0xff,2,53};
static volatile uint8_t *sep(uint32_t i){return (volatile uint8_t *)(0x03a88ef0u+i*32u);}
static volatile uint8_t *descriptor(uint32_t i){return (volatile uint8_t *)(0x03a89058u+i*12u);}
static int lock(void){return ((mutex_operation)0x005523dfu)((volatile uint32_t *)0x00f50098u);}
static int unlock(void){return ((mutex_operation)0x005523fdu)((volatile uint32_t *)0x00f50098u);}
static int done(int value){return unlock()<0?-38:value;}
int music_endpoint_prepare(uint32_t callback,uint32_t mtu)
{
    if(!callback || mtu<48u || mtu>4096u)return -30;
    if(lock()<0)return -31;
    for(uint32_t i=0;i<3u;i++)if(music_endpoint_owners[i]==callback)return done(-39);
    for(uint32_t i=0;i<3u;i++) {
        volatile uint8_t *s=sep(i),*d=descriptor(i);
        if(music_endpoint_owners[i] || s[0x12] || *(volatile uint32_t *)s ||
            *(volatile uint32_t *)(s+8) || *(volatile uint32_t *)d)continue;
        uint8_t prior_sep[32],prior_descriptor[12];
        for(uint32_t j=0;j<32u;j++){prior_sep[j]=s[j];s[j]=0;}
        for(uint32_t j=0;j<12u;j++){prior_descriptor[j]=d[j];d[j]=0;}
        *(volatile uint32_t *)s=callback;
        *(volatile uint16_t *)(s+12)=(uint16_t)mtu;
        s[14]=1;s[15]=255;
        *(volatile uint32_t *)d=(uint32_t)music_endpoint_sbc_caps;
        d[4]=4;d[8]=1;
        s[0x12]=1; /* Publish only after descriptor/handle are fully populated. */
        int result=music_gate_claim(i+1u,callback);
        if(result) {
            for(uint32_t j=0;j<32u;j++)s[j]=prior_sep[j];
            for(uint32_t j=0;j<12u;j++)d[j]=prior_descriptor[j];
            return done(-33);
        }
        music_endpoint_owners[i]=callback;
        return done((int)i+1);
    }
    return done(-32);
}
int music_endpoint_publish(uint32_t seid,uint32_t callback)
{
    if(!seid || seid>3u || !callback)return -30;
    if(lock()<0)return -31;
    uint32_t i=seid-1u;
    volatile uint8_t *s=sep(i),*d=descriptor(i);
    if(music_endpoint_owners[i]!=callback || *(volatile uint32_t *)s!=callback ||
        s[0x12]!=1u || s[0x13] || *(volatile uint32_t *)d!=(uint32_t)music_endpoint_sbc_caps ||
        d[4]!=4u || d[5] || d[6] || d[8]!=1u)return done(-34);
    if(music_endpoint_publication)return done(-36);
    volatile uint8_t *record=(volatile uint8_t *)(0x03a7c108u+7u*12u);
    if(*(volatile uint32_t *)record!=0x00090007u || *(volatile uint16_t *)(record+4))return done(-35);
    /* Do not nest native AVDTP and DB mutexes. Caller serializes publication
     * and owns this SDP record; there is no device scheduling/quiescence proof.
     */
    if(unlock()<0)return -38;
    int result=((sdp_operation)0x00607f9du)(0x00090007u);
    if(!result)music_endpoint_publication=1;
    else if(result==0x2504)music_endpoint_publication=2;
    return result;
}
uint32_t music_endpoint_publication_state(void){return music_endpoint_publication;}
int music_endpoint_capabilities(uint32_t context,uint32_t signal,uint32_t transaction,
    const uint8_t *p,uint32_t n)
{
    if(context>=2u || (signal!=2u && signal!=4u) || transaction>15u)return -30;
    volatile uint8_t *ctx=(volatile uint8_t *)(0x03a88eb8u+context*28u);
    uint32_t channel=ctx[0x13];if(channel>=12u)return -30;
    volatile uint8_t *ch=(volatile uint8_t *)(0x03a88f50u+channel*8u);
    if(*(volatile uint16_t *)ch<0x40u || ch[4] || ch[6]!=context || ch[5]!=0x10u)return -30;
    reply_handler reject=(reply_handler)0x005756adu;
    if(!p || !n || n>128u || (uintptr_t)p>UINT32_MAX-n)return reject(channel,transaction,signal,0,0x11);
    uint32_t seid=p[0]>>2;
    if(!seid || seid>3u)return reject(channel,transaction,signal,0,0x12);
    uint32_t i=seid-1u,owner=music_endpoint_owners[i];
    cap_handler stock=(cap_handler)0x005748e5u;
    if(!owner)return stock(context,signal,transaction,p,n);
    volatile uint8_t *s=sep(i),*d=descriptor(i);
    if(*(volatile uint32_t *)s!=owner || *(volatile uint32_t *)d!=(uint32_t)music_endpoint_sbc_caps ||
        d[4]!=4u || d[5] || d[6] || d[8]!=1u)return -40;
    if(n!=1u)return reject(channel,transaction,signal,0,0x11);
    if(p[0]&3u)return reject(channel,transaction,signal,0,1);
    if(!(s[0x12]&0x3fu))return reject(channel,transaction,signal,0,s[0x12]?0x31:0x12);
    if(signal==4u)return stock(context,signal,transaction,p,n);
    /* Stock GetCapabilities always supplies flags0x19. Clear HeaderCompression
     * bit8: this provider cannot accept category6 or decode compressed headers.
     * The original serializer still reads descriptor and builds the response.
     */
    int result=((cap_serializer)0x005a6929u)(transaction,signal,0x11,0,i,context);
    return result?reject(channel,transaction,signal,0,0x31):0;
}
