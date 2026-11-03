/* Exact HWID1352/8.00 private ABI, offline prototype. Native AVDTP command
 * dispatcher owns its mutex at both gates and at the reply helper. This
 * serialized contract is not a recovered installer or a proven live lock
 * hierarchy. Module/callback/descriptor remain pinned; no unload is offered.
 */
#include <stdint.h>
#include "remote_binding_v1.h"
#include "../../native/avdtp-gate/gate.h"
typedef int32_t (*reply_fn)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t);
typedef int32_t (*command_fn)(uint32_t,uint32_t,uint32_t,const uint8_t *,uint32_t);
typedef int32_t (*send_fn)(uint32_t,uint32_t,uint8_t *,uint16_t *);
extern int32_t stock_reply_relocated(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t);
extern volatile uint32_t music_endpoint_owners[3];
struct native_reply_scope {
    uint32_t active,channel,transaction,signal,generation;
    uint32_t attempts,queued,short_writes,scope_errors,start_rejected;
    uint32_t last_expected,last_written;
    int32_t last_send_result;
};
volatile struct native_reply_scope nr_scope;
static volatile uint8_t *sep(uint32_t i){return (volatile uint8_t *)(0x03a88ef0u+i*32u);}
static volatile uint8_t *ch(uint32_t i){return (volatile uint8_t *)(0x03a88f50u+i*8u);}

/* All nonselected replies keep the original exact relocated prologue/body.
 * The selected acceptance is only the two-byte standard response, and uses
 * original L2CAP TX allocation/copy/queue. A zero return alone is insufficient:
 * outer receive can return0 despite native send failure and no queued record.
 */
int32_t nr_reply_dispatch(uint32_t channel,uint32_t transaction,uint32_t signal,
                           uint32_t category,uint32_t error)
{
    if(!nr_scope.active || channel!=nr_scope.channel || transaction!=nr_scope.transaction ||
       signal!=nr_scope.signal || error || (signal!=3u && signal!=7u && signal!=9u))
        return stock_reply_relocated(channel,transaction,signal,category,error);
    if(channel>=12u || transaction>15u)return 0x2930;
    uint8_t packet[6]={0,0,0,0,(uint8_t)((transaction<<4)|2u),(uint8_t)signal};
    uint16_t written=0;
    nr_scope.attempts++;nr_scope.last_expected=2;
    int32_t result=((send_fn)0x005a7795u)(*(volatile uint16_t *)ch(channel),6u,packet,&written);
    nr_scope.last_written=written;nr_scope.last_send_result=result;
    if(result || written!=2u){nr_scope.short_writes++;return result?result:0x2930;}
    nr_scope.queued++;nsg_reply_witness(signal,nr_scope.generation);return 0;
}

static int selected(uint32_t seid)
{
    if(!seid || seid>3u)return 0;
    uint32_t owner=music_endpoint_owners[seid-1u];
    return owner && *(volatile uint32_t *)sep(seid-1u)==owner;
}
static int32_t rejection(uint32_t channel,uint32_t tx,uint32_t signal,uint32_t category,uint32_t error)
{return ((reply_fn)0x005756adu)(channel,tx,signal,category,error);}

/* A scope associates the nested acceptance reply with the real native command
 * channel/transaction/signal. No Python per-message setter is used. Scope IDs
 * never wrap; these IDs are NOT remote stream/session generations or admission
 * certificates. Config validation still belongs to the frozen SBC gate.
 */
static int enter(uint32_t context,uint32_t tx,uint32_t signal)
{
    if(nr_scope.active || nr_scope.generation==UINT32_MAX || context>=2u || tx>15u){
        nr_scope.scope_errors++;return -70;
    }
    volatile uint8_t *ctx=(volatile uint8_t *)(0x03a88eb8u+context*28u);
    uint32_t channel=ctx[0x13];if(channel>=12u)return -70;
    volatile uint8_t *c=ch(channel);
    if(*(volatile uint16_t *)c<0x40u || c[4] || c[5]!=0x10u || c[6]!=context)return -70;
    nr_scope.channel=channel;nr_scope.transaction=tx;nr_scope.signal=signal;
    nr_scope.generation++;nr_scope.active=1;return 0;
}
int32_t nr_configuration_gate(uint32_t context,uint32_t signal,uint32_t tx,
                              const uint8_t *body,uint32_t length)
{
    if(signal!=3u && signal!=5u)return -70;
    if(!body || !length || length>128u || (uintptr_t)body>UINT32_MAX-length || !selected(body[0]>>2))
        return music_configuration_gate(context,signal,tx,body,length);
    int32_t result=enter(context,tx,signal);if(result)return result;
    if(signal==3u && nsg_config_begin(context,tx,body,length,nr_scope.generation)){
        nr_scope.active=0;return rejection(nr_scope.channel,tx,signal,0,0x31u);
    }
    result=music_configuration_gate(context,signal,tx,body,length);
    if(signal==3u)nsg_config_end(result);
    nr_scope.active=0;return result;
}
int32_t nr_start_suspend_gate(uint32_t context,uint32_t signal,uint32_t tx,
                              const uint8_t *body,uint32_t length)
{
    if(signal!=7u && signal!=9u)return -70;
    command_fn original=(command_fn)0x005752cdu;
    if(context>=2u || tx>15u)return -70;
    volatile uint8_t *ctx=(volatile uint8_t *)(0x03a88eb8u+context*28u);
    uint32_t envelope_channel=ctx[0x13];
    if(envelope_channel>=12u)return -70;
    if(!body || !length || length>128u || (uintptr_t)body>UINT32_MAX-length)
        return rejection(envelope_channel,tx,signal,0,0x11u);
    uint32_t owned=0;
    for(uint32_t i=0;i<length;i++)if(selected(body[i]>>2))owned=1;
    if(!owned)return original(context,signal,tx,body,length);
    int32_t result=enter(context,tx,signal);if(result)return result;
    uint32_t channel=nr_scope.channel;
    if(length!=1u || (body[0]&3u)){
        nr_scope.start_rejected++;nr_scope.active=0;
        return rejection(channel,tx,signal,body[0],0x12u);
    }
    uint32_t seid=body[0]>>2;
    volatile uint8_t *s=sep(seid-1u);
    /* Do not let original reject-send-success fall through and set state8.
     * This module only owns one endpoint per request. Other endpoint requests
     * go unchanged to stock. It does not grant media admission by state8.
     */
    if(s[0x13] || s[0x12]!=(signal==7u?4u:8u) || s[0x11]!=context){
        nr_scope.start_rejected++;nr_scope.active=0;
        return rejection(channel,tx,signal,body[0],0x31u);
    }
    if(nsg_start_begin(context,seid,signal,nr_scope.generation)){
        nr_scope.start_rejected++;nr_scope.active=0;
        return rejection(channel,tx,signal,body[0],0x31u);
    }
    result=original(context,signal,tx,body,length);
    if(signal==7u)nsg_start_end(result);
    nr_scope.active=0;return result;
}
