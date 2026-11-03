#!/usr/bin/env python3
"""Prepare warm attach derivative. No guest, device, or ownership claim."""
from pathlib import Path
import hashlib,json
BASE=Path(__file__).resolve().parent
ROOT=BASE.parents[1]
old=ROOT/'staging/native-player-remote-pause/mixer_source_pause_v1.c'
text=old.read_text()
start=text.index('static int initialize_stage1(void)')
end=text.index('static int start_first_external_packet',start)
replacement=r'''
/* Structural admission, NOT a durable native channel ownership witness.
 * Acquire the original channel's profile mutex without waiting: IRQ masking
 * protects the free-owner test and native acquisition from another task.
 * No native condition, queue, channel or profile is reset/constructed here.
 * Other native direct queue/provider callers remain outside this boundary. */
volatile uint32_t mw_attempts,mw_attaches,mw_denials,mw_last_reason;
static uint32_t mw_word(const volatile uint8_t *p,uint32_t offset)
{ return *(const volatile uint32_t *)(p+offset); }
static int mw_structural_check(void)
{
    uint32_t timer=*(volatile uint32_t *)0x00f090a0u;
    if(!timer || mw_word(RECORD,0x88u)!=0xd4475b83u ||
       mw_word(RECORD,0x78u)!=timer)return -303;
    if(RECORD[0]!=8u || RECORD[0x1f8u]!=8u || RECORD[0x1a8u]!=8u)return -304;
    if(RECORD[0x15du]!=0u || mw_word(RECORD,0x160u)!=0x277c6bu)return -305;
    if(mw_word(RECORD,0x1acu)!=0xffffu ||
       *(volatile uint16_t *)(RECORD+0x1c0u) ||
       *(volatile uint32_t *)(0x034e68d8u+8u*4u))return -306;
    if(MIXER[0x84u])return -307;
    if(RECORD[2])return -308;
    for(uint32_t i=0;i<68u;i++)if(RECORD[0xf4u+i])return -308;
    if(*(volatile uint8_t *)(0x034e9398u+8u)!=1u)return -309;
    return 0;
}
int mw_attach_stage1(void)
{
    uint32_t flags,actor,owner;int r;
    mw_attempts++;
    /* Existing context check only covers normal task context, not ownership. */
    extern int mcs_native_normal_context(void *);
    if(!mcs_native_normal_context(0)){r=-301;goto denied;}
    actor=((uint32_t (*)(void))0x358d25u)();
    flags=((uint32_t (*)(void))0x21b6ccu)();
    owner=mw_word(RECORD,0x1d0u);
    if(!actor || owner){
        ((void (*)(uint32_t))0x21b6dcu)(flags);r=-302;goto denied;
    }
    /* Original mutex is now known free in this IRQ-bounded interval. */
    ((void (*)(volatile void *))0x3009a1u)(RECORD+0x1c8u);
    if(mw_word(RECORD,0x1d0u)!=actor){
        ((void (*)(uint32_t))0x21b6dcu)(flags);r=-302;goto denied;
    }
    r=mw_structural_check();
    ((void (*)(uint32_t))0x21b6dcu)(flags);
    if(!r)r=aas_initialize((uint32_t)(uintptr_t)RECORD,(uint32_t)(uintptr_t)POOL);
    ((void (*)(volatile void *))0x3008b1u)(RECORD+0x1c8u);
    if(r)goto denied;
    mw_attaches++;mw_last_reason=0;return 0;
denied:
    mw_denials++;mw_last_reason=(uint32_t)r;return r;
}
static int initialize_stage1(void)
{ return mw_attach_stage1(); }
'''
text=text[:start]+replacement+text[end:]
text=text.replace(' * The cold channel setup and allocator/hardware boundaries remain explicit\n * offline contracts; warm-system readiness and SEP publication are separate.',
' * Native preexisting-channel structural admission replaces global cold reset.\n * Durable ownership and actual live navigation readiness remain unproven.')
path=BASE/'mixer_source_warm_v1.c'
with path.open('x')as f:f.write(text)
with (BASE/'warm-source-derivation-v1.json').open('x')as f:
 json.dump(dict(original_path=str(old.relative_to(ROOT)),original_sha256=hashlib.sha256(old.read_bytes()).hexdigest(),new_path=str(path.relative_to(ROOT)),new_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),preparer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),guest_executed=False,device_IO=False,durable_ownership=False),f,indent=2)
print('Prepared warm-only Source derivative')
