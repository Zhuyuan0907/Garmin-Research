/* LOCAL READONLY PLATFORM DIAGNOSTIC TEST INPUT ONLY. Original Big5 entry and original40 forwarded.
 * No allocation, file write, voice/audio call, host runtime or new exported API.
 * Fixed addresses target only Taiwan HWID1352/SW8.00 MAIN. */
typedef unsigned int u32; typedef unsigned short u16; typedef unsigned char u8;
extern u32 original_tts_entry(u32 *);
extern u8 __marker_bss_start[],__marker_bss_end[];
struct state { u32 magic_a,magic_b,requested,raw,attempts,saved_valid,why,index,handle,payload; u16 before[5]; u32 sample_mask,sample[12],hw_cpsr,hw_midr,hw_sctlr,hw_accepted,hw_tag; };
volatile struct state marker_state;
static const u16 id[20]={'m','e','i','-','l','i','n','g','b'};
typedef u32 (*one)(u32);
static u32 call(u32 fn,u32 arg){return ((one)fn)(arg);}
static u32 same(const u16*a,const u16*b,u32 max){u32 i;for(i=0;i<max;i++){u16 x=a[i],y=b[i];if(x!=y)return 0;if(!x)return 1;}return 0;}
static u32 original_version(const u16*v){return v[0]=='2'&&v[1]=='.'&&v[2]=='1'&&v[3]=='0'&&!v[4];}
static u32 hexunit(u16 x){return (x>='0'&&x<='9')||(x>='A'&&x<='F');}
static u32 marked_version(const u16*v){return (v[0]=='W'||v[0]=='U'||v[0]=='X'||hexunit(v[0]))&&hexunit(v[1])&&hexunit(v[2])&&hexunit(v[3])&&!v[4];}

/* The observation is made at voice-module initialization, NOT guaranteed
 * after all navigation/audio startup. Bits describe one IRQ-bounded sample;
 * idle/free-looking fields never certify native channel ownership or a
 * constructed semaphore. No pointer from these fields is dereferenced. */
static u16 digit(u32 x){return (u16)(x<10u?'0'+x:'A'+x-10u);}
/* Only normal privileged task modes read CP15. Other modes report skip.
 * These are ordinary MRS/MRC reads; no MSR/MCR, allocation, table access,
 * cache/TLB operation, audio function, file write or new task is performed.
 * Tag high nibble: bit0=System (rather than SVC), bit1=MMU enabled,
 * bit2=D-cache enabled, bit3=I-cache enabled. Low12=CPU part field.
 * Uxxx/Xxxx is a skipped read with low5 CPSR mode. Cached entry snapshot. */
__attribute__((used,noinline))
u32 platform_format_tag(u32 mode,u32 midr,u32 sctlr){
 u32 flags=(mode==0x1fu);
 if(sctlr&1u)flags|=2u;if(sctlr&4u)flags|=4u;if(sctlr&0x1000u)flags|=8u;
 return (flags<<12)|((midr>>4)&0xfffu);
}
__attribute__((used,noinline))
u32 sample_platform(void){
 u32 status,midr=0,control=0,mode,tag;
 __asm__ volatile("mrs %0, cpsr" : "=r"(status));mode=status&31u;
 marker_state.hw_cpsr=status;marker_state.hw_accepted=0;
 if(mode!=0x13u&&mode!=0x1fu){
  marker_state.hw_midr=0;marker_state.hw_sctlr=0;marker_state.hw_tag=mode;return mode;
 }
 __asm__ volatile("mrc p15, 0, %0, c0, c0, 0" : "=r"(midr));
 __asm__ volatile("mrc p15, 0, %0, c1, c0, 0" : "=r"(control));
 marker_state.hw_midr=midr;marker_state.hw_sctlr=control;marker_state.hw_accepted=1;
 tag=platform_format_tag(mode,midr,control);marker_state.hw_tag=tag;return tag;
}

__attribute__((section(".text.cache_marker_entry"),used))
u32 cache_marker_entry(u32*descriptor){
 u32 raw,i,region,slot,sm=0,file=0,fp=0,h,p,index,target=0,targetp=0,n=0,matches=0,driver=0;
 u32 list_held=0,slot_held=0,file_held=0; u16*v; u8*z;
 /* NOLOAD state survives a repeated same-image entry. Never dereference an
  * old handle/payload; rediscover the current unique native record each time. */
 if(marker_state.magic_a!=0x374d3941||marker_state.magic_b!=0xc8b2c6be){
  for(z=__marker_bss_start;z<__marker_bss_end;z++)*(volatile u8*)z=0;
  marker_state.magic_b=0xc8b2c6be;marker_state.magic_a=0x374d3941;
 }
 marker_state.requested=descriptor[0];marker_state.attempts++;marker_state.why=0;
 raw=original_tts_entry(descriptor);marker_state.raw=raw;
 if(raw!=11){marker_state.why=1;return raw;}
 if(*(u32*)0xf09094||!*(u32*)0xf09090){marker_state.why=2;return raw;}
 /* Stock nonblocking try primitive returns1 when it actually owns semaphore.
  * Skip the optional marker if another task owns any lock; no wait/wake. */
 if(!call(0x300935,0x344cf00)){marker_state.why=3;return raw;}list_held=1;
 index=call(0x273e53,(u32)id);
 if(index==0xffffffff){marker_state.why=4;goto done;}
 target=call(0x273a85,index);
 if(!target){marker_state.why=5;goto done;}
 targetp=call(0x388805,target);
 if(!targetp){marker_state.why=6;goto done;}
 h=*(u32*)0xf09668;
 while(h&&n<128){
  p=call(0x388805,h);if(!p){marker_state.why=7;goto done;}
  if(same((u16*)(p+0x3fc),id,20))matches++;
  h=*(u32*)(p+0x774);n++;
 }
 if(h||matches!=1){marker_state.why=8;goto done;}
 if(!same((u16*)(targetp+0x3fc),id,20)||*(u8*)(targetp+0x760)!=1||*(u32*)(targetp+0x764)!=0x0ca73f5a){marker_state.why=9;goto done;}
 region=*(u8*)0xf09660;slot=*(u8*)(0x105e424+2*region+1);
 if(!*(u8*)(0x105e424+2*region)||slot>=32){marker_state.why=10;goto done;}
 sm=0x105e624+36*slot+4;
 if(!call(0x300935,sm)){marker_state.why=11;goto done;}slot_held=1;
 if(!*(u8*)(0x105e424+2*region)||*(u8*)(0x105e424+2*region+1)!=slot){marker_state.why=12;goto done;}
 file=call(0x2d30af,region);
 if(!file||file!=*(u32*)(sm+24)||(file&3)){marker_state.why=13;goto done;}
 if(!call(0x300935,file+32)){marker_state.why=14;goto done;}file_held=1;
 if(!*(u8*)file||!*(u32*)(file+12)||!*(u32*)(file+4)){marker_state.why=15;goto done;}
 fp=call(0x388805,*(u32*)(file+4));
 if(!fp){marker_state.why=16;goto done;}
 /* Mirror 1FDB8E's path composition without its unchecked allocation:
  * provider+44 supplies driver descriptor; descriptor byte1 yields N:.
  * Refuse multidigit drivers, and compare only a bounded original pathname. */
 driver=*(u32*)(*(u32*)(file+12)+44);
 if(driver){
  i=*(u8*)(driver+1);
  if(i>=10||*(u16*)targetp!=(u16)('0'+i)||*(u16*)(targetp+2)!=':'||!same((u16*)fp,(u16*)(targetp+4),253)){marker_state.why=16;goto done;}
 }else if(!same((u16*)fp,(u16*)targetp,255)){marker_state.why=16;goto done;}
 v=(u16*)(targetp+0x6b8);
 if(marked_version(v)){marker_state.why=marker_state.saved_valid?17:18;goto done;}
 if(!original_version(v)){marker_state.why=19;goto done;}
 if(!marker_state.saved_valid){for(i=0;i<5;i++)marker_state.before[i]=v[i];marker_state.saved_valid=1;}
 if(!original_version((const u16*)marker_state.before)){marker_state.why=20;goto done;}
 marker_state.index=index;marker_state.handle=target;marker_state.payload=targetp;
 i=sample_platform();
 *(volatile u16*)(targetp+0x6b8)=marker_state.hw_accepted?digit((i>>12)&15u):((marker_state.hw_cpsr&31u)==0x10u?'U':'X');*(volatile u16*)(targetp+0x6ba)=digit((i>>8)&15u);
 *(volatile u16*)(targetp+0x6bc)=digit((i>>4)&15u);*(volatile u16*)(targetp+0x6be)=digit(i&15u);
 *(volatile u16*)(targetp+0x6c0)=0;
done:
 if(file_held)call(0x3008b1,file+32);
 if(slot_held)call(0x3008b1,sm);
 if(list_held)call(0x3008b1,0x344cf00);
 return raw;
}
