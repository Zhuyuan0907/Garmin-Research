/* EMULATION ONLY: original Big5 bootstrap, private state, RAM cache marker.
 * No replacement exports, sound, filesystem writes or installable package. */
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
extern u32 original_tts_entry(u32 *descriptor);
extern u8 __marker_bss_start[], __marker_bss_end[];
#ifndef CONTROL
#define CONTROL 0
#endif
struct state { u32 requested, boot_raw, marked, index, handle, payload, why; u16 before[5]; };
volatile struct state marker_state;
static const u16 identity[20] = {
#if CONTROL == 3
 'x','e','i','-','l','i','n','g','b'
#else
 'm','e','i','-','l','i','n','g','b'
#endif
};
typedef u32 (*one)(u32);
static u32 call1(u32 address, u32 arg) { return ((one)address)(arg); }
__attribute__((section(".text.cache_marker_entry"),used))
u32 cache_marker_entry(u32 *descriptor) {
 u8 *z; u32 raw,i,idx,h,p; u32 shadow[13]; u32 *input=descriptor;
 for(z=__marker_bss_start;z<__marker_bss_end;z++) *(volatile u8*)z=0;
 marker_state.requested=descriptor[0];
#if CONTROL == 1 || CONTROL == 2
 for(i=0;i<13;i++) shadow[i]=descriptor[i];
#if CONTROL == 1
 shadow[0]=0x50001;
#else
 shadow[0]=(descriptor[0]==0x50000)?0x60000:0x50001;
#endif
 input=shadow;
#endif
 raw=original_tts_entry(input); marker_state.boot_raw=raw;
 /* Keep every real raw result. Mark only a real 11, never native 6 or 5. */
 if(raw!=11) { marker_state.why=1; return raw; }
 call1(0x3009a1,0x344cf00);
 idx=call1(0x273e53,(u32)identity); marker_state.index=idx;
 if(idx==0xffffffff) { marker_state.why=2; goto done; }
 h=call1(0x273a85,idx); marker_state.handle=h;
 if(!h) { marker_state.why=3; goto done; }
 p=call1(0x388805,h); marker_state.payload=p;
 if(!p || *(u8*)(p+0x760)!=1 || *(u32*)(p+0x764)!=0x0ca73f5a) { marker_state.why=4; goto done; }
 for(i=0;i<20;i++) if(*(u16*)(p+0x3fc+2*i)!=identity[i]) { marker_state.why=5; goto done; }
 for(i=0;i<5;i++) marker_state.before[i]=*(u16*)(p+0x6b8+2*i);
 if(marker_state.before[0]!='2'||marker_state.before[1]!='.'||marker_state.before[2]!='1'||marker_state.before[3]!='0'||marker_state.before[4]!=0) { marker_state.why=6; goto done; }
 /* Exactly four characters and the fifth terminating UTF16 NUL. */
 *(volatile u16*)(p+0x6b8)='M'; *(volatile u16*)(p+0x6ba)='7';
 *(volatile u16*)(p+0x6bc)='Q'; *(volatile u16*)(p+0x6be)='9';
 *(volatile u16*)(p+0x6c0)=0;
 marker_state.marked=1;
done: call1(0x3008b1,0x344cf00); return raw;
}
