#!/usr/bin/env python3
"""Prepare a bounded RAM-only audio-state diagnostic from accepted voice code.
No device write, guest execution, new audio API or native state mutation.
"""
import sys,hashlib,json,ast
from pathlib import Path
from datetime import datetime,timezone
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2]
BASE=Path(__file__).resolve().parent
OLD=ROOT/'staging/native-player-inline-fields/marker-package-prep'
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
from capstone.arm import ARM_OP_MEM,ARM_REG_PC
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def create(p,d):
    with p.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
def main():
    n=NativeImage();functions=[]
    for name,a,b in [('all_channel_reset',0x277e20,0x277e4c),('record_reset',0x269f1c,0x269f6c),('channel_table_initialize',0x269f6c,0x26a016),('profile_replace',0x277d26,0x277e20),('mutex_constructor',0x3008a0,0x3008b0)]:
        rows=[]
        for i in n.instructions(a,b):
            r=dict(PC=i.address,opcode=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str)
            for op in i.operands:
                if op.type==ARM_OP_MEM and op.mem.base==ARM_REG_PC:
                    p=((i.address+4)&~3)+op.mem.disp;r.update(literal=p,value=n.word(p))
            rows.append(r)
        functions.append(dict(name=name,start=a,end=b,rows=rows,kind='bounded exact original instruction interval; not full CFG/execution'))
    table=n.read(0xacb12c,18*28);mapping=[table[28*i]for i in range(18)]
    assert sorted(mapping)==list(range(18))and mapping.index(8)==8
    assert n.word(0x277e74)==0x034e68d8 and n.word(0x277ee4)==0x034e6920
    assert n.word(0x26a0f8)==0x034e6f08 and n.word(0x26a0fc)==0xacb12c
    assert n.word(0x277e9c)==0x277c6b
    zero=next(r for r in n.zeros if r['runtime_start']<=0x034e3cf4 and 0x034e7f48+0x208<=r['runtime_end'])
    old=OLD/'strict_cache_marker_entry.c';source=old.read_text()
    source=source.replace('u16 before[5]; };','u16 before[5]; u32 sample_mask,sample[12]; };')
    marked="static u32 marked_version(const u16*v){return v[0]=='M'&&v[1]=='7'&&v[2]=='Q'&&v[3]=='9'&&!v[4];}"
    changed="static u32 hexunit(u16 x){return (x>='0'&&x<='9')||(x>='A'&&x<='F');}\nstatic u32 marked_version(const u16*v){return v[0]=='W'&&hexunit(v[1])&&hexunit(v[2])&&hexunit(v[3])&&!v[4];}"
    assert source.count(marked)==1;source=source.replace(marked,changed)
    function=r'''
/* The observation is made at voice-module initialization, NOT guaranteed
 * after all navigation/audio startup. Bits describe one IRQ-bounded sample;
 * idle/free-looking fields never certify native channel ownership or a
 * constructed semaphore. No pointer from these fields is dereferenced. */
static u16 digit(u32 x){return (u16)(x<10u?'0'+x:'A'+x-10u);}
static u32 sample_audio(void){
 volatile u8*r=(volatile u8*)0x034e7f48u;
 volatile u8*m=(volatile u8*)(0x034e5378u+8u*0x130u);
 volatile u8*p=(volatile u8*)0x034e3cf4u;
 u32 saved=call(0x21b6cc,0),mask=0,i,clear=1,free=0;
 u32 a[12];
 a[0]=*(volatile u32*)(r+0x88u);a[1]=r[0x1f8u];
 a[2]=*(volatile u32*)(r+0x160u);a[3]=r[0x15du];
 a[4]=*(volatile u32*)(r+0x1acu);a[5]=*(volatile u16*)(r+0x1c0u);
 a[6]=r[2];
 for(i=0;i<68u;i++)if(r[0xf4u+i])clear=0;a[7]=clear;
 a[8]=*(volatile u32*)(0x034e68d8u+8u*4u);a[9]=m[0x84u];
 for(i=0;i<5u;i++)if(!p[576u*i+12u])free++;a[10]=free;
 a[11]=r[0x1a8u];
 call(0x21b6dc,saved);
 if(a[0]==0xd4475b83u)mask|=1u;if(a[1]==8u)mask|=2u;
 if(a[2]==0x277c6bu)mask|=4u;if(a[3]==0u)mask|=8u;
 if(a[4]==0xffffu)mask|=16u;if(!a[5])mask|=32u;
 if(!a[6])mask|=64u;if(a[7])mask|=128u;
 if(!a[8])mask|=256u;if(!a[9])mask|=512u;
 if(a[10])mask|=1024u;if(a[11]==8u)mask|=2048u;
 for(i=0;i<12u;i++)marker_state.sample[i]=a[i];
 marker_state.sample_mask=mask;return mask;
}
'''
    entry='__attribute__((section(".text.cache_marker_entry"),used))';assert source.count(entry)==1
    source=source.replace(entry,function+'\n'+entry)
    writer=""" *(volatile u16*)(targetp+0x6b8)='M';*(volatile u16*)(targetp+0x6ba)='7';
 *(volatile u16*)(targetp+0x6bc)='Q';*(volatile u16*)(targetp+0x6be)='9';
 *(volatile u16*)(targetp+0x6c0)=0;"""
    replacement=""" i=sample_audio();
 *(volatile u16*)(targetp+0x6b8)='W';*(volatile u16*)(targetp+0x6ba)=digit((i>>8)&15u);
 *(volatile u16*)(targetp+0x6bc)=digit((i>>4)&15u);*(volatile u16*)(targetp+0x6be)=digit(i&15u);
 *(volatile u16*)(targetp+0x6c0)=0;"""
    assert source.count(writer)==1;source=source.replace(writer,replacement)
    path=BASE/'warm_cache_marker_entry_v1.c'
    with path.open('x')as f:f.write(source)
    oldbuild=OLD/'build_strict_marker.py';build=oldbuild.read_text().replace('strict_cache_marker_entry.c','warm_cache_marker_entry_v1.c')
    build=build.replace("d.mkdir(exist_ok=True)","d.mkdir(exist_ok=False)")
    build=build.replace('Build only local EMULATION-ONLY raw images; never VPM/SIG/installers.','Build local warm diagnostic raw image; no device action.')
    ast.parse(build)
    builder=BASE/'build_warm_probe_v1.py'
    with builder.open('x')as f:f.write(build)
    meaning=['condition+0x18 has original magic','record+0x1F8 identifies channel8','profile queue callback is stock277C6B','profile byte+0x15D is0','list head field+4 isFFFF','node count is0','provider prepared byte is0','68 provider methods are0','global channel8 source head is0','mixer active byte is0','at least one provider busy byte is0','native mapping byte identifies channel8']
    contract=dict(all_passed=True,kind='exact original static contract and prepared diagnostic source; not a warm playback or App result',
        MAIN_sha256=sha(ROOT/'evidence/firmware-analysis/main_02bd.bin'),functions=functions,original_mapping_hex=table.hex(),channel_mapping=mapping,
        native_RAM_zero_range=zero,display_encoding='W followed by three uppercase hex digits; 12 observation bits, not a readiness/ownership certificate',bit_meaning={str(i):v for i,v in enumerate(meaning)},
        voice_initialization_timing='Only this module entry snapshot; may precede full native audio startup. Aud Ver displays a cached result, not a live monitor.',
        sample_reads_native_audio_only=True,no_audio_write_or_profile_reset=True,no_new_allocation_or_file_io=True,
        retained_original_entry40_APIs_and_raw11_guard=True,original_metadata_locks_and_identity_guards_retained=True,
        guarded_writes='Private appended BSS plus five UTF16 version writes to uniquely identified original cached MeiLing record; original loader/voice runtime writes still occur.',
        source_sha256={str(p.relative_to(ROOT)):sha(p)for p in (Path(__file__),old,oldbuild,path,builder,ROOT/'scripts/analyze_native_sections.py')},
        guest_executed=False,device_IO=False,native_channel_exclusive_or_full_warm_boot_or_phone_App_verified=False,updated_utc=datetime.now(timezone.utc).isoformat())
    create(BASE/'warm-audio-static-and-diagnostic-source-contract-v1.json',contract)
    print(json.dumps(dict(all_passed=True,source_sha256=sha(path),mapping=mapping,prepared=True,guest_executed=False,device_IO=False)))
if __name__=='__main__':main()
