#!/usr/bin/env python3
"""Generate exact prologues/ARM entry shims and three-mutex warm derivative."""
from pathlib import Path
import sys,json,hashlib
ROOT=Path(__file__).resolve().parents[2];BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
n=NativeImage()
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def create(p,d):
 with p.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
old=ROOT/'staging/native-player-warm-entry/mixer_source_warm_v1.c'
s=old.read_text()
start=s.index('    owner=mw_word(RECORD,0x1d0u);')
end=s.index('    r=mw_structural_check();',start)
replacement='''    owner=mw_word(RECORD,0x1d0u)|mw_word(RECORD,0x1e8u)|mw_word(RECORD,0x60u);
    if(!actor || owner){
        ((void (*)(uint32_t))0x21b6dcu)(flags);r=-302;goto denied;
    }
    /* Exact locks: profile/outer registration +1C8, direct list writer
     * +1E0, provider/source record +58. All checked free under IRQ exclusion.
     * No wait or lock-order contention is introduced by this acquisition. */
    ((void (*)(volatile void *))0x3009a1u)(RECORD+0x1c8u);
    ((void (*)(volatile void *))0x3009a1u)(RECORD+0x1e0u);
    ((void (*)(volatile void *))0x3009a1u)(RECORD+0x58u);
'''
s=s[:start]+replacement+s[end:]
s=s.replace('    r=mw_structural_check();\n    ((void (*)(uint32_t))0x21b6dcu)(flags);',
'''    r=mw_structural_check();
    extern int rg_claim_locked(uint32_t);
    extern void rg_validation_test_hook(void),rg_abandon_unpublished(void);
    if(!r)r=rg_claim_locked(actor);
    ((void (*)(uint32_t))0x21b6dcu)(flags);
    /* Hook absent unless the offline test task has been explicitly created. */
    if(!r)rg_validation_test_hook();''')
s=s.replace('    ((void (*)(volatile void *))0x3008b1u)(RECORD+0x1c8u);',
'''    if(r)rg_abandon_unpublished();
    ((void (*)(volatile void *))0x3008b1u)(RECORD+0x58u);
    ((void (*)(volatile void *))0x3008b1u)(RECORD+0x1e0u);
    ((void (*)(volatile void *))0x3008b1u)(RECORD+0x1c8u);''')
new=BASE/'mixer_source_route_v1.c'
with new.open('x')as f:f.write(s)
asm=['.syntax unified','.cpu arm1176jzf-s']
patches=[]
for name,address in [('profile',0x277d26),('queue',0x277c6a),('selector',0x2f9f2e),('prepare',0x4379d4),('allocate',0x48ee68)]:
 size=10 if address%4==2 else(16 if name=='prepare'else 12)
 # Preserve all four incoming register arguments. Patched Thumb pushes r3;
 # the ARM shim restores it and the incoming SP before tail-branching to C.
 asm+=['.section .text.rg_'+name+'_entry,"ax",%progbits','.arm','.global rg_'+name+'_entry','.type rg_'+name+'_entry,%function','rg_'+name+'_entry:','ldr r3, [sp], #4','b rg_'+name+'_gate',
 '.section .text.rg_stock_'+name+',"ax",%progbits','.thumb','.align 2','.global rg_stock_'+name,'.type rg_stock_'+name+',%function','.thumb_func','rg_stock_'+name+':']
 raw=n.read(address,size)
 if name in('profile','queue','selector'):
  assert all(i.mnemonic not in ('bl','b','beq','bne','ldr') or '[pc,'not in i.op_str for i in n.instructions(address,address+size))
  asm+=['.byte '+','.join(hex(x)for x in raw)]
 elif name=='prepare':
  assert raw.hex()=='ffb505001900f43081b0fff7c1fe2c00'
  asm+=['push {r0,r1,r2,r3,r4,r5,r6,r7,lr}','movs r5,r0','movs r1,r3','adds r0,#0xf4','sub sp,#4','ldr r3,3f','blx r3','movs r4,r5']
 else:
  assert raw.hex()=='30b404003248314a0021cb00'
  asm+=['push {r4,r5}','movs r4,r0','ldr r0,3f','ldr r2,4f','movs r1,#0','lsls r3,r1,#3']
 asm+=['push {r3}','ldr r3,1f','mov ip,r3','pop {r3}','bx ip','.align 2','1: .word '+hex(address+size+1)]
 if name=='prepare':asm+=['3: .word 0x437765']
 if name=='allocate':asm+=['3: .word 0xffff','4: .word 0x034e3cf4']
 patches.append(dict(name=name,address=address,patch_bytes=size,before_hex=raw.hex(),restore_r3_and_SP_in_ARM_shim=True,original_native_body_return_preserved=True))
ap=BASE/'route_original_entries_v1.S'
with ap.open('x')as f:f.write('\n'.join(asm)+'\n')
deps={str(p.relative_to(ROOT)):sha(p)for p in(Path(__file__),old,new,ap,ROOT/'scripts/analyze_native_sections.py',ROOT/'evidence/firmware-analysis/main_02bd.bin')}
create(BASE/'route-entry-derivation-v1.json',dict(all_passed=True,source_sha256=deps,patches=patches,VM_only=True,device_IO=False,durable_ownership=False))
print(json.dumps(dict(all_passed=True,patches=5,device_IO=False)))
