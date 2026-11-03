#!/usr/bin/env python3
"""Focused original ResourceRef ownership/hash/resolve controls; backup only.

Uses unchanged stock GIR and an explicit read-only guest mapping. No GUI paint,
loader/root/device acceptance or native installation is established here.
"""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
import unicorn
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from emulate_native_player_external_fonts import BUILD
from probe_native_player_resources import ResourceVM,GIR,INPUT,STAGE
from emulate_native_vpm_filesystem import require

def hash_name(raw):
    value=0xffffffff
    for byte in raw:
        value=((value<<4)+byte)&0xffffffff;high=value&0xf0000000
        if high:value=(value^(high>>24))&~high
    return value&0x7fffffff

def main():
    require(unicorn.__version__=='2.1.4','Use isolated Unicorn2.1.4')
    vm=ResourceVM(NativeImage(),json.loads((ROOT/BUILD).read_text()));vm.invoke(0x395981,())
    registration=vm.register_stock_GIR();cases=[];ref=INPUT+0x100;copy=INPUT+0x110;out=INPUT+0x200;name=INPUT+0x400
    preflight=json.loads((STAGE/'resource-ABI-and-MainMenu-preflight.json').read_text())
    tokens={int(r['hash'],16)for r in preflight['appended_GIR']['entries']}
    hashes=[]
    for raw in [b'PI_PLAYER_UNKNOWN_RESOURCE_1352',b'BOOT_SPLASHSCREEN',b'']:
        vm.uc.mem_write(name,raw+b'\0');actual=vm.invoke(0x1c853b,(0xffffffff,name))
        require(actual==hash_name(raw),'Independent hash differs from original')
        hashes.append(dict(ASCII=raw.decode(),native_hash=hex(actual),in_stock_image_catalog=actual in tokens))
    cases.append(dict(name='original_hash_matches_independent32bit_instructions',passed=True,queries=hashes))
    raw=b'PI_PLAYER_UNKNOWN_RESOURCE_1352';require(hash_name(raw)not in tokens,'Unknown control accidentally names stock resource')
    vm.uc.mem_write(name,raw+b'\0');vm.invoke(0x3894b5,(ref,name))
    owned=vm.word(ref+4);require(vm.word(ref)==0 and owned and vm.ascii(owned)==raw.decode(),'Name constructor did not own a copy')
    vm.invoke(0x389531,(copy,ref));second=vm.word(copy+4)
    require(vm.word(copy)==0 and second!=owned and vm.ascii(second)==raw.decode(),'Copy did not duplicate owned name')
    vm.invoke(0x3894f1,(copy,copy));require(vm.word(copy+4)==second and not vm.raw_allocations[second]['freed'],'Self assignment changed ownership')
    vm.invoke(0x389545,(ref,));vm.invoke(0x389545,(copy,))
    require(vm.raw_allocations[owned]['freed'] and vm.raw_allocations[second]['freed'],'Original destructors did not free names')
    require(bytes(vm.uc.mem_read(name,len(raw)+1))==raw+b'\0','Original caller name buffer changed')
    cases.append(dict(name='missing_name_constructor_deep_copy_self_assignment_and_native_destruction',passed=True,
        input_name_borrowed=False,distinct_owned_allocations=[hex(owned),hex(second)],both_names_freed=True,
        callback_module_or_font_unload_not_tested=True))
    vm.invoke(0x3894ad,(ref,0x8a56eac));vm.invoke(0x389531,(copy,ref))
    require(vm.word(copy)==0x8a56eac and vm.word(copy+4)==0,'Hash reference copied as a string pointer')
    vm.invoke(0x389545,(copy,));require(not vm.raw_allocations.get(0x8a56eac),'Numeric resource token was allocated/freed')
    variants=[];expected=preflight['appended_GIR']['original_MainMenu_selected_hash']['variants']
    for variant in [0,1]:
        vm.uc.mem_write(out,b'\xcc'*128)
        accepted=vm.invoke(0x41c3db,(0,0x8a56eac,variant,out));words=struct.unpack('<21I',vm.uc.mem_read(out,84))
        require(accepted==1 and words[0]==0x8a56eac and list(words[1:16])==expected[variant]['metadata_words'] and
            words[18:20]==(64,64) and words[20]==int(expected[variant]['locator'],16),'Resolved stock variant descriptor differs')
        require(bytes(vm.uc.mem_read(out+84,44))==b'\xcc'*44,'Resolver wrote beyond84-byte output')
        variants.append(dict(variant=variant,descriptor_words=[hex(x)for x in words],tail_unchanged=True))
    cases.append(dict(name='original_hash_only_resource_copy_and_both_native84byte_variants',passed=True,variants=variants))
    controls=[]
    for token in [0,0x01234567]:
        require(token not in tokens,'Missing hash control exists in stock catalog')
        vm.invoke(0x3894ad,(ref,token));vm.uc.mem_write(out,b'\xcc'*128)
        accepted=vm.invoke(0x3895c3,(ref,out))
        require(accepted==0 and bytes(vm.uc.mem_read(out,128))==b'\xcc'*128,'Missing resource changed output or reported success')
        controls.append(dict(hash=hex(token),returned=accepted,descriptor_unchanged=True))
    cases.append(dict(name='empty_and_missing_numeric_resource_refs_do_not_invent_images',passed=True,controls=controls))
    for pointer,entry in vm.raw_allocations.items():vm.verify_guard(pointer,entry)
    require(bytes(vm.uc.mem_read(GIR,len(vm.resource_bytes)))==vm.resource_bytes,'Readonly stock GIR mutated')
    for region in vm.stock.copies:
        if region['runtime_start'] in [0x50000,0x04400000]:
            require(bytes(vm.uc.mem_read(region['runtime_start'],region['size']))==vm.stock.read(region['load_start'],region['size']),
                'Stock executable region mutated')
    paths={Path(__file__).resolve(),ROOT/'scripts/probe_native_player_resources.py',STAGE/'resource-ABI-and-MainMenu-preflight.json',ROOT/'evidence/firmware-analysis/main_02bd.bin'}
    for mod in tuple(sys.modules.values()):
        name=getattr(mod,'__file__',None)
        if name:
            p=Path(name).resolve()
            if p.is_file()and p.is_relative_to(ROOT/'scripts'):paths.add(p)
    proof=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,case_count=len(cases),cases=cases,
        all_passed=True,original_registration=registration,resource_calls=vm.resource_calls,
        source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(paths)},
        all_raw_allocation_canaries_intact=True,readonly_GIR_unchanged=True,stock_executable_regions_unchanged=True,
        device_io=False,sounds_emitted=False,full_player_rendering_integration_checkpoint=False,
        limits='Focused original resource instructions with explicit stock GIR placement, heap/kernel/driver inventories. No actual boot/root/display/App, modified package acceptance, direct phone music or module/font-cache safe unload claim.')
    target=ROOT/'evidence/firmware-analysis/native-resource-reference-ABI-emulation.json';target.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(groups=len(cases),source_count=len(paths),all_passed=True,evidence=str(target.relative_to(ROOT)))))

if __name__=='__main__':main()
