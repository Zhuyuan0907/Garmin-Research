#!/usr/bin/env python3
"""Bound native audio-page construction/action entry using runtime copy mappings.

Old 24-slot candidates stopped at the first conditional-code pointer. These
tables contain additional startup-backed pointers, including the actual audio
settings action at slot60. No runtime GUI registration or device patching.
"""
from datetime import datetime, timezone
import hashlib,json
from pathlib import Path

from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from analyze_sdp_activation import trace


def main():
    stock=NativeImage();image=RuntimeImage(stock)
    tables=[]
    for name,address,count,next_rtti in [('PageSettingsAudio',0xc0cc9c,66,0xbdfd30),
                                        ('PageAudioMixer',0xc06b24,57,0xbdf7d4)]:
        assert image.word(address-8)==0
        rtti=image.word(address-4)
        slots=[]
        for slot in range(count):
            pointer=image.word(address+slot*4)
            target=pointer&~1
            backing=next(c for c in stock.copies if c['runtime_start']<=target and target+2<=c['runtime_end'])
            assert backing['runtime_start']!=0xf00000,'Pointer is normal initialized data, not a code region'
            slots.append({'slot':slot,'pointer':hex(pointer),'mode':'Thumb' if pointer&1 else 'ARM',
                'load_address':hex(stock.runtime_to_load(target,2)),
                'requires_conditional_startup_copy':backing['conditional']})
        assert image.word(address+count*4)==0 and image.word(address+count*4+4)==next_rtti
        tables.append({'class':name,'address':hex(address),'rtti':hex(rtti),'slot_count':count,
            'slots':slots,'end_has_next_zero_offset_to_top_and_RTTI':True})
    assert tables[0]['slots'][60]['pointer']=='0x5193c9'
    starts=[0x518ec2,0x51914e,0x5193c8,0x53146c,0x531ce8,0x36c00a,0x36c10a,0x2e2c48]
    functions={hex(a):trace(image,a,3000) for a in starts}
    assert all(not f['instruction_limit_reached'] and not f['unresolved_exits'] for f in functions.values())
    def instruction(entry,address):
        return next(r for r in functions[hex(entry)]['instructions'] if r['address']==hex(address))
    assert instruction(0x53146c,0x53147c)['literal_value']=='0xc06b24'
    assert instruction(0x53146c,0x531480)['instruction']=='str r1, [r0]'
    assert instruction(0x5193c8,0x51941e)['literal_value']=='0x258c'
    assert instruction(0x5193c8,0x519428)['direct_call']=='0x53146c'
    assert instruction(0x5193c8,0x519436)['direct_call']=='0x36c00a'
    assert instruction(0x51914e,0x519180)['direct_call']=='0x53146c'
    assert instruction(0x518ec2,0x518eca)['string']=='STR_AUDIO_SETTINGS'
    assert instruction(0x518ec2,0x518f0e)['string']=='STR_AUDIO_MIXER'
    indirect_calls=[{'entry':entry,**r} for entry,f in functions.items() for r in f['instructions']
                    if r['instruction'].startswith('blx ') and 'direct_call' not in r]
    deps=[Path(__file__),ROOT/'scripts/analyze_native_sections.py',ROOT/'scripts/analyze_native_voice_acceptance.py',
          ROOT/'scripts/analyze_sdp_activation.py',ROOT/'evidence/firmware-analysis/main_02bd.bin']
    out={'updated_utc':datetime.now(timezone.utc).isoformat(),'stock_sha256':EXPECTED,
        'full_vtables':tables,'functions':functions,'bounded_function_count':len(functions),
        'indirect_callees_not_resolved':indirect_calls,
        'source_sha256':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in deps},
        'audio_settings_action':{'parent_class':'PageSettingsAudio','vtable_slot':60,'handler':'0x5193c8',
             'selector_zero_calls_stock_mixer_constructor':True,'allocator':'0x3954cc','allocation_bytes':0x258c,
             'constructor':'0x53146c','constructor_sets_vtable':'0xc06b24',
             'following_page_publication_call':'0x36c00a','third_argument':10,
             'selector_one_is_separate_dialog_branch':True,'other_selectors_return_without_new_page':True},
        'old_short_map_limitation':'Old ROM-only code-pointer filter stopped at slot24. Both tables include five conditional-copy code pointers and continue to57/66 slots. This is new extended evidence; old frozen candidate file is unchanged.',
        'new_App_or_generic_plugin_install_API_identified':False,
        'actual_UI_dispatch_or_screen_execution_verified':False,'live_conditional_copy_flag_verified':False,
        'device_io':False,'firmware_modified':False,'device_install_candidate':False,
        'limitations':'Static exact firmware only. Complete local branch CFGs are not complete callee semantics; indirect callbacks remain unresolved. Existing page action/constructor/publication call is not arbitrary App registration or file installation. Allocator/UI objects/lifetime/rendering were not executed on device; conditional-code startup flag remains unknown.'}
    p=ROOT/'evidence/firmware-analysis/native-music-ui-static.json'
    p.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'evidence':str(p.relative_to(ROOT)),'vtables':[t['slot_count'] for t in tables],
        'bounded_functions':len(functions),'device_io':False}))


if __name__=='__main__':main()
