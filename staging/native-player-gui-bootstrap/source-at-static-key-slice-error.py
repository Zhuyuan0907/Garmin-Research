#!/usr/bin/env python3
"""Exact original mutex, scoped guard and dispatcher diagnostic bootstrap."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json
from analyze_native_sections import ROOT,NativeImage,EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from analyze_native_usb_transition import cfg

def main():
    image=RuntimeImage(NativeImage())
    ranges=[(0x5d2f7c,0x5d2f9e),(0x3103d8,0x3103ee),(0x3008a0,0x3008b0),
        (0x310400,0x31040c),(0x31040c,0x310418),(0x351bd0,0x351be2),(0x351be2,0x351bf2),
        (0x5d2130,0x5d215c),(0x3896f8,0x389724),(0x2c0a1e,0x2c0a38),(0x2c0e9a,0x2c0f2e)]
    functions={hex(a):cfg(image,a,b)for a,b in ranges}
    for entry,function in functions.items():
        assert not function['unresolved_exits']and not function['instruction_limit_reached'],entry
    rows={int(row['address'],16):row for function in functions.values()for row in function['instructions']}
    assert image.word(0x5d2530)==image.word(0x5d2ff8)==0x34a59a8
    assert rows[0x5d2f80]['direct_call']=='0x3103d8'
    assert rows[0x3103de]['instruction']=='str r0, [r4]'and image.word(0x310418)==0xc1b5dc
    assert image.word(0xc1b5dc+8)==0x310401 and image.word(0xc1b5dc+12)==0x31040d
    assert rows[0x351bda]['instruction']=='ldr r2, [r2, #8]'and rows[0x351bdc]['instruction']=='blx r2'
    assert rows[0x351bea]['instruction']=='ldr r1, [r1, #0xc]'and rows[0x351bec]['instruction']=='blx r1'
    assert rows[0x310404]['direct_call']=='0x3009a0'and rows[0x310410]['direct_call']=='0x3008b0'
    assert rows[0x5d214a]['direct_call']=='0x5d2232'and image.word(0x5d2538)==0x4ba8
    assert image.word(0x5d3004)==0x5d29df
    label=image.read(0x5d3008,40).split(b'\0')[0].decode('ascii')
    assert label=='Dispatcher::DispatcherTest::testDispatcher'
    source=Path(__file__).resolve();files=[source,ROOT/'scripts/analyze_native_sections.py',
        ROOT/'scripts/analyze_native_voice_acceptance.py',ROOT/'scripts/analyze_native_usb_transition.py',
        ROOT/'evidence/firmware-analysis/main_02bd.bin']
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in files},
        complete_bounded_CFG_count=len(functions),functions=functions,original_bootstrap='0x5d2f7c',
        missing_object_is_Cpp_mutex_not_tree_or_GUI_data_map=True,mutex_object='0x34a59a8',mutex_bytes=28,
        original_mutex_vtable='0xc1b5dc',original_mutex_constructor='0x3103d8',
        original_backend_initializer='0x3008a0',original_scoped_lock_guard='0x351bd0',original_scoped_unlock_guard='0x351be2',
        original_virtual_lock='0x310400',original_virtual_unlock='0x31040c',
        original_singleton_entry='0x5d2130',singleton_pointer_global='0xf11c8c',singleton_allocation_bytes=0x4ba8,
        singleton_constructor='0x5d2232',original_dtor_registration='0x3896f8',
        original_diagnostic_registry_getter='0x2c0a1e',original_diagnostic_registration='0x2c0e9a',
        diagnostic_callback='0x5d29df',diagnostic_key=label,
        real_boot_order_kernel_thread_ownership_dispatcher_event_delivery_or_safe_lifetime_verified=False,
        device_io=False,sounds_emitted=False,
        limits='Eleven bounded original functions; indirect lock/unlock slots verified against immutable vtable. Original bootstrap constructs mutex and registers destructor/dispatcher diagnostic, not proof of running diagnostic, real GUI thread or scheduler. Singleton constructor/callback bodies not recursively recovered here. Native runtime execution remains separate controls/development.')
    path=ROOT/'staging/native-player-gui-bootstrap/gui-runtime-bootstrap-static-preflight.json';path.parent.mkdir(exist_ok=True)
    assert not path.exists(),'Use a new proof namespace';path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(complete_CFGs=len(functions),missing_mutex='0x34a59a8',diagnostic_registration=label)))

if __name__=='__main__':main()
