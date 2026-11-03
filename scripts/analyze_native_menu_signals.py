#!/usr/bin/env python3
"""Bounded stock shared-signal construction/subscription paths; backup only."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from analyze_native_usb_transition import cfg
from analyze_native_loader import scan_calls

STAGE=ROOT/'staging/native-player-mainmenu-context'
GLOBALS=[0x3471b58+36*n for n in range(8)]

def main():
    stock=NativeImage();image=RuntimeImage(stock)
    ranges=[(0x4a388a,0x4a39f6),(0x4a3846,0x4a3854),
        (0x4419b8,0x441a6a),(0x36270c,0x362746),(0x362a2c,0x362aae),
        (0x441368,0x4413c4),(0x49d504,0x49d54e)]
    functions={hex(a):cfg(image,a,b)for a,b in ranges}
    for key,f in functions.items():assert not f['unresolved_exits'] and not f['instruction_limit_reached'],(key,f['unresolved_exits'])
    rows={int(r['address'],16):r for f in functions.values()for r in f['instructions']}
    assert rows[0x4a384a]['literal_value']=='0x3471c30'
    assert rows[0x4a384e]['direct_call']=='0x4419b8'
    assert rows[0x441a36]['instruction']=='ldr r0, [r0]'
    assert rows[0x441a4a]['direct_call']=='0x36294e'
    assert rows[0x4a3970]['direct_call']=='0x362a2c'
    source=Path(__file__).resolve()
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        source_sha256={str(source.relative_to(ROOT)):hashlib.sha256(source.read_bytes()).hexdigest()},
        complete_bounded_CFG_count=len(functions),functions=functions,
        original_initializer='0x4a388a',shared_signal_globals=[hex(p)for p in GLOBALS],
        original_subscription_wrapper='0x4a3846 ->0x4419b8 ->0x36294e',
        original_generic_signal_constructor='0x36270c',
        selected_global='0x3471c30',selected_shared_pointer_loaded_at='0x441a36',
        direct_call_scan=scan_calls(stock,{0x4a388a,0x4a3846}),
        no_general_MainMenu_or_device_execution=True,device_io=False,sounds_emitted=False,
        limits='Original bounded paths locate eight shared signals and the missing owner of the observed subscription. Their event meanings and actual boot initialization order are not recovered. No general-menu, callback delivery, audio, visible App, physical display or accepted package is established.')
    path=STAGE/'shared-signal-static-preflight.json';assert not path.exists(),'Use a new static namespace'
    path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(complete_CFGs=len(functions),globals=len(GLOBALS),output=str(path.relative_to(ROOT)))))

if __name__=='__main__':main()
