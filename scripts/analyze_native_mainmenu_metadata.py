#!/usr/bin/env python3
"""Consumer default reads and original bank lookup/dispatcher bounded CFGs."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from analyze_native_usb_transition import cfg

STAGE=ROOT/'staging/native-player-mainmenu-metadata'

def main():
    im=RuntimeImage(NativeImage())
    ranges=[(0x35d430,0x35d568),(0x2363b0,0x2363e4),(0x26a240,0x26a288),
        (0x26a300,0x26a336),(0x35d568,0x35d5d8),(0x35d5d8,0x35d614),(0x35d614,0x35d630)]
    functions={hex(a):cfg(im,a,b)for a,b in ranges}
    assert all(not f['unresolved_exits']and not f['instruction_limit_reached']for f in functions.values())
    rows={int(r['address'],16):r for f in functions.values()for r in f['instructions']}
    assert rows[0x26a30e]['direct_call']=='0x26a240'and rows[0x26a316]['instruction']=='movs r0, #0xb'
    assert rows[0x26a320]['instruction']=='rsbs r4, r4, #0'and rows[0x26a330]['instruction']=='blx r5'
    assert im.word(0x26a46c)==0x2cf443c and im.word(0x35d94c)==0xc0de40
    assert im.word(0xc0de40+256)==0x35e391
    text=im.read(0x35d950,40).decode('utf-16le').split('\0')[0];assert text=='Consumer default'
    source=Path(__file__).resolve()
    out=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        source_sha256={str(source.relative_to(ROOT)):hashlib.sha256(source.read_bytes()).hexdigest()},
        complete_bounded_CFG_count=7,functions=functions,original_metadata_reader='0x35d430',
        original_metadata_presence_getter='0x2363b0',original_generic_bank_read='0x26a300',original_profile_lookup='0x26a240',
        profile_table='0x2cf443c',profile_slots=6,original_missing_profile_error=11,
        original_generic_read_normalizes_negative_signed_lengths=True,
        consumer_default_vtable='0xc0de40',original_virtual_defaults_slot64='0x35e391',
        original_constructor='0x35d5d8',stock_UTF16_label=text,
        metadata_bank_ids=[139,140,141,142,143],metadata_body_fields=[
            dict(bank=139,offset=8,bytes=34),dict(bank=140,offset=0x788,bytes=32,read_status_flag_offset=0x788),
            dict(bank=141,offset=0x7a8,bytes=336),dict(bank=142,offset=0x8f8,bytes=560),dict(bank=143,offset=0xb28,bytes=176)],
        header_buffer_zeroed_once_then_reused_across_five_banks=True,
        actual_consumer_metadata_schema_factory_data_driver_registry_and_boot_order_recovered=False,
        indirect_calls_and_callees_not_recursively_recovered=True,device_io=False,sounds_emitted=False)
    path=STAGE/'consumer-metadata-static-preflight.json';assert not path.exists(),'Use new namespace'
    path.write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n');print(json.dumps(dict(complete_CFGs=7)))

if __name__=='__main__':main()
