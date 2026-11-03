#!/usr/bin/env python3
"""Execute stock USB/accessory-ID classification using stock threshold tables.

The registered channel record, policy byte and classification samples are
synthetic. This does not operate a cable, ADC, USB controller or host driver.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import sys

from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from analyze_sdp_activation import trace
from emulate_native_projection_io import Probe, require

RECORD=0x02cea2c4
LABELS,WINDOWS,MAP=0x8dcd8c,0x8dcd40,0x8dcdfc


def sha(blob):return hashlib.sha256(blob).hexdigest()


def wide(image,address):
    raw=image.read(address,160)
    end=next(n for n in range(0,len(raw),2) if raw[n:n+2]==b'\0\0')
    return raw[:end].decode('utf-16le')


def run(stock,image,sample,expected,channel=0,policy=11,previous=13):
    p=Probe(stock);p.uc.mem_map(RECORD&~4095,4096)
    p.guarded(RECORD,24)
    record=bytearray(24)
    record[:4]=bytes([0,previous,14,14])
    struct.pack_into('<4I',record,4,3290,LABELS,WINDOWS,MAP)
    record[20]=11
    p.uc.mem_write(RECORD,bytes(record));p.uc.mem_write(0xf08ac0,bytes([policy]))
    result=p.call(0x33213e,channel,sample)
    require(result==expected,'Original ID classifier differs')
    require(p.data(RECORD,24)==bytes(record),'Pure query changed channel state')
    p.guard_ok(RECORD,24)
    require(not p.fixtures,'Classifier reached an unexpected function fixture')
    require(p.visits[0x332124]==1,'Native channel lookup bypassed')
    label=wide(image,image.word(LABELS+result*8+4)) if result<14 else 'unknown/no classified type'
    return {'synthetic_classification_sample':sample,'synthetic_channel':channel,
            'synthetic_policy_byte':policy,'synthetic_previous_type':previous,
            'native_type_result':result,'stock_display_label':label,
            'registered_record_and_guard_unchanged':True,'all_passed':True,
            'native_functions_executed':{hex(a):p.visits[a] for a in
                (0x33213e,0x332124,0x332046,0x33202a)},
            'function_fixtures':[],'actual_ADC_or_USB_role_change_executed':False}


def main():
    stock=NativeImage();image=RuntimeImage(stock)
    require(image.word(0x3323a0)==LABELS and image.word(0x3323a4)==WINDOWS and
            image.word(0x332394)==MAP,'Stock USB ID table references differ')
    cases=[run(stock,image,sample,expected) for sample,expected in
           [(0,0),(32,0),(33,14),(59,1),(850,12),(851,14),(877,13),(1000,13),(1001,14)]]
    cases.append(run(stock,image,1000,14,channel=4))
    # A stock policy branch can reinterpret the last band. Do not label the
    # policy fixture as this unit's hardware ID or configuration value.
    cases.append(run(stock,image,1000,10,policy=0,previous=10))
    require(cases[0]['stock_display_label']=='USB Type-A' and
            cases[6]['stock_display_label']=='USB Type-B','Stock labels differ')
    functions={hex(a):trace(image,a,500) for a in (0x33213e,0x332124,0x332046)}
    require(all(not f['instruction_limit_reached'] and not f['unresolved_exits']
                for f in functions.values()),'Unresolved local classification CFG')
    types=[{'type':n,'predicate_pointer':hex(image.word(LABELS+n*8)),
            'label':wide(image,image.word(LABELS+n*8+4))} for n in range(14)]
    deps={Path(__file__).resolve(),ROOT/'evidence/firmware-analysis/main_02bd.bin'}
    for module in list(sys.modules.values()):
        name=getattr(module,'__file__',None)
        if name and Path(name).resolve().parent==ROOT/'scripts' and name.endswith('.py'):
            deps.add(Path(name).resolve())
    output={'updated_utc':datetime.now(timezone.utc).isoformat(),
        'exact_target':{'HWID':1352,'software':'8.00','stock_sha256':EXPECTED},
        'source_sha256':{str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in sorted(deps)},
        'cases':cases,'functions':functions,'stock_type_labels_and_predicates':types,
        'stock_classification_windows':list(struct.iter_unpack('<HH',image.read(WINDOWS,44))),
        'stock_band_to_type_map':list(image.read(MAP,11)),
        'registered_channel_record_fixture':{'address':hex(RECORD),'bytes':24,
            'type_predicate_label_table_offset':8,'classification_windows_offset':12,
            'band_map_offset':16,'band_count_offset':20},
        'all_passed':True,'stock_code_mappings_write_protected':True,
        'device_io':False,'firmware_modified':False,'device_install_candidate':False,
        'USB_host_AOA_or_VBUS_drive_verified':False,
        'observed_3_29V_conversion_to_classification_input_verified':False,
        'live_policy_channel_registration_or_ADC_sample_verified':False,
        'scope':'Original pure query33213E→332124/332046 executes on a synthetic registered channel with exact stock tables, testing USB Type-A/Type-B bands, inclusive bounds/gaps, invalid channel and a policy-dependent remapping. No function fixtures, transition setter, ADC/voltage calibration, USB ID cable, VBUS, hardware controller, AOA, host registration or actual phone session. Label/predicate tables do not prove drivers for listed USB Audio/Ethernet/etc.'}
    path=ROOT/'evidence/firmware-analysis/native-usb-id-emulation.json'
    path.write_text(json.dumps(output,indent=2)+'\n')
    print(json.dumps({'evidence':str(path.relative_to(ROOT)),'cases':len(cases),
                      'native_type_results':[c['native_type_result'] for c in cases],
                      'all_passed':True,'device_io':False}))


if __name__=='__main__':main()
