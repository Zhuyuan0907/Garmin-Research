#!/usr/bin/env python3
"""Host-only finite-scope audit and seal; never opens MAIN or IMG."""
from pathlib import Path
import hashlib
import json
import os
import sys
import time

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def put(name,value):
    p=HERE/name;assert not p.exists();p.write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n')
def stat(p):
    s=p.stat();return[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def prepare():
    ledger=json.loads((HERE/'read-ledger.json').read_bytes())
    assert ledger['bytes']==5300 and ledger['bytes']<=32768
    main=ROOT/'evidence/firmware-analysis/main_02bd.bin'
    assert stat(main)==ledger['MAIN_stat'] # stat only; no MAIN open/hash
    captures=[]
    for batch in ledger['batches']:
        p=ROOT/batch['path'];b=p.read_bytes();assert sha(b)==batch['sha256']
        x=json.loads(b);assert x['handles_closed'] and x['MAIN_stat_before']==x['MAIN_stat_after']==ledger['MAIN_stat']
        captures.append(dict(path=batch['path'],sha256=sha(b),bytes_read=x['explicit_read_bytes'],
                             operations=x['explicit_read_operations']))
    assert sum(v['bytes_read'] for v in captures)==5300
    input_bindings=json.loads((HERE/'input-bindings.json').read_bytes())
    for pin in input_bindings['files']:
        p=ROOT/pin['path'];b=p.read_bytes();assert sha(b)==pin['sha256'] and len(b)==pin['bytes']
        assert p.stat().st_mode&511==292
    cpu=json.loads((HERE/'producer-cpu-proof.json').read_bytes())
    assert cpu['completed_cases']==1 and cpu['completed_original_instructions']==31
    assert cpu['stop']=='0x2ca82c' and cpu['unknown_callback_returns_faked'] is False
    ws=json.loads((HERE/'five-exact-witnesses.json').read_bytes());assert len(ws['witnesses'])==5
    cpu_sha=sha((HERE/'producer-cpu-proof.json').read_bytes())
    corrections=[
      '10E058/10E0EE are allocated 10-byte scratch-entry+6 stores, not kind5 payload+6; 10FBF8 writes a component slot vector.',
      'The captured 110430..1104B0 window starts in an existing literal/data pool. Its linear instructions and inferred PC literals are not control-flow evidence; all actual read bytes remain charged.',
      '358FDC calls 3985D8 on a 25-byte token representation. B9DCE4 is a binary field-bit-routing table, not printf/sscanf text. Provisional source6numeric_scan names are retained with this correction.',
      '111CA4/111D0A wrappers only establish a separate source-enumerator frontier; they are not proven type1163 producers. The 10C60C branch itself truly enumerates type1163.',
      'The producer takes SP+64, not SP+6C directly. SP+64 is the running minimum of matching candidate values; SP+6C remains the previously proven calendar-week threshold.'
    ]
    put('proof.json',dict(schema='native-ap-registry-kind5-date-producer-proof/v1',
      source_sha256=sha((HERE/'probe_producer.py').read_bytes()),capture_source_sha256=sha((HERE/'capture_windows.py').read_bytes()),
      captures=captures,new_MAIN_bytes=5300,new_MAIN_operations=ledger['operations'],MAIN_cap=32768,
      IMG_read_bytes=0,IMG_reads=0,device_operations=0,whole_MAIN_or_IMG_hash=False,
      producer_cpu_sha256=cpu_sha,completed_original_CPU_cases=1,completed_original_instructions=31,
      five_witnesses_sha256=sha((HERE/'five-exact-witnesses.json').read_bytes()),
      source_field_routing_sha256=sha((HERE/'source-field-routing.json').read_bytes()),
      source_inputs_stat_and_hash_checked=True,source_MAIN_stat_stable=True,
      precise_field_chain=dict(
        actual_payload_store=dict(pc='0x110a10',bytes='e080',instruction='STRH r0,[r4,#6]',source='SP+64'),
        typed_commit=dict(kind_store_pc='0x110a02',byte1_OR='0xa0',type_literal='0x110d24=0x101a',call_pc='0x110a34',call_bytes='b9f1fafe',target='0x2ca82c',length='low16(256+80*payload_u16_at_2)'),
        caller_min=dict(initial='0xffff at1105d0/1105d6',provider_call='11069e→10e7b8',provider_arg1='SP+6c weekthreshold',update='1106ae..1106b8 min including ties'),
        provider_match=dict(entry_size=12,candidate_value='u16(entry+4)',maximum_over_matching_entries=True,
                            exact_match='entry+6 == decoded metadata+0; entry+8,+9,+10 zero wildcard or exact bytes decodedmetadata+2,+3,+4',
                            zero_candidate='sets r6=0xffff',return_pc='0x10ea0c'),
        source_table=dict(store_pc='0x10ee86',store_bytes='8180',input='word(source+4)',
                          constructor='10EE08',caller='10F05A',caller_into_Mapload='1103e4',
                          first_supply='10C60C enumerates typed1163 and compares exactly25 bytes',
                          other_supply='10C5FC/10C604 wrappers feed independent source frontier, not source identity proof'),
        token_field=dict(parser='358FDC→3985D8',input_representation_bytes=25,true_word4_store='0x398804',
                        routing_width=13,bits=list(range(13)),normalization='398880..398888: bit12=1 maps word4 tozero',
                        actual_private_token_or_license_data_read=False),
        metadata_matching_input=dict(provider='10E7B8',original_read_dispatch='1C8782',decoder='1E0B64',
                                    source='incoming context+34 handle/base,+38 mode; firstoffset context+134',
                                    raw_live_provider_not_bound=True),
        consumer='10F198..10F1B0 accepts actual kind5 pair;110FA4 u16 payload+6 participates min/110FEE date-week compare'),
      reused_closed_date_and_status_scope=dict(path='staging/navigation-native-ap-registry-node-semantics-v1/proof.json',rerun=False),
      corrections=corrections,synthetic_fixture=cpu['fixture'],stop_before_allocator=True,
      unknown_callee_returns_substituted=False,previous_closed_cases_rerun=False,
      all_assigned_bounded_checks_passed=True,closed_with_data_origin_gap=True,
      remaining_blockers=[
       'No real private token, actual decoded candidate numeric value, live registry/provider state or current clock was read.',
       'Persistent/live origin of source enumerator and metadata read mode remains unknown; no complete cold Mapload/provider execution.',
       'The field is numeric and compared with proven current-week threshold; expiry/license-purpose names and same epoch for real token value are not established.',
       'No AP overlay/renderer acceptance, actual v3 regression cause or 128MiB/GMP physical-window cause proved.'
      ],minimal_next_entry='Bounded source/provider object construction ABI at10F05A→10C604/111CA4 and live metadata context+34/+38/+134, using synthetic/nonprivate data only.',
      real_expiry_reason_proved=False,authorization_bypass_tested=False,renderer_proved=False,
      v3_fixed=False,physical_acceptance=False,App_completed=False,full_address_update_completed=False,
      shared_or_sealed_input_modified=False,all_scope_handles_closed=True))
    handoff='''NEW navigation-native-ap-registry-date-producer-v1 — sealed bounded read-only result

The true type101A/kind5 payload+6 writer is 110A10 (e080 STRH r0,[r4,#6]).
1109F8..110A34 sets kind5 (byte1 OR A0), writes the opaque pair at +8/+C,
and passes type101A and low16(256+80*count) to the real 2CA82C allocator.
The value comes from SP+64: min of descriptor-provider returns, initialized
FFFF. 10E7B8 returns max matching 12-byte source entries' u16+4 (zero yields
FFFF); input r1 is the separately proven current-week threshold SP+6C.

12-byte source entry+4 is written at10EE86 from the parsed source word+4.
358FDC→3985D8 processes a25-byte token representation; its true word+4 store
is398804. Exact binary table routing selects13bits0..12;398880..398888 maps
bit12 set tozero. This is not an sscanf/date-text routine. No true private
token, UNL text, serial or decoded authorization data is stored here.
The original source enumerator10C60C uses type1163; other source enumeration
and metadata context+34/+38/+134 construction remain an explicit frontier.

One new ORIGINAL CPU fixture passed:31instructions1109F8→original BL110A34→
2CA82C entry. Synthetic candidate1500/count2/pair, exact416byte argument,
kind5/field6 and every byte outside explicit stores verified. The typed
allocator, token decoder, metadata provider and renderer were not executed;
there are no fake callback returns. Prior7date/status and mount/matrix cases
were not rerun. FreshMAIN5300B (cap32768), IMG0, no whole input hashes.

Five exact byte witnesses and all capture read ledgers are retained. Two
provisional window labels were wrong (110430literalpool;binary source table
was not a textual scan format);proof explicitly corrects them without
erasing any read receipt. No source/firmware/device/canonical/report changes.
No expiry purpose, real token epoch, v3 road rootcause, overlay/render result,
physical acceptance, App or full-address-update completion is claimed.
All source handles closed. Scope stops after this finite producer witness.
'''
    (HERE/'HANDOFF.txt').write_text(handoff)
    put('host-final-audit.json',dict(schema='bounded-producer-final-audit/v1',PID=os.getpid(),
      time_ns=time.time_ns(),new_MAIN_opened=False,IMG_opened=False,guest_rerun=False,
      all_checks_passed=True,all_handles_closed=True,proof_sha256=sha((HERE/'proof.json').read_bytes())))
    print(json.dumps(dict(proof_sha256=sha((HERE/'proof.json').read_bytes()),CPU_sha256=cpu_sha,
                         MAIN_bytes=5300,MAIN_operations=ledger['operations'],IMG_bytes=0,guest_rerun=False,handles_closed=True)))
def seal():
    assert (HERE/'host-final-audit.json').exists() and not (HERE/'sealed-files.json').exists()
    paths=sorted(p for p in HERE.iterdir() if p.is_file())
    for p in paths:p.chmod(0o444)
    rows=[]
    for p in paths:
        b=p.read_bytes();assert p.stat().st_mode&511==292
        rows.append(dict(path=str(p.relative_to(ROOT)),bytes=len(b),sha256=sha(b),mode='0444'))
    p=HERE/'sealed-files.json'
    p.write_text(json.dumps(dict(schema='garmin-bounded-readonly-scope-seal/v1',scope=str(HERE.relative_to(ROOT)),files=rows,
      file_count=len(rows),all_assigned_checks_passed=True,scope_closed_with_data_origin_gap=True,
      all_handles_closed=True,shared_or_device_mutation=False,renderer_proved=False,v3_fixed=False,
      full_goal_completed=False),indent=2)+'\n');p.chmod(0o444)
    print(json.dumps(dict(seal_sha256=sha(p.read_bytes()),sealed_files=len(rows),mode='0444',
                         proof_sha256=sha((HERE/'proof.json').read_bytes()),all_handles_closed=True)))
if __name__=='__main__':
    assert len(sys.argv)==2
    {'prepare':prepare,'seal':seal}[sys.argv[1]]()
