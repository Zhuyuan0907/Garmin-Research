#!/usr/bin/env python3
"""Independently replay one sealed cold FP boot plus full native component run."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json
from analyze_native_sections import NativeImage
ROOT=Path(__file__).resolve().parents[1]
BASE='staging/native-player-cold-fp-controller/runtime/'
OUT='evidence/firmware-analysis/native-cold-fp-controller-emulation.json'
def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def main():
    assert not (ROOT/OUT).exists(),'Keep positive proof immutable'
    meta=read(BASE+'terminal-metadata.json');probe=read(meta['probe']);stock=NativeImage()
    for p,d in meta['source_sha256'].items():assert sha(p)==d,p
    for k in ['runner','runner_snapshot','inputs','probe','guard_copy_source','guard_copy_provenance','previous_checkpoint','sealer']:
        assert sha(meta[k])==meta[k+'_sha256'],k
    assert meta['terminal_exit_code']==0 and meta['authoritative_terminal_result_received_from_exec']and probe['completed']and probe['full_scoped_final_guards_passed']
    boot=probe['cold_boot'];assert boot['original_FP_boot_executed']and boot['original_listener_registered']and boot['whole_TCB108_unchanged']and boot['released_list_backend24_checked']
    assert boot['FPSCR']=='0x03000000'and boot['FPowner']==0 and not boot['multiowner_exchange_executed']
    assert probe['cold_fill']['whole16384_FF_checked']and not probe['cold_fill']['host_filled_stack']
    zones=[]
    for zone in probe['cold_boot_zones'].values():
        expected=bytearray.fromhex(zone['before_hex']);start=int(zone['start'],16)
        for row in zone['stores']:
            offset=int(row['address'],16)-start;n=row['size'];assert 0<=offset and offset+n<=len(expected)
            assert expected[offset:offset+n].hex()==row['before_hex']
            if row['kind']=='original_MAIN_CPU_store':
                opcode=bytes.fromhex(row['opcode_hex']);assert stock.read(int(row['load_PC'],16),len(opcode))==opcode
            else:
                assert row['kind']=='declared_initial_ready_membership_input'
                assert (int(row['address'],16),n,row['value'])in [(0x9503f90,4,0x9508f90),(0x9503fa6,1,1)]
            expected[offset:offset+n]=row['value'].to_bytes(n,'little')
        assert zone['whole_zone_replayed']and hashlib.sha256(expected).hexdigest()==zone['after_sha256']
        zones.append(dict(start=zone['start'],bytes=len(expected),stores=len(zone['stores']),independently_replayed=True))
    assert len(zones)==5
    comp=read('staging/controller-gir-prep-stock-v2/verification.json');binary=(ROOT/comp['flat_binary']).read_bytes();extra=[]
    for zone in probe['extra_zones']:
        expected=bytearray.fromhex(zone['before_hex']);start=int(zone['start'],16)
        for row in zone['stores']:
            offset=int(row['address'],16)-start;n=row['size'];assert 0<=offset and offset+n<=len(expected)
            assert expected[offset:offset+n].hex()==row['before_hex'];opcode=bytes.fromhex(row['opcode_hex']);pc=int(row['PC'],16)
            if row.get('writer_kind')=='frozen_ARM_companion':assert binary[pc-0xea10000:pc-0xea10000+len(opcode)]==opcode
            else:assert stock.read(pc,len(opcode))==opcode
            expected[offset:offset+n]=row['value'].to_bytes(n,'little')
        assert zone['whole_net_zone_matches_original_stores']and hashlib.sha256(expected).hexdigest()==zone['after_sha256']
        extra.append(dict(start=zone['start'],bytes=len(expected),stores=len(zone['stores']),independently_replayed=True))
    assert len(extra)==22
    cache=bytearray(786432);cpu=raw_count=0
    for row in probe['whole_cache_journal']:
        offset=row['address']-0x34fa3bc;n=row['bytes'];assert 0<=offset and offset+n<=len(cache)
        assert cache[offset:offset+n].hex()==row['before_hex'];payload=bytes.fromhex(row['after_hex']);info=row['metadata']
        assert len(payload)==n
        if info['kind']=='exact_original_MAIN_CPU_store':
            opcode=bytes.fromhex(info['opcode_hex']);assert stock.read(int(info['load_PC'],16),len(opcode))==opcode
            assert info['running_task']=='0x9503f90'and n==row['events']*info['width'];cpu+=row['events']
        else:
            assert info['kind']=='raw_exact_backup_file_input'and row['events']==1
            data=(ROOT/'backups/20261002T154458Z/files'/info['path'][3:]).read_bytes()
            assert data[info['file_offset']:info['file_offset']+n]==payload and hashlib.sha256(payload).hexdigest()==info['input_sha256'];raw_count+=1
        cache[offset:offset+n]=payload
    assert cpu==probe['native_cache_CPU_store_count']and raw_count==112
    assert probe['memory']['whole_original_shared_font_cache_replayed']and probe['memory']['all_scoped_memory_guards_passed']and probe['memory']['all_SQL_statements_closed']
    assert len(probe['component_calls'])==11 and all(r['returned']for r in probe['component_calls'])
    assert probe['component_return']=='0x1'and probe['component_result20'][2:4]==[0x2ffc,1]
    assert len(probe['native_cache_allocations'])==280 and sum(r['freed']for r in probe['native_cache_allocations'])==59
    assert len(probe['native_cache_read_bindings'])==112 and all(r['actual_caller_return_observed']for r in probe['native_cache_read_bindings'])
    assert probe['actual_FPU_state']['FPowner']=='0x9503f90'and not probe['invalid_accesses']and not probe['native_fatal_entries']
    assert not probe['cache_observer_UcErrors']and not probe['unexpected_emulation_UcErrors']
    deps=dict(meta['source_sha256']);deps[str(Path(__file__).resolve().relative_to(ROOT))]=sha(str(Path(__file__).resolve().relative_to(ROOT)))
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,case_count=1,
        cases=[dict(name='cold_typed_controller_original_FP_boot_and_complete_native_component',passed=True,session_id=meta['session_id'],
            original_FP_boot_executed=True,original_listener_registered=True,whole_controller_native_FF_fill=True,
            whole_boot_TCB108_and_released_list24_verified=True,original_helpers_returned=11,full_scoped_final_guards_passed=True)],
        source_sha256=deps,artifacts_sha256={p:sha(p)for p in [BASE+'terminal-metadata.json',meta['probe'],meta['guard_copy_provenance']]},
        independent_cold_boot_zone_replays=zones,independent_component_zone_replays=extra,whole_cache_replay_sha256=hashlib.sha256(cache).hexdigest(),
        native_cache_CPU_store_events=cpu,exact_raw_backup_input_chunks=raw_count,independent_cold_scenarios=1,
        only_first_same_controller_FP_verified=True,multiowner_FP_or_foreground_or_accepted_package_or_physical_App_or_direct_music_verified=False,
        guest_execution_by_verifier=False,device_io=False,sounds_emitted=False)
    with (ROOT/OUT).open('x')as f:json.dump(result,f,ensure_ascii=False,indent=2);f.write('\n')
    print(json.dumps(dict(all_passed=True,case_count=1,cold_zones=len(zones),component_zones=len(extra),cache_CPU_events=cpu,source_dependencies=len(deps))))
if __name__=='__main__':main()
