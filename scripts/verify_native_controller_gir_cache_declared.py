#!/usr/bin/env python3
"""Independently replay sealed native component journals; no guest execution."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,sys
from analyze_native_sections import NativeImage
ROOT=Path(__file__).resolve().parents[1]
BASE='staging/native-player-controller-gir-integration/runtime-cache-declared/'
OUT='evidence/firmware-analysis/native-controller-gir-cache-declared-emulation.json'
def read(path):return json.loads((ROOT/path).read_text())
def sha(path):return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
def main():
    meta=read(BASE+'terminal-metadata.json');probe=read(meta['probe']);actual=read(meta['actual_observer_state']);declared=read(meta['declared_cache_state'])
    for path,digest in meta['source_sha256'].items():assert sha(path)==digest,path
    for key in ['runner','runner_snapshot','inner_observer','inner_snapshot','driver','driver_snapshot','outer_inputs',
        'inner_inputs','driver_inputs','probe','actual_observer_state','declared_cache_state','peer_review','previous_checkpoint','previous_audit','sealer']:
        assert sha(meta[key])==meta[key+'_sha256'],key
    assert meta['session_id']==14246 and meta['terminal_exit_code']==0 and probe['completed']and probe['full_scoped_final_guards_passed']
    assert len(probe['component_calls'])==11 and all(row['returned']for row in probe['component_calls'])
    assert probe['component_return']=='0x1'and probe['component_result20'][2:4]==[0x2ffc,1]
    assert not declared['cache_observer_UcErrors']and not declared['unexpected_emulation_UcErrors']
    assert declared['whole_declared_cache_zero_sha256']==hashlib.sha256(bytes(786432)).hexdigest()
    stock=NativeImage();cache=bytearray(786432);cpu_count=0;raw_count=0
    for row in actual['whole_cache_journal']:
        offset=row['address']-0x34fa3bc;size=row['bytes'];assert 0<=offset and offset+size<=len(cache)
        before=bytes.fromhex(row['before_hex']);payload=bytes.fromhex(row['after_hex'])
        assert len(payload)==len(before)==size and cache[offset:offset+size]==before
        info=row['metadata']
        if info['kind']=='exact_original_MAIN_CPU_store':
            opcode=bytes.fromhex(info['opcode_hex']);assert stock.read(int(info['load_PC'],16),len(opcode))==opcode
            assert info['running_task']=='0x9503f90'and size==row['events']*info['width'];cpu_count+=row['events']
        else:
            assert info['kind']=='raw_exact_backup_file_input'and row['events']==1
            raw=(ROOT/'backups/20261002T154458Z/files'/info['path'][3:]).read_bytes()
            assert raw[info['file_offset']:info['file_offset']+size]==payload and hashlib.sha256(payload).hexdigest()==info['input_sha256'];raw_count+=1
        cache[offset:offset+size]=payload
    assert cpu_count==actual['native_cache_CPU_store_count']==356833
    comp_manifest=read('staging/controller-gir-prep-stock-v2/verification.json');comp=(ROOT/comp_manifest['flat_binary']).read_bytes()
    zones=[]
    for zone in probe['extra_zones']:
        raw=bytearray.fromhex(zone['before_hex']);assert len(raw)==zone['bytes']
        for row in zone['stores']:
            offset=int(row['address'],16)-int(zone['start'],16);size=row['size'];assert 0<=offset and offset+size<=len(raw)
            assert raw[offset:offset+size].hex()==row['before_hex'];opcode=bytes.fromhex(row['opcode_hex']);pc=int(row['PC'],16)
            if row.get('writer_kind')=='frozen_ARM_companion':assert comp[pc-0xea10000:pc-0xea10000+len(opcode)]==opcode
            else:assert stock.read(pc,len(opcode))==opcode
            raw[offset:offset+size]=int(row['value']).to_bytes(size,'little')
        assert zone['whole_net_zone_matches_original_stores']and hashlib.sha256(raw).hexdigest()==zone['after_sha256']
        zones.append(dict(start=zone['start'],bytes=zone['bytes'],stores=len(zone['stores']),independently_replayed=True))
    assert len(zones)==19
    for row in probe['initialized_data_journal']['stores']:
        opcode=bytes.fromhex(row['original_opcode_hex']);assert stock.read(int(row['PC'],16),len(opcode))==opcode
    for row in actual['native_cache_allocations']:
        assert row['actual_caller_return_observed']and not row.get('failed')
        assert row['units']==((row['requested_bytes']+7)>>3)+1 and row['capacity']==(row['units']-1)*8
        assert stock.read((row['LR']&~1)-4,4).hex()==row['caller_opcode_hex']
        assert 0x34fa3bc<=row['pointer']-8 and row['pointer']+row['capacity']<=0x35ba3bc and (row['pointer']-0x34fa3bc)%8==0
    assert len(actual['native_cache_allocations'])==280 and sum(row['freed']for row in actual['native_cache_allocations'])==59
    assert len(actual['native_cache_read_bindings'])==112 and all(row['actual_caller_return_observed']for row in actual['native_cache_read_bindings'])
    assert not actual['native_cache_alloc_pending']and not actual['native_cache_returns_pending']and not actual['native_cache_free_pending']and not actual['native_cache_read_pending']and actual['native_cache_reader_route_pending']is None
    memory=probe['memory'];assert memory['whole_original_shared_font_cache_replayed']and memory['full_original_font_activation_index_path_and_selector_checked']
    assert len(memory['resident_font_streams'])==8 and len(memory['actual_font_inventory'])==13 and memory['all_SQL_statements_closed']
    for font in memory['actual_font_inventory']:
        active=font['index']not in [6,11];assert font['metadata_flags'][1]==int(active)and font['context_error']==('0x0'if active else'0x66')
    assert len(probe['native_endpoint']['native_inventory']['tasks'])==5 and len(probe['native_endpoint']['resident_four_frames'])==4
    assert probe['native_endpoint']['whole_TCB108_compared_with_exact_native_deltas']and not probe['invalid_accesses']and not probe['native_fatal_entries']
    deps=dict(meta['source_sha256']);deps[str(Path(__file__).resolve().relative_to(ROOT))]=sha(str(Path(__file__).resolve().relative_to(ROOT)))
    artifacts={path:sha(path)for path in [BASE+'terminal-metadata.json',meta['probe'],meta['actual_observer_state'],meta['declared_cache_state'],meta['peer_review']]}
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,case_count=1,
        cases=[dict(name='full_compiled_stock_GIR_preparation_on_actual_native_controller',passed=True,session_id=14246,
            original_helper_returns=11,cache_CPU_stores=cpu_count,native_cache_allocations=280,native_cache_frees=59,original_font_read_bindings=112,
            whole_cache_bytes=786432,whole_zone_replays=19,five_TCB108_and_four_frames52_preserved=True,readonly_code_and_raw_backup_fonts=True)],
        source_sha256=deps,artifacts_sha256=artifacts,independent_whole_zone_replays=zones,
        independent_cache_replay_sha256=hashlib.sha256(cache).hexdigest(),cache_raw_input_chunks=raw_count,
        source_inventory_includes_prior_protected_files_and_is_not_a_count_of_independent_experiments=True,
        actual_runtime_full_cache_read_comparison_witness=memory['whole_original_shared_font_cache_replayed'],
        original_GUI_bank_and_initialized_bank_guards_passed=True,all_SQL_statements_closed=True,
        raw_filesystem_heap_geometry_clock_and_exception_entry_are_declared_fixtures=True,
        physical_App_or_foreground_or_multiowner_FP_or_package_acceptance_or_direct_phone_music_verified=False,
        new_guest_execution_by_this_verifier=False,device_io=False,sounds_emitted=False)
    with (ROOT/OUT).open('x')as out:json.dump(result,out,ensure_ascii=False,indent=2);out.write('\n')
    print(json.dumps(dict(all_passed=True,case_count=1,source_dependencies=len(deps),cache_CPU_stores=cpu_count,native_allocations=280,raw_chunks=raw_count,zone_replays=len(zones))))
if __name__=='__main__':main()
