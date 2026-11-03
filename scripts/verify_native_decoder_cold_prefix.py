#!/usr/bin/env python3
"""Verify sealed cold prefix independently of the later Dispatcher outcome."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json
from analyze_native_sections import ROOT,NativeImage
BASE='staging/native-player-decoder-scope/runtime/'
OUT='evidence/firmware-analysis/native-decoder-cold-prefix-emulation.json'
def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def main():
    assert not (ROOT/OUT).exists(),'Preserve independently verified prefix'
    meta=read(BASE+'terminal-metadata.json');terminal=read(meta['probe']);prefix=read(meta['cold_prefix']);stock=NativeImage()
    assert meta['authoritative_terminal_result_received_from_exec'] and meta['terminal_exit_code'] in [0,1]
    for p,s in meta['source_sha256'].items():assert sha(p)==s,p
    for k in ['runner','runner_snapshot','inputs','probe','FP_helper','GUI_observer','cold_prefix','sealer']:
        assert sha(meta[k])==meta[k+'_sha256'],k
    assert prefix['cold_prefix_full_guards_passed'] and meta['cold_prefix_full_guards_passed'] and terminal['cold_prefix_full_guards_passed']
    assert prefix['completed'] is False and prefix['body_full_guards_passed'] is False,'Prefix must not pretend the body completed'
    boot=prefix['cold_boot'];assert boot['original_FP_boot_executed'] and boot['original_listener_registered']
    assert boot['whole_TCB108_unchanged'] and boot['released_list_backend24_checked'] and boot['FPSCR']=='0x03000000' and boot['FPowner']==0
    assert boot['cold_controller_fill']['whole16384_FF_checked'] and not boot['cold_controller_fill']['host_filled_stack']
    boot_replays=[]
    for zone in boot['whole_boot_zones'].values():
        expected=bytearray.fromhex(zone['before_hex']);start=int(zone['start'],16)
        for store in zone['stores']:
            offset=int(store['address'],16)-start;n=store['size'];assert 0<=offset and offset+n<=len(expected)
            assert expected[offset:offset+n].hex()==store['before_hex']
            if store['kind']=='original_MAIN_CPU_store':
                op=bytes.fromhex(store['opcode_hex']);assert stock.read(int(store['load_PC'],16),len(op))==op
            else:
                assert store['kind']=='declared_initial_ready_membership_input' and (int(store['address'],16),n,store['value']) in [(0x9503f90,4,0x9508f90),(0x9503fa6,1,1)]
            expected[offset:offset+n]=store['value'].to_bytes(n,'little')
        assert zone['whole_zone_replayed'] and hashlib.sha256(expected).hexdigest()==zone['after_sha256']
        boot_replays.append(dict(start=zone['start'],bytes=len(expected),events=len(zone['stores']),independently_replayed=True))
    comp=read('staging/controller-gir-prep-stock-v2/verification.json');binary=(ROOT/comp['flat_binary']).read_bytes();component_replays=[]
    for zone in prefix['extra_zones']:
        expected=bytearray.fromhex(zone['before_hex']);start=int(zone['start'],16)
        for store in zone['stores']:
            offset=int(store['address'],16)-start;n=store['size'];assert 0<=offset and offset+n<=len(expected)
            assert expected[offset:offset+n].hex()==store['before_hex'];op=bytes.fromhex(store['opcode_hex']);pc=int(store['PC'],16)
            if store.get('writer_kind')=='frozen_ARM_companion':assert binary[pc-0xea10000:pc-0xea10000+len(op)]==op
            else:assert stock.read(pc,len(op))==op
            expected[offset:offset+n]=store['value'].to_bytes(n,'little')
        assert zone['whole_net_zone_matches_original_stores'] and hashlib.sha256(expected).hexdigest()==zone['after_sha256']
        component_replays.append(dict(start=zone['start'],bytes=len(expected),events=len(zone['stores']),independently_replayed=True))
    assert len(boot_replays)==5 and len(component_replays)==22
    cache=bytearray(786432);cpu=raw=0
    for event in prefix['whole_cache_journal']:
        offset=event['address']-0x34fa3bc;n=event['bytes'];assert 0<=offset and offset+n<=len(cache)
        assert cache[offset:offset+n].hex()==event['before_hex'];payload=bytes.fromhex(event['after_hex']);info=event['metadata']
        assert len(payload)==n
        if info['kind']=='exact_original_MAIN_CPU_store':
            opcode=bytes.fromhex(info['opcode_hex']);assert stock.read(int(info['load_PC'],16),len(opcode))==opcode
            assert info['running_task']=='0x9503f90' and n==event['events']*info['width'];cpu+=event['events']
        else:
            assert info['kind']=='raw_exact_backup_file_input' and event['events']==1
            data=(ROOT/'backups/20261002T154458Z/files'/info['path'][3:]).read_bytes()
            assert data[info['file_offset']:info['file_offset']+n]==payload and hashlib.sha256(payload).hexdigest()==info['input_sha256'];raw+=1
        cache[offset:offset+n]=payload
    assert cpu==prefix['native_cache_CPU_store_count'] and cpu>0 and raw==112
    # Each store and its original opcode/before bytes is independently replayed.
    # Per-run hook event counts may differ around a timed observation boundary;
    # require whole final bytes against the previous independently verified case.
    previous_cache=read('evidence/firmware-analysis/native-dispatcher-cold-prefix-emulation.json')
    assert hashlib.sha256(cache).hexdigest()==previous_cache['whole_cache_replay_sha256']
    assert previous_cache['all_passed'] and previous_cache['native_cache_CPU_store_events']==356834
    assert len(prefix['component_calls'])==11 and all(c['returned'] for c in prefix['component_calls'])
    assert prefix['component_return']=='0x1' and prefix['component_result20'][2:4]==[0x2ffc,1]
    assert prefix['memory']['all_scoped_memory_guards_passed'] and prefix['memory']['all_SQL_statements_closed']
    assert prefix['memory']['whole_original_shared_font_cache_replayed'] and prefix['memory']['whole_original_cache_bytes']==786432
    assert len(prefix['native_cache_allocations'])==280 and sum(c['freed'] for c in prefix['native_cache_allocations'])==59
    assert len(prefix['native_cache_read_bindings'])==112 and all(c['actual_caller_return_observed'] for c in prefix['native_cache_read_bindings'])
    deps=dict(meta['source_sha256']);verifier=str(Path(__file__).resolve().relative_to(ROOT));deps[verifier]=sha(verifier);deps['evidence/firmware-analysis/native-dispatcher-cold-prefix-emulation.json']=sha('evidence/firmware-analysis/native-dispatcher-cold-prefix-emulation.json')
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,case_count=1,
        cases=[dict(name='complete_cold_component_prefix_before_decoder_scope_Dispatcher_attempt',passed=True,session_id=meta['session_id'],
            native_helpers_returned=11,full_cold_prefix_scoped_guards_passed=True)],source_sha256=deps,
        artifacts_sha256={p:sha(p) for p in [BASE+'terminal-metadata.json',meta['probe'],meta['cold_prefix']]},
        independent_cold_boot_zone_replays=boot_replays,independent_component_zone_replays=component_replays,
        whole_cache_replay_sha256=hashlib.sha256(cache).hexdigest(),native_cache_CPU_store_events=cpu,exact_raw_backup_input_chunks=raw,
        subsequent_body_terminal_exit_code=meta['terminal_exit_code'],subsequent_body_error=meta['error'],
        subsequent_Dispatcher_body_or_multiowner_scheduling_or_foreground_verified=False,
        cache_event_count_independently_derived_per_run=True,whole_cache_bytes_equal_previous_verified_case=True,
        guest_execution_by_verifier=False,device_io=False,sounds_emitted=False,
        scope='Complete cold-controller boot/component prefix is independently sealed before later native queued Dispatcher work. Its5boot/22component/cache histories cannot gain later body events. Later terminal outcome is preserved separately; this prefix is not a full Dispatcher/foreground/App/scheduler FP or hardware music proof.')
    with (ROOT/OUT).open('x') as f:json.dump(result,f,ensure_ascii=False,indent=2);f.write('\n')
    print(json.dumps(dict(all_passed=True,case_count=1,cold_zones=5,component_zones=22,cache_CPU_events=cpu,terminal_exit_code=meta['terminal_exit_code'])))
if __name__=='__main__':main()
