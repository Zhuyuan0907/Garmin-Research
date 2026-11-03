#!/usr/bin/env python3
"""Create proof/handoff or seal this finite static-only namespace."""
from pathlib import Path
import argparse
import hashlib
import json
import os

ROOT = Path('/root/garmin')
HERE = Path(__file__).resolve().parent


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def new_json(name, data):
    p = HERE / name
    assert not p.exists()
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False) + '\n')


def prepare():
    exact = json.loads((HERE/'exact-map-string-search.json').read_bytes())
    direct = json.loads((HERE/'container-direct-call-search.json').read_bytes())
    finite = json.loads((HERE/'bounded-static-witnesses.json').read_bytes())
    for name, proof in [('search_exact_map_strings.py',exact),
                        ('find_container_callers.py',direct),
                        ('capture_bounded_witnesses.py',finite)]:
        assert digest(HERE/name) == proof['source_sha256']
    assert exact['MAIN_stat_before'] == exact['MAIN_stat_after']
    assert direct['MAIN_stat_before'] == direct['MAIN_stat_after']
    assert finite['MAIN_stat_before'] == finite['MAIN_stat_after']
    assert exact['MAIN_stat_before'] == direct['MAIN_stat_before'] == finite['MAIN_stat_before']
    assert len(finite['witnesses']) == 5
    assert finite['actual_explicit_read_bytes'] == 710
    assert finite['actual_explicit_read_operations'] == 15
    assert finite['AP_renderer_or_admission_binding_proved'] is False
    assert finite['exponent_8K_hard_limit_proved'] is False
    assert finite['boundary_128MiB_hard_limit_proved'] is False
    sections = json.loads((ROOT/'evidence/firmware-analysis/native-sections.json').read_bytes())
    executable_spans = [dict(load_start=hex(s['load_start']),load_end=hex(s['load_end']),
                             runtime_start=hex(s['runtime_start']),bytes=s['load_end']-s['load_start'],
                             conditional_startup_copy=s['conditional'])
                        for s in sections['copies']
                        if s['runtime_start'] not in [0xf00000,0xffff0000]]
    receipt = dict(schema='native-AP-static-scope-tool-receipts/v1',
      actual_tools=[
        dict(chunk='191451',exit_code=1,action='Initial inline search command syntax failure',
             reads='No MAIN opened: Python syntax error before code execution',
             preserved_receipt='initial-command-syntax-failure.json'),
        dict(chunk='97a5aa',exit_code=0,action='Saved exact-map-string search',
             source='search_exact_map_strings.py',result='exact-map-string-search.json'),
        dict(initial_chunk='74f159',session_id=77794,terminal_chunk='4a402f',exit_code=0,
             action='Saved exact-target direct branch scan and seven UTF16 map terms',
             source='find_container_callers.py',result='container-direct-call-search.json'),
        dict(chunk='bfab0a',exit_code=0,action='Ephemeral two-span disassembly support',
             requested_spans=[['0x49e960',288],['0x1e7df0',224]],
             retained_instruction_evidence='Successful saved capture below supersedes only its selected fragments'),
        dict(chunk='9b1319',exit_code=0,action='Ephemeral shared parser first1024B disassembly support',
             requested_spans=[['0x1e8046',1024]]),
        dict(chunk='0b3674',exit_code=0,action='Ephemeral five local caller disassembly spans',
             requested_spans=[['0x2ddcb0',900],['0x3a7650',850],['0x167220',520],
                              ['0xfe740',600],['0x1e86ce',760]],
             output_truncated=True,output_truncation_not_success_evidence=True),
        dict(chunk='d3552b',exit_code=0,action='Two exact aligned filename pointer searches plus five local disassembly spans',
             filename_targets=['0x167410','0x3a77f0'],aligned_literal_hits=[0,0],
             requested_spans=[['0x167270',340],['0x10a7d0',230],['0x110ec0',240],
                              ['0x3ca990',120],['0xfea50',164]]),
        dict(chunk='4095c3',exit_code=0,action='One layer of AP-name callee and adjacent map metadata caller',
             requested_spans=[['0x1670d0',376],['0x3a7480',480]]),
        dict(chunk='924659',exit_code=0,action='Three exact literal/context byte reads',
             requested_spans=[['0x1673c8',108],['0xfe7dc',26],['0x2ddd14',50]]),
        dict(chunk='9c3e1a',exit_code=1,action='Initial saved witness capture rejected omitted UTF16 NUL',
             explicit_partial_read_bytes=682,explicit_partial_read_operations=10,
             preserved_source='capture_bounded_witnesses_initial_filename_length_failure.py',
             preserved_receipt='static-capture-initial-length-failure.json'),
        dict(chunk='60db18',exit_code=0,action='Corrected saved finite witness capture',
             explicit_read_bytes=710,explicit_read_operations=15,
             source='capture_bounded_witnesses.py',result='bounded-static-witnesses.json'),
      ],
      search_read_scope=dict(MAIN_mmap_length=finite['MAIN_stat_before'][2],
                            exact_string_searches='Exact ASCII ten terms, UTF16 seven terms and bounded exact aligned-pointer searches',
                            direct_branch_search_load_spans=executable_spans,
                            direct_branch_search_logical_span_bytes=sum(x['bytes'] for x in executable_spans),
                            actual_physical_IO_bytes_not_instrumented=True,
                            no_claim_that_710B_is_total_scope_read_volume=True),
      CPU_executed=False, candidate_IMG_read=False, original_IMG_read=False,
      USB_or_device_access=False, whole_MAIN_or_IMG_hash=False,
      old_closed_suite_executed=False, sealed_input_modified=False,
      all_explicit_MAIN_handles_closed=True)
    new_json('actual-tool-receipts.json',receipt)
    proof = dict(schema='bounded-native-AP-container-admission-research/v1',
      outcome='Bounded insufficiency: true AP renderer/admission path unresolved',
      exact_target_platform=dict(device='Taiwan nuvi2565RT',HWID=1352,software='8.00'),
      exact_MAIN_SHA_inherited=finite['MAIN_identity_sha256_inherited'],
      MAIN_stat_verified_stable_across_saved_runs=finite['MAIN_stat_before'],
      direct_branch_candidate_count=len(direct['direct_branch_candidates']),
      direct_branch_candidates_are_not_all_control_flow_verified=True,
      witness_count=5,
      source_artifacts=[dict(path=str((HERE/name).relative_to(ROOT)),sha256=digest(HERE/name))
                        for name in ['search_exact_map_strings.py','exact-map-string-search.json',
                                     'find_container_callers.py','container-direct-call-search.json',
                                     'capture_bounded_witnesses.py','bounded-static-witnesses.json',
                                     'actual-tool-receipts.json']],
      established=[
        'Exact UTF16 gmapprom1.img and its ADR/caller are present in unconditional MAIN.',
        'The selected shared cache→mount→DSKIMG parser branches match actual instruction bytes.',
        'Selected shared geometry uses dynamic shifts for header61/62 and u16 declaredblockcount.',
        'Selected shared branch checks sectorbytes512, not a 4K blocksize equality.',
      ],
      unresolved=[
        'Exact AP filename→file/container instance→drawing admission/reader call graph.',
        'Which reader and descriptor actual AP rendering uses after map selection/layer arbitration.',
        'Whether 8K block delta4 is rejected, mishandled, or supported by that true AP path.',
        'Whether an actual 128MiB guard exists on that true AP path.',
        'Cause of v3 physical roads-disappear failure; no checksum/priority/capacity diagnosis made.',
      ],
      CPU_execution_skipped_under_parent_stop_rule='No true AP binding identified. Running embedded/shared VPM parser or an isolated arithmetic slice would not prove AP drawing admission.',
      minimal_next_scope=dict(kind='New targeted static-only consumer binding, if assigned',
                             entries=['0x1101ea map-enumeration caller candidate',
                                      '0x2cabbc/0x2ca82c actual map-metadata queries'],
                             target='Identify the map record handed to true drawing/component reader and follow its actual driver descriptor; keep VPM route classified separately.',
                             prerequisite='New scope authorization/bounded budget; no whole OS traversal or old CPU replay'),
      all_assigned_finite_static_checks_passed=True,
      true_AP_path_identified=False, geometry_limit_determined=False,
      native_CPU_case_passed=False, UI_or_device_acceptance_proved=False,
      v3_physical_acceptance=False, full_address_update_complete=False,
      local_source_and_proof_only=True, all_MAIN_handles_closed=True)
    new_json('proof.json',proof)
    handoff = '''本範圍已停止：真 AP 繪圖／admission reader 尚未識別。

交付五條原 MAIN 位址與 bytes：
1. 167282 63a2 ADR →167410 UTF16 gmapprom1.img；167290 fff71eff BL1670d0。
   該 callee 是 formatting/property-style 呼叫形狀，無繪圖／容器 admission 綁定。
2. 1e7e54 16f76ffe BLfeb36，讀22B；1e7e64 61f158fa BL349318 比較 DSKIMG。
3. fea9e e9f016fe BL1e86ce；1e899c fff753fb BL1e8046，僅共用 cache/mount/parser。
4. 1e82da 9040、1e82fc 8840 執行兩個動態 LSL；1e8316 7352 存 u16 blockcount。
   本104B片段沒有 delta==3 比較，不能據此推論真 AP 支援8K。
5. 1e83c4 00d0 BEQ1e83c8；1e83c6 71e7 B1e82ac。比較的是 sectorbytes512，
   不區分9+3與9+4，但也不證明下游接受8192B block。

8K 或128MiB硬限制：均未證明。v3道路消失原因未定位，未猜 checksum／priority。
既有 VPM 綁定不轉稱 AP renderer；未跑1E8046 CPU或舊23筆 suite。
最小下一個可分開授權的新scope：沿1101ea map enumeration及2cabbc/2ca82c metadata
找交給真正繪圖/component reader的 map record/driver descriptor；目前只有候選入口。

710B/15次是最後正式小片段 capture，不是全scope總讀量。此前有唯讀 mmap exact字串、
direct-call scan和有限局部 disasm；physicalIO未量測，actual-tool-receipts.json如實分開。
初次capture讀682B後因UTF16含NUL需28B卻只取26B，assert拒絕；保存失敗source/receipt。
更正後原 bytes/指令guard、三次saved-run MAIN前後stat都通過。

未開原IMG/候選IMG、USB／車機；未改sealed來源、v2/v3、report、ZIP或安裝器。
僅自己的source/proof/receipts；所有 MAIN handles 關閉。不是新候選或可安裝修改。
v3實機接受仍false；全台新地址更新未完成，車機依root最後資訊維持v2。
'''
    (HERE/'HANDOFF.txt').write_text(handoff)
    print(json.dumps(dict(outcome=proof['outcome'],witness_count=5,
                          proof_sha256=digest(HERE/'proof.json'),handles_closed=True),ensure_ascii=False))


def seal():
    assert not (HERE/'sealed-files.json').exists()
    proof=json.loads((HERE/'proof.json').read_bytes())
    supplement=json.loads((HERE/'supplemental-pointer-origin-proof.json').read_bytes())
    assert supplement['MAIN_stat_before']==supplement['MAIN_stat_after']==proof['MAIN_stat_verified_stable_across_saved_runs']
    assert supplement['source_sha256']==digest(HERE/'audit_pointer_origins.py')
    assert proof['supplemental_pointer_origin_audit']['sha256']==digest(HERE/'supplemental-pointer-origin-proof.json')
    assert len(json.loads((HERE/'bounded-static-witnesses.json').read_bytes())['witnesses'])==5
    files = [p for p in sorted(HERE.iterdir()) if p.is_file()]
    assert all(p.suffix in ['.py','.json','.txt'] for p in files)
    rows = []
    for p in files:
        os.chmod(p,0o444)
        rows.append(dict(path=str(p.relative_to(ROOT)),bytes=p.stat().st_size,
                         sha256=digest(p),mode='0444'))
    new_json('sealed-files.json',dict(schema='bounded-source-proof-seal/v1',files=rows,
             all_assigned_finite_static_checks_passed=True,
             bounded_gap_closed_as_gap_not_AP_success=True,
             true_AP_path_identified=False,CPU_executed=False,
             all_MAIN_handles_closed=True,device_acceptance=False))
    os.chmod(HERE/'sealed-files.json',0o444)
    print(json.dumps(dict(files=len(rows)+1,seal_sha256=digest(HERE/'sealed-files.json'),
                          proof_sha256=digest(HERE/'proof.json'),handles_closed=True)))


if __name__ == '__main__':
    args=argparse.ArgumentParser()
    args.add_argument('--seal',action='store_true')
    ns=args.parse_args()
    seal() if ns.seal else prepare()
