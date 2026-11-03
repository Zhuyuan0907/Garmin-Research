#!/usr/bin/env python3
"""Freeze new scoped evidence for root publication, with no VM or device I/O."""
from pathlib import Path
from datetime import datetime, timezone
from functools import lru_cache
import hashlib
import json

ROOT = Path(__file__).resolve().parents[2]
B = 'staging/native-player-native-allocation/'
A = B + 'audio-session-static/'
C = 'staging/native-player-continuous-session/'

def read(path):
    return json.loads((ROOT/path).read_text())

@lru_cache(None)
def sha(path):
    digest = hashlib.sha256()
    with (ROOT/path).open('rb') as handle:
        while chunk := handle.read(8*1024*1024):
            digest.update(chunk)
    return digest.hexdigest()

def main():
    output = ROOT/B/'publication-inputs.json'
    assert not output.exists(), 'Preserve frozen manifest'
    frozen = {}
    findings = {}
    def register(entries):
        for path, digest in entries.items():
            assert sha(path) == digest, path
            assert path not in frozen or frozen[path] == digest, path
            frozen[path] = digest
    def add(key, path, scope, pass_field='all_passed'):
        d = read(path)
        assert d[pass_field] is True, path
        findings[key] = dict(path=path, sha256=sha(path), scope=scope, pass_field=pass_field)
        for field in ('source_sha256', 'dependency_sha256', 'verified_runtime_dependencies',
                      'artifacts_sha256', 'output_sha256', 'generated_sha256'):
            if isinstance(d.get(field), dict):
                register(d[field])
        for case in d.get('cases', []):
            assert case['passed'], path
            if 'path' in case:
                register({case['path']:case['sha256']})
        frozen[path] = sha(path)

    rows = [
        ('native_public_heap_v1_observer_static', B+'gui-static/native-allocation-observer-contract.json', '79 pure host controls; not native allocation success.'),
        ('native_public_heap_original_constructor_observed', B+'verification/native-heap-constructor-observed-prefix.json', 'Original public heap constructor genuinely returned; independent original stores and constructor-stack replay. Native48/8 still false.'),
        ('native_public_heap_complete_cold_prefix', B+'verification/native-public-heap-cold-prefix.json', 'Independent complete 5boot/24component/11helper/fontcache cold prefix; later body failed.'),
        ('native_public_heap_v1_partial_terminal_scope', B+'verification/native-public-heap-partial-journals.json', '7body/8FP/bank/2public actual-final replays; 24 inherited terminal after-snapshots absent, so no full24 terminal claim.'),
        ('native_public_heap_v1_host_return_erratum', B+'gui-static/native-allocation-v1-terminal-scope-correction.json', 'Actual returned88246A0 came from inherited host allocator; zero original malloc frames/raw operations.'),
        ('native_public_heap_v2_observer_static', B+'gui-static/native-allocation-observer-v2-contract.json', '120 pure host controls; original thunk admission, not native malloc success.'),
        ('native_public_heap_v2_host_return_erratum', B+'gui-static/native-allocation-v2-terminal-scope-correction.json', 'Original thunk ran but WidgetVM intercepted2DC954 before PUSH; returned8400020 is host fixture.'),
        ('native_public_heap_v3_observer_static', B+'gui-static/native-allocation-observer-v3-contract.json', '187 pure host controls and exact pending frame/provider gates; guest outcome separate.'),
        ('native_public_heap_inherited_provider_audit', B+'gui-static/native-allocation-inherited-provider-audit-v3.json', 'AST45 inherited classes, bounded13 original functions; no guest or allocator success claim.'),
        ('native_constructor_leaf_helpers_static', B+'constructor-leaf-helpers-static.json', '8 exact leaf instructions; no native body execution claim.'),
        ('native_audio_full_reader_ARM_build', A+'build-v3.json', 'Freestanding ARM ET_EXEC has zero undefined symbols; bounded audio driver, not full player.'),
        ('native_audio_full_reader_actual_two_cases', A+'audio-session-emulation-v2-proof.json', 'Actual compiled512-byte submit, original queue/selector/provider/fullreader with leases through full return; explicit service/actor fixtures.'),
        ('native_audio_full_reader_independent_files', A+'audio-session-v2-independent-file-verification.json', '2 independent file-only cases;5757CPUstores/5789joint events;16 tracked zones include15RW plus unchanged RX sentinel; no guest rerun.'),
        ('native_audio_mixer_handoff_ticket_scope', A+'native-mixer-handoff-and-ticket-reuse-scope-review.json', 'Original mixer call sites and TCB handoff still missing; finite ticket reuse issue is static counterexample, not a new runtime case.'),
        ('native_continuous_session_static_contract', C+'build-v1.json', 'New stable session identity vs per-buffer ticket; ARM ET_EXEC zero undefined symbols, not native scheduling or hardware.'),
        ('native_continuous_session_host_controls', C+'continuous-session-host-controls-v3.json', '25 HOST ASan/UBSan groups only; native evidence recorded separately.'),
        ('native_continuous_session_actual_three_cases', C+'continuous-session-emulation-v1-proof.json', 'Actual root ARM cases:12 same-slot generations/24 full pulls, underrun/resume and localStop; output-consumer read-index is explicit fixture.'),
    ]
    for row in rows:
        add(*row)
    add('native_constructor_continuation_static', B+'constructor-continuation-static.json',
        '13 original opcode assertions and next60/16 allocation scopes; no constructor success.',
        'all_encoding_assertions_passed')
    add('native_public_heap_v3_actual_terminal_scope', B+'runtime-v3/terminal-metadata.json',
        'Actual terminal EXIT1/61dabd; original malloc frame/lock reached, hard stop38806C; no48/8 return or complete body.',
        'authoritative_terminal_result_received_from_exec')
    continuous_independent = C+'continuous-session-v1-independent-file-verification.json'
    if (ROOT/continuous_independent).exists():
        assert (ROOT/C/'continuous-session-v1-independent-file-seal.json').exists(), 'Await final file seal'
        add('native_continuous_session_independent_files', continuous_independent,
            'File-only independent recorded CPU/fixture full-zone replay; no native mixer handoff or hardware claim.')

    for path in (B+'verification/file-verifier-source-seal.json',
                 A+'audio-session-v2-independent-file-seal.json',
                 *([C+'continuous-session-v1-independent-file-seal.json'] if (ROOT/continuous_independent).exists() else [])):
        d = read(path)
        for field in ('source_sha256','output_sha256','sources'):
            if isinstance(d.get(field), dict):
                register(d[field])
        frozen[path] = sha(path)
    # Completed root attempts and receipts are immutable. Do not enumerate live runtime-v3.
    for directory in ('runtime','runtime-v2','runtime-v3'):
        for p in (ROOT/B/directory).rglob('*'):
            if p.is_file() and '__pycache__' not in p.parts:
                path = str(p.relative_to(ROOT)); frozen[path] = sha(path)
    for path in (B+'terminal-receipt.json', B+'terminal-v2-receipt.json', B+'terminal-v3-receipt.json',
                 B+'verification/file-verification-terminal-receipt.json',
                 B+'gui-static/native-allocation-v3-host-controls-terminal-receipt.json',
                 A+'guest-v1-terminal-tool-receipt.json', A+'guest-v2-terminal-tool-receipt.json',
                 A+'audio-session-v2-independent-verifier-terminal-tool-receipt.json',
                 C+'continuous-session-v3-contract.json', C+'guest-v1-terminal-tool-receipt.json',
                 C+'root-preflight-terminal-tool-receipts.json',
                 'scripts/probe_native_dispatcher_public_heap_allocation_v3.py',
                 B+'runtime-v3/root-launch-and-live-observation-receipt.json'):
        frozen[path] = sha(path)
    frozen[str(Path(__file__).resolve().relative_to(ROOT))] = sha(str(Path(__file__).resolve().relative_to(ROOT)))
    v1 = read(B+'runtime/terminal-metadata.json')
    v2 = read(B+'runtime-v2/terminal-metadata.json')
    v3 = read(B+'runtime-v3/terminal-metadata.json')
    v3_probe = read(B+'runtime-v3/terminal-probe.json')
    v3_allocator = v3_probe['body_actor_observations']['native_allocation_observer']
    assert v3['terminal_exit_code']==1 and v3['actual_exec_chunk']=='61dabd'
    assert v3_probe['registers']['pc']=='0x38806c'
    assert len(v3_allocator['raw_ops'])==1 and v3_allocator['raw_ops'][0]['native_body_returned']
    assert not v3_allocator['two_native_allocations_returned']
    heap_scope = dict(v1_session=87914, v1_terminal_exit=1, v1_actual_chunk='4ab59e',
        original_public_constructor_return_verified=True, original48_or8_native_allocation_success=False,
        v1_native_malloc_frames=0, v1_native_raw_operations=0, v1_host_pointer='0x88246a0',
        v1_inherited24_actual_terminal_after_missing=True,
        v1_metadata=B+'runtime/terminal-metadata.json', v1_metadata_sha256=sha(B+'runtime/terminal-metadata.json'),
        v2_session=24221,v2_terminal_exit=1,v2_actual_chunk='7d85a6',
        v2_original_thunk_executed=True,v2_original2DC954_PUSH_executed=False,v2_host_pointer='0x8400020',
        v2_metadata=B+'runtime-v2/terminal-metadata.json',v2_metadata_sha256=sha(B+'runtime-v2/terminal-metadata.json'),
        v3_session=27241,v3_terminal_exit=1,v3_actual_chunk='61dabd',v3_stop_PC='0x38806c',
        v3_original_malloc_frame_reached=True,v3_original_lock_returned=True,v3_native48_or8_returned=False,
        v3_metadata=B+'runtime-v3/terminal-metadata.json',v3_metadata_sha256=sha(B+'runtime-v3/terminal-metadata.json'))
    assert v1['terminal_exit_code']==v2['terminal_exit_code']==1
    next_attempt=dict(session_id=27241,PID=575848,runner='scripts/probe_native_dispatcher_public_heap_allocation_v3.py',
        runner_sha256=sha('scripts/probe_native_dispatcher_public_heap_allocation_v3.py'),
        observed_live_receipt=B+'runtime-v3/root-launch-and-live-observation-receipt.json',
        observed_live_receipt_sha256=sha(B+'runtime-v3/root-launch-and-live-observation-receipt.json'),
        terminal_receipt=B+'terminal-v3-receipt.json',terminal_receipt_sha256=sha(B+'terminal-v3-receipt.json'),
        status='Authoritative terminal EXIT1 at38806C; new static analysis of page branch in progress; do not poll or restart27241.',
        terminal_exit_code=1,actual_chunk='61dabd',native48_or8_success_not_yet_verified=True,
        observation_is_not_terminal_success=True)
    prefix = B+'verification/native-public-heap-cold-prefix.json'
    details = [
        '原廠 public heap 初始化真正返回；獨立重建1571筆原private／WORK stores及57筆constructor stack stores。這不等於後續原生配置成功。',
        '原廠冷啟動前綴完整通過11 helpers／5boot／24component及字型快取；後段首頁物件仍未完成。',
        '修正第一輪配置證據：返回指標來自舊模擬器服務，原malloc沒有執行。7body／8FP／初始bank及2public區獨立重建；24 inherited區缺少實際terminal after，保留此限制。',
        '第二輪原配置跳板已执行，但下一入口仍被舊Widget模擬服务攔截。45個inherited classes與13個原函式已核對；新版187項純host controls通過，guest結果另記。',
        '第三輪原配置PUSH與底層malloc開始執行、原廠鎖真正返回；在38806C未核對的page／provider分支硬停。原48／8-byte配置仍未返回，失敗與完整cold prefix證據已保留。',
        '新ARM音訊元件經原廠註冊、音源選取與準備，兩次完整讀取共512bytes；音訊逐byte相符，參照保留到原64-byte frame完整返回。',
        '音訊兩案例由獨立純檔案核對5757筆CPU stores／5789筆共同事件；15個RW區與1個不變RX sentinel完整重建，沒有重跑guest。',
        '持續音訊改用固定session身分，與每批可重用FIFO ticket分開；25項HOST控制及零undefined的ARM映像通過。',
        '新增三組真ARM案例：同一原音源接收12批512-byte資料、24次完整讀取；暫時缺資料輸出靜音後可續播；本地Stop拒絕新提交和新讀取。輸出混音ring的consumer仍為明示fixture。',
        '原廠混音器TCB、跨執行緒音源交接及2FA572／2FA536兩條完整讀取接線尚未完成；獨占witness仍為−200，native STOP_DONE、實機App與手機直連音樂仍未達成。',
    ]
    if (ROOT/continuous_independent).exists():
        details.append('持續音訊三案例另由純檔案獨立重建CPU／fixture事件與最終記憶體；不把模擬服務或離線成功當成實機播放。')
    manifest=dict(updated_utc=datetime.now(timezone.utc).isoformat(),frozen_files_sha256=frozen,
        findings=findings,new_complete_cold_suites=[dict(path=prefix,sha256=sha(prefix),case_count=1,
            scope='Complete original cold prefix; later malloc body encountered inherited host allocation and failed.')],
        heap_terminal_scope=heap_scope,next_heap_attempt=next_attempt,
        parallel_research=dict(live_subagent_count=2,agents_currently_running=True,
            completed_agent_task='continuous-session independent file verification',
            active_agent_tasks=['original mixer TCB and full-return handoff prototype',
                                'original malloc private-page/MMU mapping next-scope analysis'],
            continued_round_completed=False,root_owns_runtime_and_publication=True),
        public_details=details)
    output.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(all_passed=True,findings=len(findings),new_frozen_files=len(frozen),public_details=len(details))))

if __name__=='__main__':
    main()
