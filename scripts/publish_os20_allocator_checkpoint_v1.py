#!/usr/bin/env python3
"""Publish a bounded stock allocator/create-prefix result, not complete App."""
import hashlib
import html
import importlib.util
import json
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('helpers', ROOT / 'scripts/publish_native_warm_probe_checkpoint_v1.py')
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
read, sha, create, write = P.read, P.sha, P.create, P.write
OLD = 'evidence/firmware-analysis/garminos-trace-compaction-checkpoint-audit.json'
OUT = 'evidence/firmware-analysis/native-os20-allocator-checkpoint-audit.json'
B = 'staging/native-os20-allocator-checkpoint-v1/'
G = 'staging/native-os20-allocator-v2/'
C = 'native/os20-task-bridge/allocator-contract-v1.json'


def main():
    assert not (ROOT / OUT).exists() and not (ROOT / B).exists()
    old, guest, files, contract = [read(p) for p in
        (OLD, G + 'guest-proof.json', G + 'ROOT_FILE-proof-v1.json', C)]
    assert all(d['all_passed'] for d in (old, guest, files, contract))
    assert old['current_findings'] == 301 and old['current_public_details'] == 285
    assert len(old['protected_sources']) == 4671 and guest['case_count'] == files['case_count'] == 3
    assert files['totals'] == dict(CPU_stores=4273, store_effective_addresses=4273,
                                  whole_zones=30, instructions=6470, native_full_returns=34, boundaries=3)
    for path, code in [('staging/native-os20-allocator-v1/terminal-tool-receipt.json', 1),
                       (G + 'terminal-tool-receipt.json', 0), (G + 'FILE-v1-terminal-tool-receipt.json', 0)]:
        result = read(path)['actual_terminal_result']
        assert result['exit_code'] == code and 'session_id' not in result
    assert all(sha(path) == h for path, h in old['canonical_after_sha256'].items())
    protected, focused = dict(old['protected_sources']), {}

    def register(path, expected=None):
        actual = sha(path)
        assert expected is None or expected == actual, path
        assert path not in protected or protected[path] == actual, path
        protected[path] = actual
        focused[path] = actual

    for data in (guest, files, contract):
        for path, h in data['source_sha256'].items():
            register(path, h)
    for directory in ('staging/native-os20-allocator-v1/', G):
        for path in sorted((ROOT / directory).rglob('*')):
            if path.is_file():
                register(str(path.relative_to(ROOT)))
    for path in (C, OLD, 'scripts/probe_os20_allocator_v1.py', 'scripts/probe_os20_allocator_v2.py',
                 'scripts/verify_os20_allocator_files_v1.py', 'scripts/publish_os20_allocator_checkpoint_v1.py',
                 'staging/garminos-trace-compaction-checkpoint-v1/publication-terminal-tool-receipt.json',
                 'staging/garminos-trace-compaction-checkpoint-v1/fresh-live-readback.json'):
        register(path)
    state, task, public = [read(path) for path in P.CANONICAL[:3]]
    app, progress = state['native_app_music'], public['research_progress']
    assert state['goal_status'] == 'active' and not state['goal_complete'] and state['required_work_remaining']
    assert len(app['static_findings']) == 301 and len(progress['completed']) == 285
    assert not app['native_app_running'] and not app['direct_phone_music_verified']
    latest, service = read('evidence/report-web-latest.json'), P.service_now()
    with urllib.request.urlopen(urllib.request.Request(latest['url'], headers={'Cache-Control': 'no-cache'}), timeout=10) as response:
        before = response.read()
        assert response.status == 200 and 'no-store' in response.headers.get('Cache-Control', '')
    assert hashlib.sha256(before).hexdigest() == sha(P.CANONICAL[3])
    (ROOT / B).mkdir()
    snapshots = []
    for original, name in [(OLD, 'previous-audit.json'), ('evidence/report-web-latest.json', 'previous-web.json')] + list(zip(
            P.CANONICAL, ['previous-state.json', 'previous-task.json', 'previous-public.json', 'previous-report.html'])):
        path = B + name
        with (ROOT / path).open('xb') as stream:
            stream.write((ROOT / original).read_bytes())
        register(path)
        snapshots.append(dict(original=original, snapshot=path, sha256=sha(path)))
    findings = [
        ('native_os20_allocator_veneer_ABI', C,
         'Exact ARM veneers point to stock calloc and malloc wrappers. Default word F070B0 is allocation policy0, not a heap pointer. Raw allocator and descriptor query share the earlier GUI allocator. NULL/nonreturn guarantee, overflow and physical heap remain unverified.'),
        ('native_os20_two_allocations_new_software_heap', G + 'guest-proof.json',
         'NEW private32KiB/public64KiB inputs initialized by unchanged original code. Stock OS20 create prefix successfully allocates and clears100bytes plus uninitialized4248byte workspace. Original pagepop and software mapping run; current TCB/tables/storage are declared fixtures. Stop before original task-object constructor, no task or callback execution.'),
        ('native_os20_allocator_ROOT_FILE_EA_replay', G + 'ROOT_FILE-proof-v1.json',
         '4273 exact original store effective addresses and source-register values,30 whole zones,6470 instructions and34 helper ABI returns checked. Two completed EXIT1 prefix scopes retained without rerun; failed one-page prediction corrected in separate scope. Diagnostic bodies unexecuted; not independent agent or full nonstore semantic replay.')]
    for key, path, scope in findings:
        assert key not in app['static_findings']
        app['static_findings'][key] = dict(evidence=path, evidence_sha256=sha(path), scope=scope,
            evidence_type='ROOT bounded native-code and FILE evidence', device_io=False, physical_App_or_audio_verified=False)
    details = [
        '原OS20的ARM配置跳板已核對：395440進入原calloc，39544C與先前GUI的3954CC共同進入原malloc。F070B0保存預設配置政策0，不是heap指標；兩者都經原配置器與descriptor查詢。原建立本體沒有先检查空配置，配置失敗會進原診斷路徑，但診斷本體是否不返回及安全NULL保證仍未確認。',
        '新的明示私有32KiB／公開64KiB模型，完全由原heap／list初始化建立欄位與自由頁，沒有手填WORK或free-head。原OS20建立前段實際取得100bytes且逐byte清零的descriptor，以及4248bytes未清零workspace；兩者對齊且不重疊。相關配置鎖已釋放，停在521E90、尚未呼叫工作物件建構器2FCD0A；沒有新task或App執行。',
        '原pagepop完整返回三次：descriptor頁與兩個後續private頁都由原自由鏈取出。原mapping與IRQ／cache／TLB函式執行，四個原L2 stores按實際頁返回值重建；MMU保持關閉、L1/L2與current TCB是明示輸入，public資料亦已由測試模型提供，不能視為真實RAM或MMU映射可用。',
        '缺少公開extent時，原allocator抵達診斷；只有4096byte私有extent則更早被原初始化的剩餘extent檢查拒絕。首版錯預測會到pagepop，因此第三情境未finalize；前兩個已完成EXIT1 prefix保留不重跑，只重新完成第三控制。FILE核對4273個CPUstore地址和值、30完整區域、34 helper ABI返回及6470條指令。所有紀錄用gzip，沒有新增MAIN副本。']
    now = datetime.now(timezone.utc)
    focus = ('Stock OS20 allocator prefix returned descriptor100/workspace4248 over NEW declared heap and software tables. '
             'Next recover2FCD0A/2FCCCE object construction and arg5 semantics, then legal native TCB/root and GUI readiness. '
             'Physical CPU/MMU/heap, resident ownership, menu/direct phone A2DP still open. Pairing FIRST; original full goal active.')
    next_text = '接著恢復2FCD0A／2FCCCE工作物件建構與參數5的意義，再接原TCB建立、root callback及GUI就緒流程。新模型配置成功不代表實機heap；只讀CPU診斷現場回覆仍待確認，原生App、正常音訊所有權和手機直接A2DP繼續研究。'
    old_next = progress['phases'][4]['next']
    state.update(updated_utc=now.isoformat(), current_priority=focus)
    state['next_actions'] = [focus,
        'Preserve original failed8KiB GUI allocation scope; new isolated32KiB/public64KiB test is not the old full Dispatcher boot or physical RAM proof.',
        'Optional prepared CPU diagnostic availability question remains unanswered; reuse exact reversible voice installer when real USB is available. No repeat question.',
        'Continue native task and music ownership/lifetime, actual menu/App and direct A2DP; microphone canceled, fidelity deferred, Android Auto later, Maps deferred.',
        'Keep sole backup image and read-only compressed old traces; gzip new evidence and never overwrite frozen shared inputs.']
    app['remaining_work'] = state['next_actions'][:4]
    app['development_observations']['OS20_allocator_new_software_heap'] = dict(
        contract=C, guest=G + 'guest-proof.json', ROOT_FILE=G + 'ROOT_FILE-proof-v1.json', totals=files['totals'],
        original_two_allocation_returns=True, isolated_new_input_not_old_full_GUI_boot=True,
        original_task_object_constructor_executed=False, original_TCB_root_or_App_executed=False,
        physical_CPU_or_MMU_or_heap_verified=False)
    state['last_goal_turn'].update(
        classification='progress', previous_goal_turn_classification='progress', validated_utc=now.isoformat(),
        previous_state_snapshot=B + 'previous-state.json', previous_current_audit_snapshot=B + 'previous-audit.json',
        focused_evidence=G + 'ROOT_FILE-proof-v1.json', focused_evidence_sha256=sha(G + 'ROOT_FILE-proof-v1.json'),
        next_focus=focus, reasons=[finding[2] for finding in findings],
        device_IO=False, device_io=False, device_files_written=False, physical_CPU_identified=False,
        complete_native_App_or_phone_audio=False, goal_status='active', full_goal_complete=False)
    for key in ('updated_utc', 'current_priority', 'next_actions', 'last_goal_turn'):
        task[key] = state[key]
    public.update(updated=now.isoformat(), deep_research=state)
    progress['completed'].extend(details)
    progress['phases'][4]['completed'].extend(details)
    progress['phases'][4]['next'] = next_text
    progress.update(research_updated_utc=now.isoformat(), next=next_text)
    assert len(app['static_findings']) == 304 and len(progress['completed']) == 289
    assert progress['estimate_percent'] == 37 and progress['phases'][4]['estimate_percent'] == 35
    card = ('<div class="card"><h2>最新進展：原廠OS20配置前段已在新模型通過</h2><p>'
            '原工作建立前段已實際配置100bytes清零descriptor與4248bytes未清零workspace，相關鎖已釋放。'
            '新的私有32KiB／公開64KiB輸入由原初始化建立自由頁，沒有手填WORK或free-head。'
            '<strong>停在下一個工作物件建構呼叫之前；尚未建立新task或執行播放器。</strong></p><p>'
            '缺少公開extent與只有一頁私有extent均抵達原診斷路徑，後者比原先預測更早被初始化檢查拒絕。'
            'FILE核對4273個store的地址和值、30個完整區域、34次原helper返回及6470條指令。'
            '已完成的首版兩個prefix情境保留不重跑，只補完失敗控制。</p><p>'
            '原頁pop與software mapping實際執行，但MMU關閉、TCB／表格／資料storage為模型輸入，'
            '不能當作實機RAM或hardware mapping證明。下一步恢復工作物件、TCB與GUI就緒流程；'
            'CPU診斷待現場回覆，原語音2.10保持還原。整體37%、App35%；本轮沒有實機操作或MAIN副本。</p></div>')
    report, count = re.subn(r'<div class="card"><h2>最新進展：原廠OS20工作橋接路徑</h2>.*?</div>',
                          lambda _: card, before.decode(), count=1, flags=re.S)
    assert count == 1
    old_row = '<tr><td>原生 App 入口與功能整合</td><td>35%</td><td>' + html.escape(old_next) + '</td></tr>'
    assert report.count(old_row) == 1
    report = report.replace(old_row, '<tr><td>原生 App 入口與功能整合</td><td>35%</td><td>' + html.escape(next_text) + '</td></tr>', 1)
    report, count = re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',
        lambda match: match[1] + match[2] + ''.join('<li>' + html.escape(d) + '</li>' for d in details) + match[3],
        report, count=1, flags=re.S)
    assert count == 1
    report, count = re.subn(r'<p><strong>下一步：</strong>.*?</p>',
        lambda _: '<p><strong>下一步：</strong>' + html.escape(next_text) + '</p>',
        report, count=1, flags=re.S)
    assert count == 1
    # Preserve the CPU question and prepared reversible physical candidate.
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    iso = local.isoformat(timespec='seconds')
    for name in ('report-updated-time', 'research-updated-time'):
        report, count = re.subn(r'<time id="' + name + r'" datetime="[^"]+">[^<]+</time>',
            '<time id="' + name + '" datetime="' + iso + '">' + local.strftime('%Y/%m/%d %H:%M:%S') + '</time>',
            report, count=1)
        assert count == 1
    assert 'REDACTED_PRIVATE_ID' not in report and not re.search(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b', report)
    for row in snapshots:
        assert sha(row['original']) == row['sha256']
    create(B + 'publication-inputs.json', dict(all_passed=True, protected_sources=protected,
        focused_sources=focused, prior4671_sources_inherited_not_fresh_full_rehash=True,
        new_findings=findings, details=details, guest_rerun=False, device_IO=False))
    register(B + 'publication-inputs.json')
    for path, data in zip(P.CANONICAL[:3], (state, task, public)):
        write(path, data)
    (ROOT / P.CANONICAL[3]).write_text(report)
    after = {path: sha(path) for path in P.CANONICAL}
    with urllib.request.urlopen(urllib.request.Request(latest['url'], headers={'Cache-Control': 'no-cache'}), timeout=10) as response:
        served = response.read()
        assert response.status == 200 and 'no-store' in response.headers.get('Cache-Control', '')
    assert served == report.encode() and P.service_now() == service
    audit = dict(old, all_passed=True, updated_utc=now.isoformat(), previous_checkpoint=B + 'previous-audit.json',
        protected_sources=protected, canonical_after_sha256=after, current_state_sha256=after[P.CANONICAL[0]],
        report_sha256=after[P.CANONICAL[3]], local_report_sha256=after[P.CANONICAL[3]], served_report_sha256=after[P.CANONICAL[3]],
        current_findings=304, current_public_details=289, current_focused_sources_sha256=focused,
        prior_full_source_rehash_repeated_this_turn=False, publisher_second_full_source_rehash_claimed=False,
        OS20_new_software_allocator_totals=files['totals'],
        actual_OS20_allocator_prefix_executed_in_declared_new_input=True,
        actual_task_object_constructor_or_native_TCB_or_root_callback_executed=False,
        physical_heap_or_MMU_mapping_or_CPU_identified=False,
        scope_checks=dict(old['scope_checks'], OS20_allocator_NEW_input_not_old_GUI_boot=True,
                          two_allocation_full_returns_not_task_or_App=True, all4273_store_EA_values_FILE_checked=True,
                          synthetic_TCB_and_L1_L2_not_hardware=True, failed_prefix_scopes_preserved=True))
    create(OUT, audit)
    assert latest.pop('current_garmin_trace_compaction_checkpoint') == OLD
    latest.setdefault('historical_offline_checkpoint_audits', {})['prior_garmin_trace_compaction_checkpoint'] = dict(
        audit=B + 'previous-audit.json', audit_sha256=sha(B + 'previous-audit.json'), all_passed=True)
    latest.update(updated_utc=now.isoformat(), current_native_os20_allocator_checkpoint=OUT,
        checkpoint_sha256={OUT: sha(OUT)}, local_report_sha256=after[P.CANONICAL[3]], served_report_sha256=after[P.CANONICAL[3]],
        report_bytes=len(served), served_latest_report=True, canonical_hash_readback_uncached=True, service_not_restarted=True)
    latest['progress_display_verified'].update(completed_items=289, report_updated_time=iso,
        research_updated_time=iso, OS20_new_allocator_prefix_scope_visible=True)
    write('evidence/report-web-latest.json', latest)
    print(json.dumps(dict(all_passed=True, findings=304, details=289, protected_sources=len(protected),
        report_sha256=after[P.CANONICAL[3]], report_bytes=len(served), updated_Taiwan=iso,
        goal_status='active', device_IO=False)), flush=True)


if __name__ == '__main__':
    main()
