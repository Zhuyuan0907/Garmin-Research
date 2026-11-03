#!/usr/bin/env python3
"""Publish the original named-create/POST result with boot and App limits."""
import gzip
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
OLD = 'evidence/firmware-analysis/garminos-storage-followup-checkpoint-audit.json'
OUT = 'evidence/firmware-analysis/native-os20-create-checkpoint-audit.json'
B = 'staging/native-os20-create-checkpoint-v1/'
C = 'native/os20-task-bridge/create-contract-v2.json'
F = 'staging/native-os20-create-file-v1/ROOT_FILE-proof-v1.json'
DIRECTORIES = ['staging/native-os20-create-continuation-v1/', 'staging/native-os20-create-continuation-v2/',
    'staging/native-os20-create-continuation-v3/', 'staging/native-os20-create-finish-v1/',
    'staging/native-os20-create-finish-v2/', 'staging/native-os20-create-file-v1/']


def served(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers={'Cache-Control': 'no-cache'}), timeout=10) as r:
        body = r.read()
        assert r.status == 200 and 'no-store' in r.headers.get('Cache-Control', '')
        return body


def main():
    assert not (ROOT / B).exists() and not (ROOT / OUT).exists()
    old, files, contract = [read(p) for p in (OLD, F, C)]
    assert all(d['all_passed'] for d in (old, files, contract))
    assert old['current_findings'] == 305 and old['current_public_details'] == 291
    assert len(old['protected_sources']) == 4714
    assert files['totals'] == dict(CPU_stores=1676, store_effective_addresses=1676,
        whole_zones=24, instructions=3403, native_full_returns=7)
    assert contract['original_create_full_ABI_return'] and not contract['actual_root_and_user_callback_executed']
    assert contract['current_TCB_is_still_synthetic'] and not contract['physical_native_App_verified']
    for base, code in zip(DIRECTORIES, (1, 1, 0, 1, 0, 0)):
        receipt = read(base + 'terminal-tool-receipt.json')['actual_terminal_result']
        assert receipt['exit_code'] == code and 'session_id' not in receipt
    assert all(sha(p) == h for p, h in old['canonical_after_sha256'].items())
    protected, focused = dict(old['protected_sources']), {}

    def register(path, expected=None):
        actual = sha(path)
        assert expected is None or expected == actual, path
        assert path not in protected or protected[path] == actual, path
        protected[path] = actual
        focused[path] = actual

    for d in (files, contract):
        for p, h in d['source_sha256'].items():
            register(p, h)
    for directory in DIRECTORIES:
        for p in sorted((ROOT / directory).iterdir()):
            if p.is_file():
                register(str(p.relative_to(ROOT)))
    for p in [C, OLD, 'scripts/continue_os20_create_v1.py', 'scripts/continue_os20_create_v2.py',
              'scripts/continue_os20_create_v3.py', 'scripts/finish_os20_create_v1.py',
              'scripts/finish_os20_create_v2.py', 'scripts/verify_os20_create_files_v1.py',
              'scripts/publish_os20_create_checkpoint_v1.py',
              'staging/garminos-storage-followup-checkpoint-v1/publication-terminal-tool-receipt.json',
              'staging/garminos-storage-followup-checkpoint-v1/fresh-live-readback.json']:
        register(p)
    state, task, public = [read(p) for p in P.CANONICAL[:3]]
    app, progress = state['native_app_music'], public['research_progress']
    assert state['goal_status'] == 'active' and not state['goal_complete'] and state['required_work_remaining']
    assert not app['native_app_running'] and not app['direct_phone_music_verified']
    assert len(app['static_findings']) == 305 and len(progress['completed']) == 291
    old_next = progress['phases'][4]['next']
    latest, service = read('evidence/report-web-latest.json'), P.service_now()
    prior = served(latest['url'])
    assert hashlib.sha256(prior).hexdigest() == sha(P.CANONICAL[3])
    (ROOT / B).mkdir()
    snapshots = []
    for original, name in [(OLD, 'previous-audit.json'), ('evidence/report-web-latest.json', 'previous-web.json')] + list(zip(
            P.CANONICAL, ['previous-state.json', 'previous-task.json', 'previous-public.json', 'previous-report.html'])):
        path, payload = B + name + '.gz', (ROOT / original).read_bytes()
        with (ROOT / path).open('xb') as f:
            with gzip.GzipFile(filename='', mode='wb', fileobj=f, mtime=0, compresslevel=6) as z:
                z.write(payload)
        assert gzip.decompress((ROOT / path).read_bytes()) == payload
        register(path)
        snapshots.append(dict(original=original, snapshot=path, encoding='gzip',
            decoded_sha256=hashlib.sha256(payload).hexdigest()))
    findings = [
        ('native_os20_name_parameter_and_conversion_corrected', C,
         'Arg5 is a valid NUL-terminated name pointer. Original2FCD0A/2FCCCE convert CP1252 into observed UTF16LE; not a generic work-object constructor. NULL name previously faulted in native strlen. NEW short name input explicit, only final two argument loads repeated, completed allocation prefix untouched.'),
        ('native_os20_create_TCB_registry_POST_full_return', C,
         'Original358BF8 built108byte TCB and52byte compact frame. Native descriptor registry and64byte adapter publication completed. Original POST inserted ready task, create returned adapter with ABI preserved. Current TCB remains synthetic, index0 priority240, no preemption/root callback/player or physical App execution.'),
        ('native_os20_create_FILE_store_and_snapshot_replay', F,
         '1676 original CPU-store addresses/values,24 whole zones,3403 instructions and7 helper full ABI returns verified from captured bytes. Explicit name inputs and exact parent restoration reviewed. No guest rerun, full nonstore interpreter or new independent agent; physical heap/MMU and boot ownership remain unknown.')
    ]
    for key, path, scope in findings:
        assert key not in app['static_findings']
        app['static_findings'][key] = dict(evidence=path, evidence_sha256=sha(path), scope=scope,
            evidence_type='ROOT bounded original create and FILE evidence', device_io=False,
            physical_App_or_audio_verified=False)
    historical = app['static_findings']['native_os20_two_allocations_new_software_heap']
    historical['scope'] = historical['scope'].replace('original task-object constructor', 'original name-conversion call')
    historical['scope_correction_reference'] = C
    details = [
        '更正原工作建立第五個參數：它是CP1252名稱指標，2FCD0A／2FCCCE是字串轉換。原程式已把Garmin Music轉為UTF-16LE，放到descriptor+60；先前NULL名稱造成原strlen讀取失敗，屬模型輸入不完整。',
        '沿用已驗證配置結果，只補名稱輸入並重新執行最後兩條參數載入；原358BF8建立108-byte TCB及52-byte compact frame，原descriptor登記和OS20回呼／參數record寫入完成。',
        '另從POST前接續執行原2FCF44；新工作狀態變ready、插入current後面，原create完整返回64-byte適配record。current仍是合成輸入、priority索引0為240；沒有preemption、root回呼或播放器執行，不能當實機App成功。',
        'FILE由原指令和pre-GP核對1676個store地址／值、24個完整區域、3403條指令及7次helper ABI返回；三個未完成嘗試的失敗來源與紀錄保留，完成範圍沒有重跑。新增ARM32 C宣告只通過語法／offset檢查。'
    ]
    next_text = '接著由原核心建立合法controller，透過原POST／WAIT／restore切入521E44 root，核對實際編譯回呼及參數，再接播放器與GUI所有權／退出流程。完整boot、實機CPU／heap／MMU及手機直接A2DP仍待驗證；現場配對第一優先。'
    now = datetime.now(timezone.utc)
    state.update(updated_utc=now.isoformat(), current_priority=
        'Original OS20 named create now completes native TCB/registry/adapter/POST and full ABI return in declared software heap. Next construct a real controller and reach original root/compiled worker through POST/WAIT/restore, then GUI/audio ownership and physical loading. Existing current remains synthetic, no task execution. Pairing FIRST; full goal active.')
    state['latest_user_instruction'] = 'Continue original native App/music research after completed user-authorized storage cleanup; Android Auto later and Maps deferred, full original scope retained.'
    state['next_actions'][0] = state['current_priority']
    app['original_OS20_named_create_complete_offline'] = dict(contract=C, FILE=F,
        native_new_TCB_created=True, native_descriptor_and_adapter_registered=True,
        original_POST_and_create_complete_return=True, original_queue_insertion=True,
        name_conversion_not_generic_constructor=True, valid_name_argument_required=True,
        existing_current_TCB_synthetic=True, original_root_or_user_callback_executed=False,
        native_boot_or_physical_heap_or_App_verified=False, totals=files['totals'])
    state['last_goal_turn'].update(classification='progress', previous_goal_turn_classification='progress',
        validated_utc=now.isoformat(), previous_state_snapshot=B + 'previous-state.json.gz',
        previous_current_audit_snapshot=B + 'previous-audit.json.gz', snapshot_encoding='gzip',
        focused_evidence=F, focused_evidence_sha256=sha(F), reasons=[scope for _, _, scope in findings],
        device_IO=False, device_io=False, device_files_written=False, goal_status='active', full_goal_complete=False)
    for name in ('updated_utc', 'latest_user_instruction', 'current_priority', 'next_actions', 'last_goal_turn'):
        task[name] = state[name]
    public.update(updated=now.isoformat(), deep_research=state)
    progress['completed'].extend(details)
    progress['phases'][4]['completed'].extend(details)
    progress['phases'][4]['next'] = next_text
    progress['research_updated_utc'] = now.isoformat()
    assert len(app['static_findings']) == 308 and len(progress['completed']) == 295
    assert progress['estimate_percent'] == 37 and progress['phases'][4]['estimate_percent'] == 35
    card = ('<div class="card"><h2>最新進展：原廠OS20建立工作已完整返回</h2><p>'
        '原建立流程已完成名稱轉換、108-byte TCB及52-byte context frame、descriptor登記、'
        '64-byte OS20適配record與原POST喚醒。原create完整返回，callee-saved registers及SP保持。'
        '<strong>此為離線模型；新工作尚未被排程執行，也尚未在車機上運行播放器。</strong></p><p>'
        '第五個參數是工作名稱指標；先前暫稱工作物件建構的2FCD0A／2FCCCE實際是字串轉換。'
        'Garmin Music已由原程式轉為UTF-16LE，NULL名稱則在原strlen失敗，屬測試輸入不完整。'
        '沿用配置結果，只重載兩條參數指令；已完成配置與TCB範圍未重跑。</p><p>'
        'FILE核對1676個store地址和值、24個完整區域、3403條指令及7次helper返回。'
        'current仍是合成TCB、MMU關閉；索引0priority240使新工作排在current之後，沒有切換。'
        '下一步建立合法controller，經原POST／WAIT／restore進入root與播放器回呼，處理GUI及音訊生命週期。'
        '原語音2.10保持還原，CPU診斷待既有現場回覆。整體37%、App35%；沒有USB、藍牙或音訊操作。</p></div>')
    report, count = re.subn(r'<div class="card"><h2>最新進展：原廠OS20配置前段已在新模型通過</h2>.*?</div>',
        lambda _: card, prior.decode(), count=1, flags=re.S)
    assert count == 1
    old_row = '<tr><td>原生 App 入口與功能整合</td><td>35%</td><td>' + html.escape(old_next) + '</td></tr>'
    assert report.count(old_row) == 1
    report = report.replace(old_row, '<tr><td>原生 App 入口與功能整合</td><td>35%</td><td>' + html.escape(next_text) + '</td></tr>', 1)
    report, count = re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',
        lambda m: m[1] + m[2] + ''.join('<li>' + html.escape(d) + '</li>' for d in details) + m[3],
        report, count=1, flags=re.S)
    assert count == 1
    report, count = re.subn(r'<p><strong>下一步：</strong>.*?</p>',
        lambda _: '<p><strong>下一步：</strong>' + html.escape(next_text) + '</p>', report, count=1, flags=re.S)
    assert count == 1
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    iso = local.isoformat(timespec='seconds')
    for name in ('report-updated-time', 'research-updated-time'):
        report, count = re.subn(r'<time id="' + name + r'" datetime="[^"]+">[^<]+</time>',
            '<time id="' + name + '" datetime="' + iso + '">' + local.strftime('%Y/%m/%d %H:%M:%S') + '</time>', report, count=1)
        assert count == 1
    assert 'REDACTED_PRIVATE_ID' not in report and not re.search(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b', report)
    for row in snapshots:
        assert sha(row['original']) == row['decoded_sha256']
    create(B + 'publication-inputs.json', dict(all_passed=True, previous_checkpoint=OLD,
        snapshots=snapshots, focused_sources=focused, prior4714_sources_inherited_not_fresh_full_rehash=True,
        findings=findings, details=details, guest_rerun=False, device_IO=False))
    register(B + 'publication-inputs.json')
    for p, d in zip(P.CANONICAL[:3], (state, task, public)):
        write(p, d)
    (ROOT / P.CANONICAL[3]).write_text(report)
    after = {p: sha(p) for p in P.CANONICAL}
    assert read(P.CANONICAL[0]) == state and read(P.CANONICAL[1]) == task and read(P.CANONICAL[2]) == public
    body = served(latest['url'])
    assert body == report.encode() and P.service_now() == service
    audit = dict(old, all_passed=True, updated_utc=now.isoformat(), previous_checkpoint=OLD,
        previous_canonical_snapshots=snapshots, protected_sources=protected,
        canonical_after_sha256=after, current_state_sha256=after[P.CANONICAL[0]],
        report_sha256=after[P.CANONICAL[3]], local_report_sha256=after[P.CANONICAL[3]], served_report_sha256=after[P.CANONICAL[3]],
        current_findings=308, current_public_details=295, current_focused_sources_sha256=focused,
        prior_full_source_rehash_repeated_this_turn=False, native_OS20_create_totals=files['totals'],
        original_named_create_TCB_registry_POST_complete_return_offline=True,
        original_task_object_constructor_or_native_TCB_or_root_callback_executed=False,
        generic_task_object_constructor_label_corrected=True, native_TCB_constructor_executed=True,
        original_root_or_user_callback_executed=False,
        current_TCB_or_boot_hardware_heap_or_App_verified=False,
        scope_checks=dict(old['scope_checks'], name_argument_and_NULL_failure_scope_corrected=True,
            original_new_TCB_and_create_return_not_task_execution=True, exact_parent_and_new_name_inputs_preserved=True,
            all1676_store_EA_values_FILE_checked=True, full_original_POST_return_and_ready_queue_inserted=True,
            old_successful_allocation_and_TCB_scopes_not_rerun=True, full_goal_and_physical_limits_preserved=True))
    # The old combined flag encoded three different claims. Retain its
    # historical meaning in a named record and expose separate current facts.
    audit.pop('original_task_object_constructor_or_native_TCB_or_root_callback_executed', None)
    audit.pop('actual_task_object_constructor_or_native_TCB_or_root_callback_executed', None)
    create(OUT, audit)
    assert latest.pop('current_garmin_storage_followup_checkpoint') == OLD
    latest.setdefault('historical_offline_checkpoint_audits', {})['prior_garmin_storage_followup_checkpoint'] = dict(
        audit=OLD, audit_sha256=sha(OLD), all_passed=True)
    latest.update(updated_utc=now.isoformat(), current_native_os20_create_checkpoint=OUT,
        checkpoint_sha256={OUT: sha(OUT)}, local_report_sha256=after[P.CANONICAL[3]],
        served_report_sha256=after[P.CANONICAL[3]], report_bytes=len(body),
        service_not_restarted=True, served_latest_report=True, canonical_hash_readback_uncached=True)
    latest['progress_display_verified'].update(completed_items=295, report_updated_time=iso,
        research_updated_time=iso, original_named_create_and_POST_return_scope_visible=True)
    write('evidence/report-web-latest.json', latest)
    print(json.dumps(dict(all_passed=True, findings=308, details=295,
        protected_sources=len(protected), report_sha256=after[P.CANONICAL[3]], report_bytes=len(body),
        updated_Taiwan=iso, original_create_complete_return=True, task_execution=False,
        goal_status='active', device_IO=False)), flush=True)


if __name__ == '__main__':
    main()
