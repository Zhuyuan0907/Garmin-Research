#!/usr/bin/env python3
"""Publish measured, completed space recovery without changing research scope."""
import hashlib
import html
import importlib.util
import json
import re
import shutil
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    'report_helpers', ROOT / 'scripts/publish_native_warm_probe_checkpoint_v1.py')
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
read, sha, create, write = P.read, P.sha, P.create, P.write
G = 'staging/garminos-trace-compaction-v1/'
B = 'staging/garminos-trace-compaction-checkpoint-v1/'
OLD = 'evidence/firmware-analysis/native-os20-task-index-checkpoint-audit.json'
OUT = 'evidence/firmware-analysis/garminos-trace-compaction-checkpoint-audit.json'


def main():
    assert not (ROOT / B).exists() and not (ROOT / OUT).exists()
    old = read(OLD)
    result = read(G + 'compaction-result.json')
    receipt = read(G + 'terminal-tool-receipt.json')['actual_terminal_result']
    post = read(G + 'post-compaction-live-verification.json')
    assert receipt['exit_code'] == 0 and 'session_id' not in receipt
    assert old['all_passed'] and old['current_findings'] == 300
    assert old['current_public_details'] == 283 and len(old['protected_sources']) == 4654
    assert result['all_passed'] and post['all_passed']
    assert result['selected_files'] == 88 and result['protected_sources_freshly_verified'] == 4654
    assert result['original_paths_preserved'] and result['original_file_contents_unchanged']
    assert result['original_backup_sha256_verified'] and result['freed_bytes'] > 4_000_000_000
    assert not result['device_IO']
    assert sha(result['archive']) == result['archive_sha256']
    assert all(sha(p) == h for p, h in old['canonical_after_sha256'].items())
    protected = dict(old['protected_sources'])
    focused = {}

    def register(path):
        actual = sha(path)
        assert path not in protected or protected[path] == actual, path
        protected[path] = actual
        focused[path] = actual

    # The terminal compaction actor freshly checked all 4654 old sources.
    # Register new evidence here; do not claim a second whole-registry pass.
    for path in sorted((ROOT / G).rglob('*')):
        if path.is_file():
            register(str(path.relative_to(ROOT)))
    for path in (OLD, 'scripts/compact_frozen_traces_v1.py',
                 'scripts/publish_trace_compaction_checkpoint_v1.py', result['archive']):
        register(path)
    state, task, public = [read(path) for path in P.CANONICAL[:3]]
    app = state['native_app_music']
    progress = public['research_progress']
    latest = read('evidence/report-web-latest.json')
    service = P.service_now()
    assert state['goal_status'] == 'active' and not state['goal_complete']
    assert state['required_work_remaining'] and not app['native_app_running']
    assert len(app['static_findings']) == 300 and len(progress['completed']) == 283
    with urllib.request.urlopen(urllib.request.Request(
            latest['url'], headers={'Cache-Control': 'no-cache'}), timeout=10) as response:
        before = response.read()
        assert response.status == 200 and 'no-store' in response.headers.get('Cache-Control', '')
    assert hashlib.sha256(before).hexdigest() == sha(P.CANONICAL[3])
    (ROOT / B).mkdir()
    snapshots = []
    for original, name in [(OLD, 'previous-audit.json'),
                           ('evidence/report-web-latest.json', 'previous-web.json')] + list(zip(
                               P.CANONICAL, ['previous-state.json', 'previous-task.json',
                                             'previous-public.json', 'previous-report.html'])):
        target = B + name
        with (ROOT / target).open('xb') as stream:
            stream.write((ROOT / original).read_bytes())
        register(target)
        snapshots.append(dict(original=original, snapshot=target, sha256=sha(target)))
    freed_gb = result['freed_bytes'] / 1_000_000_000
    free_gb = post['free_bytes'] / 1_000_000_000
    total_freed = state['storage_cleanup']['freed_bytes'] + result['freed_bytes']
    details = [
        f'再整理88份已凍結的大型JSON測試紀錄：以無損壓縮唯讀檔案系統保存，逐檔SHA-256核對後才移除未壓縮副本。原路徑仍能直接讀取，內容不變，本輪實際釋放{freed_gb:.2f}GB。',
        f'重新核對全部4654個舊保護來源及唯一完整備份sda.img雜湊；保留可編輯程式與不同測試結果。壓縮視圖設為開機自動掛載，報告及VS Code下載服務保持運行。目前可用約{free_gb:.2f}GB；清理工作不增加App研究完成百分比。'
    ]
    key = 'garminos_frozen_trace_lossless_compaction'
    assert key not in app['static_findings']
    app['static_findings'][key] = dict(
        evidence=G + 'compaction-result.json', evidence_sha256=sha(G + 'compaction-result.json'),
        scope='88 frozen large JSON files losslessly compressed, exact old paths remain readable. '
              'All4654 prior protected source hashes and sole complete original disk image freshly '
              'verified by terminal actor. Editable sources and distinct results retained; no device I/O.',
        evidence_type='ROOT actual filesystem compaction evidence', device_io=False,
        physical_App_or_audio_verified=False)
    now = datetime.now(timezone.utc)
    state.update(updated_utc=now.isoformat(), latest_user_instruction=
                 'User requests additional disk-space savings; completed lossless frozen-trace '
                 'compaction, preserve sole original backup and ongoing original research.')
    state['storage_cleanup']['trace_compaction'] = dict(
        result=G + 'compaction-result.json', post_readback=G + 'post-compaction-live-verification.json',
        archive=result['archive'], archive_sha256=result['archive_sha256'],
        freed_bytes=result['freed_bytes'], free_bytes=post['free_bytes'],
        cumulative_cleanup_freed_bytes=total_freed, original_paths_readable=True,
        frozen_trace_paths_readonly=True, selected_files=88)
    state['last_goal_turn'].update(
        classification='progress', previous_goal_turn_classification='progress',
        validated_utc=now.isoformat(), previous_state_snapshot=B + 'previous-state.json',
        previous_current_audit_snapshot=B + 'previous-audit.json',
        focused_evidence=G + 'compaction-result.json',
        focused_evidence_sha256=sha(G + 'compaction-result.json'),
        reasons=['Completed explicitly requested storage recovery; lossless compression preserves '
                 'all prior evidence and allows ongoing research with more free disk space.'],
        device_IO=False, device_io=False, device_files_written=False,
        goal_status='active', full_goal_complete=False)
    for name in ('updated_utc', 'latest_user_instruction', 'storage_cleanup', 'last_goal_turn'):
        task[name] = state[name]
    public.update(updated=now.isoformat(), deep_research=state)
    progress['completed'].extend(details)
    progress['phases'][4]['completed'].extend(details)
    progress['research_updated_utc'] = now.isoformat()
    assert len(app['static_findings']) == 301 and len(progress['completed']) == 285
    assert progress['estimate_percent'] == 37 and progress['phases'][4]['estimate_percent'] == 35
    card = ('<div class="card"><h2>空間整理：舊測試紀錄已無損壓縮</h2><p>'
            f'本輪釋放<strong>{freed_gb:.2f}GB</strong>，目前可用約<strong>{free_gb:.2f}GB</strong>。'
            '88份大型舊測試紀錄已壓縮，原路徑仍可讀取；所有內容雜湊保持相同。'
            '保留一份完整sda.img備份、研究原始碼及不同的測試結果。</p><p>'
            f'連同前輪清理，共回收約{total_freed / 1_000_000_000:.2f}GB。'
            '壓縮視圖開機自動掛載，舊紀錄為唯讀；需要修改時另建新工作檔。'
            '研究估計保持整體37%、App35%，車機功能仍持續研究。</p></div>')
    marker = '<div class="card"><h2>最新進展：原廠OS20工作橋接路徑</h2>'
    report = before.decode()
    assert report.count(marker) == 1
    report = report.replace(marker, card + marker, 1)
    report, count = re.subn(
        r'(<ul class="completed-progress">)(.*?)(</ul>)',
        lambda match: match[1] + match[2] + ''.join('<li>' + html.escape(x) + '</li>'
                                                 for x in details) + match[3],
        report, count=1, flags=re.S)
    assert count == 1
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    iso = local.isoformat(timespec='seconds')
    for name in ('report-updated-time', 'research-updated-time'):
        report, count = re.subn(
            r'<time id="' + name + r'" datetime="[^"]+">[^<]+</time>',
            '<time id="' + name + '" datetime="' + iso + '">' +
            local.strftime('%Y/%m/%d %H:%M:%S') + '</time>', report, count=1)
        assert count == 1
    assert 'REDACTED_PRIVATE_ID' not in report and not re.search(
        r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b', report)
    for snapshot in snapshots:
        assert sha(snapshot['original']) == snapshot['sha256']
    create(B + 'publication-inputs.json', dict(
        all_passed=True, protected_sources=protected, focused_sources=focused,
        details=details, old_sources_freshly_verified_by_compaction_actor=4654,
        publisher_second_full_source_rehash_claimed=False, guest_rerun=False, device_IO=False))
    register(B + 'publication-inputs.json')
    for path, data in zip(P.CANONICAL[:3], (state, task, public)):
        write(path, data)
    (ROOT / P.CANONICAL[3]).write_text(report)
    after = {path: sha(path) for path in P.CANONICAL}
    assert read(P.CANONICAL[0]) == state and read(P.CANONICAL[1]) == task
    assert read(P.CANONICAL[2]) == public
    with urllib.request.urlopen(urllib.request.Request(
            latest['url'], headers={'Cache-Control': 'no-cache'}), timeout=10) as response:
        served = response.read()
        assert response.status == 200 and 'no-store' in response.headers.get('Cache-Control', '')
    assert served == report.encode() and P.service_now() == service
    audit = dict(old, all_passed=True, updated_utc=now.isoformat(),
                 previous_checkpoint=B + 'previous-audit.json', protected_sources=protected,
                 canonical_after_sha256=after, current_state_sha256=after[P.CANONICAL[0]],
                 report_sha256=after[P.CANONICAL[3]], local_report_sha256=after[P.CANONICAL[3]],
                 served_report_sha256=after[P.CANONICAL[3]], current_findings=301,
                 current_public_details=285, trace_compaction_result=G + 'compaction-result.json',
                 trace_compaction_freed_bytes=result['freed_bytes'],
                 cumulative_cleanup_freed_bytes=total_freed, sole_backup_image_preserved=True,
                 prior_full_source_rehash_repeated_this_turn=True,
                 old_sources_freshly_verified_by_compaction_actor=4654,
                 publisher_second_full_source_rehash_claimed=False,
                 current_focused_sources_sha256=focused,
                 scope_checks=dict(old['scope_checks'], frozen88_trace_byte_hashes_preserved=True,
                                   protected4654_fresh_rehash_completed=True,
                                   lossless_read_paths_preserved=True, cleanup_does_not_advance_App_percent=True))
    create(OUT, audit)
    assert latest.pop('current_native_os20_task_index_checkpoint') == OLD
    latest.setdefault('historical_offline_checkpoint_audits', {})['prior_native_os20_task_index_checkpoint'] = dict(
        audit=B + 'previous-audit.json', audit_sha256=sha(B + 'previous-audit.json'), all_passed=True)
    latest.update(updated_utc=now.isoformat(), current_garmin_trace_compaction_checkpoint=OUT,
                  checkpoint_sha256={OUT: sha(OUT)}, local_report_sha256=after[P.CANONICAL[3]],
                  served_report_sha256=after[P.CANONICAL[3]], report_bytes=len(served),
                  served_latest_report=True, canonical_hash_readback_uncached=True,
                  service_not_restarted=True)
    latest['progress_display_verified'].update(
        completed_items=285, report_updated_time=iso, research_updated_time=iso,
        actual_trace_compaction_visible=True)
    write('evidence/report-web-latest.json', latest)
    print(json.dumps(dict(all_passed=True, findings=301, details=285,
                          protected_sources=len(protected), report_sha256=after[P.CANONICAL[3]],
                          report_bytes=len(served), updated_Taiwan=iso,
                          freed_bytes=result['freed_bytes'], free_bytes=shutil.disk_usage(ROOT).free,
                          goal_status='active', device_IO=False)), flush=True)


if __name__ == '__main__':
    main()
