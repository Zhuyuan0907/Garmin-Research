#!/usr/bin/env python3
"""Publish completed cleanup; retain original research scope and estimates."""
import gzip
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
spec = importlib.util.spec_from_file_location('helpers', ROOT / 'scripts/publish_native_warm_probe_checkpoint_v1.py')
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
read, sha, create, write = P.read, P.sha, P.create, P.write
OLD = 'evidence/firmware-analysis/native-os20-allocator-checkpoint-audit.json'
OUT = 'evidence/firmware-analysis/garminos-storage-followup-checkpoint-audit.json'
B = 'staging/garminos-storage-followup-checkpoint-v1/'
G = 'staging/garminos-storage-followup-v1/'


def served(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers={'Cache-Control': 'no-cache'}), timeout=10) as r:
        body = r.read()
        assert r.status == 200 and 'no-store' in r.headers.get('Cache-Control', '')
        return body


def main():
    assert not (ROOT / B).exists() and not (ROOT / OUT).exists()
    old, result = read(OLD), read(G + 'cleanup-result.json')
    terminal = read(G + 'terminal-tool-receipt.json')['actual_terminal_result']
    assert terminal['exit_code'] == 0 and 'session_id' not in terminal
    assert json.loads(terminal['output']) == result and result['all_passed']
    assert old['all_passed'] and old['current_findings'] == 304 and old['current_public_details'] == 289
    assert len(old['protected_sources']) == 4696
    assert all(sha(p) == h for p, h in old['canonical_after_sha256'].items())
    protected, focused = dict(old['protected_sources']), {}

    def register(path, expected=None):
        actual = sha(path)
        assert expected is None or expected == actual
        assert path not in protected or protected[path] == actual, path
        protected[path] = actual
        focused[path] = actual

    for row in result['maps']:
        for p in (row['source'], row['retained_path']):
            register(p, row['sha256'])
            assert (ROOT / p).stat().st_mode & 0o777 == 0o444
    for p in sorted((ROOT / G).iterdir()):
        if p.is_file():
            register(str(p.relative_to(ROOT)))
    for p in (OLD, 'scripts/reduce_storage_followup_v1.py', 'scripts/publish_storage_followup_v1.py'):
        register(p)
    state, task, public = [read(p) for p in P.CANONICAL[:3]]
    app, progress = state['native_app_music'], public['research_progress']
    assert state['goal_status'] == 'active' and not state['goal_complete']
    assert state['required_work_remaining'] and not app['native_app_running']
    assert len(app['static_findings']) == 304 and len(progress['completed']) == 289
    latest, service = read('evidence/report-web-latest.json'), P.service_now()
    prior = served(latest['url'])
    assert hashlib.sha256(prior).hexdigest() == sha(P.CANONICAL[3])
    (ROOT / B).mkdir()
    snapshots = []
    for original, name in [(OLD, 'previous-audit.json'), ('evidence/report-web-latest.json', 'previous-web.json')] + list(zip(
            P.CANONICAL, ['previous-state.json', 'previous-task.json', 'previous-public.json', 'previous-report.html'])):
        path = B + name + '.gz'
        payload = (ROOT / original).read_bytes()
        with (ROOT / path).open('xb') as f:
            with gzip.GzipFile(filename='', mode='wb', fileobj=f, mtime=0, compresslevel=6) as z:
                z.write(payload)
        assert gzip.decompress((ROOT / path).read_bytes()) == payload
        register(path)
        snapshots.append(dict(original=original, snapshot=path, encoding='gzip',
                              decoded_sha256=hashlib.sha256(payload).hexdigest()))
    now = datetime.now(timezone.utc)
    free = shutil.disk_usage(ROOT).free
    details = [
        f'追加空間整理：兩份各約135MB的重複地圖輸出以SHA-256確認內容相同後共用唯讀資料，四個原路徑均保持可讀；連同清除可重建下載快取，本輪實際釋放{result["freed_bytes"] / 1e6:.0f}MB。',
        f'目前可用約{free / 1e9:.2f}GB（{free / 2**30:.2f}GiB），累計整理釋放約{result["cumulative_cleanup_freed_bytes"] / 1e9:.2f}GB。唯一完整備份、研究程式、不同測試結果及已安裝工具保留；整理不增加原生App研究百分比。'
    ]
    key = 'garminos_additional_exact_map_duplicate_and_cache_cleanup'
    assert key not in app['static_findings']
    app['static_findings'][key] = dict(evidence=G + 'cleanup-result.json',
        evidence_sha256=sha(G + 'cleanup-result.json'),
        scope='Two exact map duplicates share read-only inodes; all four content hashes and paths retained. '
              'Regenerable apt/pip caches removed. Backup metadata unchanged; full backup hash was not repeated. '
              'No original sources, distinct results, installed packages, VM disks or device files removed.',
        evidence_type='ROOT measured filesystem cleanup', device_io=False,
        physical_App_or_audio_verified=False)
    state['storage_cleanup']['followup'] = dict(result=G + 'cleanup-result.json',
        freed_bytes=result['freed_bytes'], free_bytes=free,
        cumulative_cleanup_freed_bytes=result['cumulative_cleanup_freed_bytes'],
        sole_complete_backup_preserved=True, all_original_map_paths_preserved=True)
    state['updated_utc'] = now.isoformat()
    state['latest_user_instruction'] = 'User requests additional storage reduction; completed exact map deduplication and regenerable cache cleanup, original research remains active.'
    state['last_goal_turn'].update(classification='progress', validated_utc=now.isoformat(),
        focused_evidence=G + 'cleanup-result.json', focused_evidence_sha256=sha(G + 'cleanup-result.json'),
        previous_state_snapshot=B + 'previous-state.json.gz',
        previous_current_audit_snapshot=B + 'previous-audit.json.gz', snapshot_encoding='gzip',
        reasons=['Completed authorized storage reduction while preserving the sole backup and ongoing research.'],
        device_IO=False, device_io=False, device_files_written=False,
        goal_status='active', full_goal_complete=False)
    for name in ('updated_utc', 'latest_user_instruction', 'storage_cleanup', 'last_goal_turn'):
        task[name] = state[name]
    progress['completed'].extend(details)
    progress['phases'][0]['completed'].extend(details)
    progress['research_updated_utc'] = now.isoformat()
    public.update(updated=now.isoformat(), deep_research=state)
    assert progress['estimate_percent'] == 37 and progress['phases'][4]['estimate_percent'] == 35
    assert len(app['static_findings']) == 305 and len(progress['completed']) == 291
    card = ('<div class="card"><h2>空間整理：已再釋放530MB</h2><p>'
        f'本輪釋放<strong>{result["freed_bytes"] / 1e6:.0f}MB</strong>；目前可用約<strong>{free / 1e9:.2f}GB（{free / 2**30:.2f}GiB）</strong>。'
        '兩份重複地圖輸出已共用唯讀資料，原路徑與SHA-256相同；下載快取已清除，工具仍可使用。</p><p>'
        f'連同前兩輪，共回收約{result["cumulative_cleanup_freed_bytes"] / 1e9:.2f}GB。'
        '保留唯一完整USB備份、研究程式和不同測試結果。整體研究37%、App35%，研究繼續。</p></div>')
    report, count = re.subn(r'<div class="card"><h2>空間整理：舊測試紀錄已無損壓縮</h2>.*?</div>',
        lambda _: card, prior.decode(), count=1, flags=re.S)
    assert count == 1
    report, count = re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',
        lambda m: m[1] + m[2] + ''.join('<li>' + html.escape(d) + '</li>' for d in details) + m[3],
        report, count=1, flags=re.S)
    assert count == 1
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    iso = local.isoformat(timespec='seconds')
    for name in ('report-updated-time', 'research-updated-time'):
        report, count = re.subn(r'<time id="' + name + r'" datetime="[^"]+">[^<]+</time>',
            '<time id="' + name + '" datetime="' + iso + '">' + local.strftime('%Y/%m/%d %H:%M:%S') + '</time>',
            report, count=1)
        assert count == 1
    assert 'REDACTED_PRIVATE_ID' not in report
    for row in snapshots:
        assert sha(row['original']) == row['decoded_sha256']
    create(B + 'publication-inputs.json', dict(all_passed=True, previous_checkpoint=OLD,
        snapshots=snapshots, focused_sources=focused, prior4696_source_hashes_inherited=True,
        full_prior_source_rehash_repeated=False, backup_full_hash_repeated=False,
        device_IO=False, details=details))
    register(B + 'publication-inputs.json')
    for p, data in zip(P.CANONICAL[:3], (state, task, public)):
        write(p, data)
    (ROOT / P.CANONICAL[3]).write_text(report)
    after = {p: sha(p) for p in P.CANONICAL}
    assert read(P.CANONICAL[0]) == state and read(P.CANONICAL[1]) == task and read(P.CANONICAL[2]) == public
    body = served(latest['url'])
    assert body == report.encode() and P.service_now() == service
    audit = dict(old, updated_utc=now.isoformat(), all_passed=True,
        previous_checkpoint=OLD, previous_canonical_snapshots=snapshots,
        protected_sources=protected, canonical_after_sha256=after,
        current_state_sha256=after[P.CANONICAL[0]], report_sha256=after[P.CANONICAL[3]],
        local_report_sha256=after[P.CANONICAL[3]], served_report_sha256=after[P.CANONICAL[3]],
        current_findings=305, current_public_details=291,
        current_focused_sources_sha256=focused, prior_full_source_rehash_repeated_this_turn=False,
        additional_storage_cleanup_result=G + 'cleanup-result.json',
        additional_storage_cleanup_freed_bytes=result['freed_bytes'],
        cumulative_cleanup_freed_bytes=result['cumulative_cleanup_freed_bytes'],
        sole_backup_image_preserved=True,
        scope_checks=dict(old['scope_checks'], exact_map_content_and_paths_preserved=True,
                          cache_only_no_package_or_VM_removal=True, cleanup_does_not_advance_App_percent=True))
    create(OUT, audit)
    assert latest.pop('current_native_os20_allocator_checkpoint') == OLD
    latest.setdefault('historical_offline_checkpoint_audits', {})['prior_native_os20_allocator_checkpoint'] = dict(
        audit=OLD, audit_sha256=sha(OLD), all_passed=True)
    latest.update(updated_utc=now.isoformat(), current_garmin_storage_followup_checkpoint=OUT,
        checkpoint_sha256={OUT: sha(OUT)}, local_report_sha256=after[P.CANONICAL[3]],
        served_report_sha256=after[P.CANONICAL[3]], report_bytes=len(body),
        service_not_restarted=True, served_latest_report=True, canonical_hash_readback_uncached=True)
    latest['progress_display_verified'].update(completed_items=291, report_updated_time=iso,
        research_updated_time=iso, additional_storage_cleanup_visible=True)
    write('evidence/report-web-latest.json', latest)
    print(json.dumps(dict(all_passed=True, findings=305, details=291,
        protected_sources=len(protected), report_sha256=after[P.CANONICAL[3]],
        report_bytes=len(body), updated_Taiwan=iso, freed_bytes=result['freed_bytes'],
        free_bytes=shutil.disk_usage(ROOT).free, goal_status='active', device_IO=False)), flush=True)


if __name__ == '__main__':
    main()
