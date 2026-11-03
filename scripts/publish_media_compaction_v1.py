#!/usr/bin/env python3
"""Publish space reduction, retaining the latest native-worker scope and limits."""
import gzip
import hashlib
import html
import importlib.util
import json
import os
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
read, sha, create = P.read, P.sha, P.create
OLD = 'evidence/firmware-analysis/native-os20-resident-music-checkpoint-audit.json'
OUT = 'evidence/firmware-analysis/garminos-media-compaction-checkpoint-audit.json'
B = 'staging/garminos-media-compaction-checkpoint-v1/'
G = 'staging/garminos-media-compaction-v1/'


def write(path, payload):
    target = ROOT / path
    temporary = target.with_name('.media-publication-v1-' + target.name)
    assert not temporary.exists()
    with temporary.open('x') as stream:
        stream.write(payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False, indent=2) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, target)


def served(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers={'Cache-Control': 'no-cache'}), timeout=10) as response:
        assert response.status == 200 and 'no-store' in response.headers.get('Cache-Control', '')
        return response.read()


def main():
    assert not (ROOT / B).exists() and not (ROOT / OUT).exists()
    old, result, duplicates, plan = [read(path) for path in [OLD, G + 'compaction-result.json',
        G + 'exact-duplicate-result.json', G + 'verified-plan.json']]
    assert all(d['all_passed'] for d in [old, result, duplicates, plan])
    terminal = read(G + 'terminal-tool-receipt.json')['actual_terminal_result']
    assert terminal['exit_code'] == 0 and 'session_id' not in terminal
    assert json.loads(terminal['output']) == result
    assert all(sha(path) == value for path, value in old['canonical_after_sha256'].items())
    protected, focused = dict(old['protected_sources']), {}

    def register(path, expected=None):
        value = sha(path)
        assert expected is None or value == expected, path
        assert path not in protected or protected[path] == value, path
        protected[path] = value
        focused[path] = value

    # The compactor already checked all selected complete files, both before
    # and after replacement. Inherit those sealed results, without a second
    # full media/backup read or a claim to have rehashed all old sources.
    for row in plan['files']:
        path = row['path']
        assert (ROOT / path).is_symlink() and (ROOT / path).stat().st_size == row['size']
        assert path not in protected or protected[path] == row['sha256']
        protected[path] = row['sha256']
    protected[result['archive']] = result['archive_sha256']
    assert (ROOT / result['archive']).stat().st_size == result['archive_bytes']
    for row in duplicates['groups']:
        for path in row['paths']:
            register(path, row['sha256'])
    for path in sorted((ROOT / G).iterdir()):
        if path.is_file():
            register(str(path.relative_to(ROOT)))
    for path in [OLD, 'scripts/compact_frozen_media_v1.py', 'scripts/consolidate_frozen_duplicates_v1.py',
                 'scripts/publish_media_compaction_v1.py']:
        register(path)
    state, task, public = [read(path) for path in P.CANONICAL[:3]]
    assert state['goal_status'] == 'active' and not state['goal_complete'] and state['required_work_remaining']
    progress, app = public['research_progress'], state['native_app_music']
    estimates = [progress['estimate_percent'], progress['weighted_estimate_percent'],
                 [p['estimate_percent'] for p in progress['phases']]]
    latest, service = read('evidence/report-web-latest.json'), P.service_now()
    before = served(latest['url'])
    assert hashlib.sha256(before).hexdigest() == sha(P.CANONICAL[3])
    (ROOT / B).mkdir()
    snapshots = []
    for original, name in [(OLD, 'previous-audit.json'), ('evidence/report-web-latest.json', 'previous-web.json')] + list(zip(
            P.CANONICAL, ['previous-state.json', 'previous-task.json', 'previous-public.json', 'previous-report.html'])):
        target, payload = B + name + '.gz', (ROOT / original).read_bytes()
        with (ROOT / target).open('xb') as stream:
            with gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=0, compresslevel=6) as zipped:
                zipped.write(payload)
        assert gzip.decompress((ROOT / target).read_bytes()) == payload
        register(target)
        snapshots.append(dict(original=original, snapshot=target, encoding='gzip', decoded_sha256=hashlib.sha256(payload).hexdigest()))
    now, free = datetime.now(timezone.utc), shutil.disk_usage(ROOT).free
    freed = result['freed_bytes'] + duplicates['freed_bytes']
    cumulative = state['storage_cleanup']['cumulative_cleanup_freed_bytes'] + freed
    details = [
        f'追加空間整理：18個既有地圖／語音測試檔無損壓縮，全部完整檔案校驗一致；合併9組完全相同的歷史報告、封裝與程式庫副本，原路徑及內容保留。合計再釋放約{freed / 1e6:.0f}MB。',
        f'目前可用約{free / 1e9:.2f}GB（{free / 2**30:.2f}GiB），累計整理約{cumulative / 1e9:.2f}GB。完整USB備份仍只有一份；不同研究版本及可編輯原始程式保留。壓縮視圖重新掛載及開機啟用已驗證，研究百分比保持。']
    key = 'garminos_frozen_media_and_exact_copy_compaction'
    assert key not in app['static_findings']
    app['static_findings'][key] = dict(evidence=G + 'compaction-result.json', evidence_sha256=sha(G + 'compaction-result.json'),
        scope='18 frozen map/VPM read paths retain verified bytes in read-only compressed storage; nine exact-copy groups share originals. '
              'Sole complete backup, editable sources, distinct versions and live executables preserved. No native App/audio progress claim.',
        evidence_type='Lossless storage reduction and focused complete-file readback', device_io=False, physical_App_or_audio_verified=False)
    state['storage_cleanup'].update(current_free_bytes=free, cumulative_cleanup_freed_bytes=cumulative,
        media_compaction=dict(result=G + 'compaction-result.json', duplicates=G + 'exact-duplicate-result.json',
            freed_bytes=freed, archive=result['archive'], archive_bytes=result['archive_bytes'], original_paths_preserved=True))
    state.update(updated_utc=now.isoformat(), latest_user_instruction='Reduce Garmin research storage; preserve one complete backup and unique work. Full research remains active.')
    state['last_goal_turn'].update(classification='progress', validated_utc=now.isoformat(),
        focused_evidence=G + 'compaction-result.json', focused_evidence_sha256=sha(G + 'compaction-result.json'),
        previous_state_snapshot=B + 'previous-state.json.gz', previous_current_audit_snapshot=B + 'previous-audit.json.gz',
        snapshot_encoding='gzip', reasons=['Completed authorized lossless storage reduction and exact-copy consolidation.'],
        device_IO=False, device_io=False, device_files_written=False, goal_status='active', full_goal_complete=False)
    for name in ['updated_utc', 'latest_user_instruction', 'storage_cleanup', 'last_goal_turn']:
        task[name] = state[name]
    progress['completed'].extend(details)
    progress['phases'][0]['completed'].extend(details)
    progress['research_updated_utc'] = now.isoformat()
    public.update(updated=now.isoformat(), deep_research=state)
    assert estimates == [progress['estimate_percent'], progress['weighted_estimate_percent'], [p['estimate_percent'] for p in progress['phases']]]
    card = ('<div class="card"><h2>空間整理：已再釋放約195MB</h2><p>'
            f'本輪整理18個地圖／語音測試檔及9組完全相同副本，釋放<strong>{freed / 1e6:.0f}MB</strong>；'
            f'目前可用<strong>{free / 1e9:.2f}GB（{free / 2**30:.2f}GiB）</strong>。</p><p>'
            '壓縮前後的完整檔案校驗一致，原路徑保持可讀，重新掛載及開機啟用已驗證。'
            '不同研究版本和可編輯原始程式保留，完整USB備份仍只有一份。'
            f'累計整理約{cumulative / 1e9:.2f}GB；研究進度與下一步保持。</p></div>')
    report, count = re.subn(r'<div class="card"><h2>空間整理：完整備份已無損壓縮</h2>.*?</div>', lambda _: card, before.decode(), count=1, flags=re.S)
    assert count == 1
    report, count = re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)', lambda m:
        m[1] + m[2] + ''.join('<li>' + html.escape(d) + '</li>' for d in details) + m[3], report, count=1, flags=re.S)
    assert count == 1
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    iso = local.isoformat(timespec='seconds')
    for name in ['report-updated-time', 'research-updated-time']:
        report, count = re.subn(r'<time id="' + name + r'" datetime="[^"]+">[^<]+</time>',
            '<time id="' + name + '" datetime="' + iso + '">' + local.strftime('%Y/%m/%d %H:%M:%S') + '</time>', report, count=1)
        assert count == 1
    assert 'REDACTED_PRIVATE_ID' not in report
    for row in snapshots:
        assert sha(row['original']) == row['decoded_sha256']
    create(B + 'publication-inputs.json', dict(all_passed=True, snapshots=snapshots, focused_sources=focused,
        inherited_prior_sources=len(old['protected_sources']), full_prior_rehash_repeated=False,
        compactor_selected_complete_files_freshly_verified=True, publisher_selected_media_rehash_repeated=False,
        full_backup_rehash_repeated=False, device_IO=False, details=details))
    register(B + 'publication-inputs.json')
    for path, payload in zip(P.CANONICAL, [state, task, public, report]):
        write(path, payload)
    after = {path: sha(path) for path in P.CANONICAL}
    assert [read(path) for path in P.CANONICAL[:3]] == [state, task, public]
    body = served(latest['url'])
    assert body == report.encode() and P.service_now() == service
    audit = dict(old, all_passed=True, updated_utc=now.isoformat(), previous_checkpoint=OLD,
        previous_canonical_snapshots=snapshots, protected_sources=protected, canonical_after_sha256=after,
        current_state_sha256=after[P.CANONICAL[0]], report_sha256=after[P.CANONICAL[3]],
        local_report_sha256=after[P.CANONICAL[3]], served_report_sha256=after[P.CANONICAL[3]],
        current_findings=len(app['static_findings']), current_public_details=len(progress['completed']),
        current_focused_sources_sha256=focused, media_compaction_result=G + 'compaction-result.json',
        media_compaction_and_duplicates_freed_bytes=freed, cumulative_cleanup_freed_bytes=cumulative,
        prior_full_source_rehash_repeated_this_turn=False,
        full_backup_image_rehash_repeated_by_compactor=False, inherited_full_backup_validation=True,
        scope_checks=dict(old['scope_checks'], frozen_media_content_and_read_paths_preserved=True,
            exact_copy_consolidation_verified=True, cleanup_does_not_advance_App_percent=True))
    create(OUT, audit)
    assert latest.pop('current_native_os20_resident_music_checkpoint') == OLD
    latest.setdefault('historical_offline_checkpoint_audits', {})['prior_native_os20_resident_music_checkpoint'] = dict(
        audit=OLD, audit_sha256=sha(OLD), all_passed=True)
    latest.update(updated_utc=now.isoformat(), current_garmin_media_compaction_checkpoint=OUT,
        checkpoint_sha256={OUT: sha(OUT)}, local_report_sha256=after[P.CANONICAL[3]], served_report_sha256=after[P.CANONICAL[3]],
        report_bytes=len(body), service_not_restarted=True, served_latest_report=True, canonical_hash_readback_uncached=True)
    latest['progress_display_verified'].update(completed_items=len(progress['completed']),
        report_updated_time=iso, research_updated_time=iso, frozen_media_compaction_visible=True)
    write('evidence/report-web-latest.json', latest)
    print(json.dumps(dict(all_passed=True, findings=len(app['static_findings']), details=len(progress['completed']),
        protected_sources=len(protected), freed_bytes=freed, free_bytes=shutil.disk_usage(ROOT).free,
        report_sha256=after[P.CANONICAL[3]], report_bytes=len(body), goal_status='active', device_IO=False)), flush=True)


if __name__ == '__main__':
    main()
