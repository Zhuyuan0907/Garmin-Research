#!/usr/bin/env python3
"""Publish verified backup compression without changing research completion."""
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
spec = importlib.util.spec_from_file_location(
    'helpers', ROOT / 'scripts/publish_native_warm_probe_checkpoint_v1.py')
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
read, sha, create, write = P.read, P.sha, P.create, P.write
OLD = 'evidence/firmware-analysis/native-os20-scheduled-decoder-checkpoint-audit.json'
OUT = 'evidence/firmware-analysis/garminos-backup-compaction-checkpoint-audit.json'
B = 'staging/garminos-backup-compaction-checkpoint-v1/'
G = 'staging/garminos-backup-compaction-v1/'


def served(url):
    with urllib.request.urlopen(urllib.request.Request(
            url, headers={'Cache-Control': 'no-cache'}), timeout=10) as response:
        body = response.read()
        assert response.status == 200
        assert 'no-store' in response.headers.get('Cache-Control', '')
        return body


def main():
    assert not (ROOT / B).exists() and not (ROOT / OUT).exists()
    old, result = read(OLD), read(G + 'compaction-result.json')
    terminal = read(G + 'terminal-tool-receipt.json')['actual_terminal_result']
    assert terminal['exit_code'] == 0 and 'session_id' not in terminal
    assert json.loads(terminal['output'].splitlines()[-1]) == result
    assert old['all_passed'] and result['all_passed']
    assert all(sha(p) == h for p, h in old['canonical_after_sha256'].items())
    protected, focused = dict(old['protected_sources']), {}

    def register(path, expected=None):
        actual = sha(path)
        assert expected is None or actual == expected, path
        assert path not in protected or protected[path] == actual, path
        protected[path] = actual
        focused[path] = actual

    register(result['sole_physical_full_backup'], result['archive_sha256'])
    # The compactor just read and checked all 3.88GB of decompressed image and
    # all 1,402 FAT files; do not repeat that completed full read here.
    assert protected[result['logical_image_path']] == result['logical_image_sha256']
    assert (ROOT / result['logical_image_path']).is_symlink()
    assert (ROOT / result['logical_image_path']).stat().st_size == result['logical_image_bytes']
    for path in sorted((ROOT / G).iterdir()):
        if path.is_file():
            register(str(path.relative_to(ROOT)))
    for path in (OLD, 'scripts/compact_original_backup_v1.py',
                 'scripts/publish_backup_compaction_v1.py'):
        register(path)
    state, task, public = [read(path) for path in P.CANONICAL[:3]]
    app, progress = state['native_app_music'], public['research_progress']
    assert state['goal_status'] == 'active' and not state['goal_complete']
    assert state['required_work_remaining'] and not app['native_app_running']
    assert len(app['static_findings']) == 312 and len(progress['completed']) == 300
    estimates_before = (progress['estimate_percent'], progress['weighted_estimate_percent'],
                        [phase['estimate_percent'] for phase in progress['phases']])
    latest, service = read('evidence/report-web-latest.json'), P.service_now()
    prior = served(latest['url'])
    assert hashlib.sha256(prior).hexdigest() == sha(P.CANONICAL[3])
    (ROOT / B).mkdir()
    snapshots = []
    for original, name in [(OLD, 'previous-audit.json'),
                           ('evidence/report-web-latest.json', 'previous-web.json')] + list(zip(
            P.CANONICAL, ['previous-state.json', 'previous-task.json',
                          'previous-public.json', 'previous-report.html'])):
        target = B + name + '.gz'
        payload = (ROOT / original).read_bytes()
        with (ROOT / target).open('xb') as stream:
            with gzip.GzipFile(filename='', mode='wb', fileobj=stream,
                               mtime=0, compresslevel=6) as zipped:
                zipped.write(payload)
        assert gzip.decompress((ROOT / target).read_bytes()) == payload
        register(target)
        snapshots.append(dict(original=original, snapshot=target, encoding='gzip',
                              decoded_sha256=hashlib.sha256(payload).hexdigest()))
    now = datetime.now(timezone.utc)
    free = shutil.disk_usage(ROOT).free
    details = [
        f'完整USB備份已無損壓縮：原{result["logical_image_bytes"] / 1e9:.2f}GB映像，'
        f'改以{result["archive_bytes"] / 1e9:.2f}GB唯讀壓縮檔保存。'
        '完整解壓映像的SHA-256，以及備份內1,402個檔案的大小與SHA-256全部一致；'
        '確認開機掛載依賴可從停止狀態自動建立後，才移除未壓縮副本。',
        f'本輪實際釋放約{result["freed_bytes"] / 1e9:.2f}GB；目前可用約'
        f'{free / 1e9:.2f}GB（{free / 2**30:.2f}GiB）。原sda.img與files/路徑仍可唯讀存取，'
        '只保留一份實體完整備份，原始程式與各次研究結果保留；研究百分比不因空間整理增加。'
    ]
    key = 'garminos_sole_full_backup_lossless_compression'
    assert key not in app['static_findings']
    app['static_findings'][key] = dict(
        evidence=G + 'compaction-result.json', evidence_sha256=sha(G + 'compaction-result.json'),
        scope='Sole USB-exposed logical image losslessly compressed into read-only squashfs. '
              'Complete decompressed image SHA-256 and all 1,402 file hashes matched. '
              'Cold systemd dependency exercised before raw inode retirement; original paths preserved. '
              'No original source, unique result or device file removed. No new native App proof.',
        evidence_type='ROOT full-image and file readback with measured filesystem reduction',
        device_io=False, physical_App_or_audio_verified=False)
    storage = state['storage_cleanup']
    storage['backup_compaction'] = dict(result=G + 'compaction-result.json',
        sole_physical_full_backup=result['sole_physical_full_backup'],
        archive_bytes=result['archive_bytes'], logical_image_path=result['logical_image_path'],
        logical_image_sha256=result['logical_image_sha256'], freed_bytes=result['freed_bytes'],
        free_bytes=free, cumulative_cleanup_freed_bytes=result['cumulative_cleanup_freed_bytes'],
        full_image_and_all_file_hashes_verified=True, boot_dependency_tested=True,
        original_paths_preserved=True)
    storage.update(current_free_bytes=free,
        sole_physical_full_backup=result['sole_physical_full_backup'],
        cumulative_cleanup_freed_bytes=result['cumulative_cleanup_freed_bytes'])
    state['updated_utc'] = now.isoformat()
    state['latest_user_instruction'] = 'User requests further storage reduction; sole backup losslessly compressed and verified. Original native App/music and later Android Auto/offline Google Maps research stays active.'
    state['last_goal_turn'].update(classification='progress', validated_utc=now.isoformat(),
        focused_evidence=G + 'compaction-result.json',
        focused_evidence_sha256=sha(G + 'compaction-result.json'),
        previous_state_snapshot=B + 'previous-state.json.gz',
        previous_current_audit_snapshot=B + 'previous-audit.json.gz', snapshot_encoding='gzip',
        reasons=['Completed authorized storage reduction with lossless backup and full file verification.'],
        device_IO=False, device_io=False, device_files_written=False,
        goal_status='active', full_goal_complete=False)
    for name in ('updated_utc', 'latest_user_instruction', 'storage_cleanup', 'last_goal_turn'):
        task[name] = state[name]
    progress['completed'].extend(details)
    progress['phases'][0]['completed'].extend(details)
    progress['research_updated_utc'] = now.isoformat()
    public.update(updated=now.isoformat(), deep_research=state)
    assert estimates_before == (progress['estimate_percent'], progress['weighted_estimate_percent'],
                                [phase['estimate_percent'] for phase in progress['phases']])
    assert len(app['static_findings']) == 313 and len(progress['completed']) == 302
    card = ('<div class="card"><h2>空間整理：完整備份已無損壓縮</h2><p>'
        f'本輪釋放<strong>{result["freed_bytes"] / 1e9:.2f}GB</strong>；目前可用約'
        f'<strong>{free / 1e9:.2f}GB（{free / 2**30:.2f}GiB）</strong>。'
        f'唯一完整USB備份從{result["logical_image_bytes"] / 1e9:.2f}GB壓縮至'
        f'{result["archive_bytes"] / 1e9:.2f}GB，完整映像及1,402個檔案校驗一致。</p><p>'
        '原sda.img與files/仍可唯讀存取，開機掛載依賴已實測。確認壓縮備份可完整讀回後，'
        '才移除未壓縮副本；研究程式、不同測試結果及VS Code下載保留。'
        f'累計空間整理回收約{result["cumulative_cleanup_freed_bytes"] / 1e9:.2f}GB。'
        '整體研究37%、App40%，研究继续。</p></div>')
    report, count = re.subn(r'<div class="card"><h2>空間整理：已再釋放530MB</h2>.*?</div>',
        lambda _: card, prior.decode(), count=1, flags=re.S)
    assert count == 1
    report, count = re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',
        lambda match: match[1] + match[2] + ''.join(
            '<li>' + html.escape(detail) + '</li>' for detail in details) + match[3],
        report, count=1, flags=re.S)
    assert count == 1
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    iso = local.isoformat(timespec='seconds')
    for name in ('report-updated-time', 'research-updated-time'):
        report, count = re.subn(r'<time id="' + name + r'" datetime="[^"]+">[^<]+</time>',
            '<time id="' + name + '" datetime="' + iso + '">' +
            local.strftime('%Y/%m/%d %H:%M:%S') + '</time>', report, count=1)
        assert count == 1
    assert 'REDACTED_PRIVATE_ID' not in report
    for row in snapshots:
        assert sha(row['original']) == row['decoded_sha256']
    create(B + 'publication-inputs.json', dict(all_passed=True, previous_checkpoint=OLD,
        snapshots=snapshots, focused_sources=focused, prior4783_source_hashes_inherited=True,
        full_prior_source_rehash_repeated=False,
        compactor_full_image_and1402_file_readback_verified=True,
        publisher_second_full_image_rehash_repeated=False, device_IO=False, details=details))
    register(B + 'publication-inputs.json')
    for path, data in zip(P.CANONICAL[:3], (state, task, public)):
        write(path, data)
    (ROOT / P.CANONICAL[3]).write_text(report)
    after = {path: sha(path) for path in P.CANONICAL}
    assert [read(path) for path in P.CANONICAL[:3]] == [state, task, public]
    body = served(latest['url'])
    assert body == report.encode() and P.service_now() == service
    audit = dict(old, updated_utc=now.isoformat(), all_passed=True,
        previous_checkpoint=OLD, previous_canonical_snapshots=snapshots,
        protected_sources=protected, canonical_after_sha256=after,
        current_state_sha256=after[P.CANONICAL[0]], report_sha256=after[P.CANONICAL[3]],
        local_report_sha256=after[P.CANONICAL[3]], served_report_sha256=after[P.CANONICAL[3]],
        current_findings=313, current_public_details=302,
        current_focused_sources_sha256=focused, prior_full_source_rehash_repeated_this_turn=False,
        backup_compaction_result=G + 'compaction-result.json',
        backup_compaction_freed_bytes=result['freed_bytes'],
        cumulative_cleanup_freed_bytes=result['cumulative_cleanup_freed_bytes'],
        sole_backup_image_preserved=True,
        sole_physical_full_backup=result['sole_physical_full_backup'],
        full_backup_image_rehash_repeated_by_compactor=True,
        full_backup_image_and_all1402_files_verified=True,
        scope_checks=dict(old['scope_checks'], lossless_full_image_storage=True,
                          original_backup_paths_preserved=True,
                          cold_compressed_file_mount_dependency_passed=True,
                          cleanup_does_not_advance_App_percent=True))
    create(OUT, audit)
    assert latest.pop('current_native_os20_scheduled_decoder_checkpoint') == OLD
    latest.setdefault('historical_offline_checkpoint_audits', {})[
        'prior_native_os20_scheduled_decoder_checkpoint'] = dict(
            audit=OLD, audit_sha256=sha(OLD), all_passed=True)
    latest.update(updated_utc=now.isoformat(), current_garmin_backup_compaction_checkpoint=OUT,
        checkpoint_sha256={OUT: sha(OUT)}, local_report_sha256=after[P.CANONICAL[3]],
        served_report_sha256=after[P.CANONICAL[3]], report_bytes=len(body),
        service_not_restarted=True, served_latest_report=True,
        canonical_hash_readback_uncached=True)
    latest['progress_display_verified'].update(completed_items=302, report_updated_time=iso,
        research_updated_time=iso, full_backup_lossless_compaction_visible=True)
    write('evidence/report-web-latest.json', latest)
    print(json.dumps(dict(all_passed=True, findings=313, details=302,
        protected_sources=len(protected), report_sha256=after[P.CANONICAL[3]],
        report_bytes=len(body), updated_Taiwan=iso, freed_bytes=result['freed_bytes'],
        free_bytes=shutil.disk_usage(ROOT).free, goal_status='active', device_IO=False)), flush=True)


if __name__ == '__main__':
    main()
