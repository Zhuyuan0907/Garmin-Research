#!/usr/bin/env python3
"""Publish the bounded metadata finding without authorizing a native build."""
import argparse
import copy
from datetime import datetime, timezone
import gzip
import json
import re
from zoneinfo import ZoneInfo

from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, replace, service, sha

FILES = ['evidence/deep-research-state.json', 'evidence/task-state.json', 'reports/findings.json',
         'reports/nuvi2565RT.html', 'evidence/report-web-latest.json']
FIELD = 'latest_native_music_retention_checkpoint'
ARTIFACT = 'staging/native-music-symbol-provenance-readonly-20261007-v1/'


def require(value, reason):
    if not value:
        raise ValueError(reason)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--provenance-sha', required=True)
    args = parser.parse_args()
    raw = (ROOT / (ARTIFACT + 'provenance.json')).read_bytes()
    require(sha(raw) == args.provenance_sha, 'Reviewed provenance hash')
    proof = json.loads(raw)
    require(proof['API_label_erratum']['correct_kind'] == 'const struct umc_exports object'
            and proof['API_label_erratum']['ARM32_source_layout_bytes'] == 36
            and proof['compiler_sections_and_link_gc_declared']
            and not proof['exact_linker_GC_cause_proven']
            and not proof['current_same_image_metadata_contract_satisfied']
            and not proof['device_IO'], 'Partial FILE finding, not native success')
    for path, pin in proof['host_guard_source_pins'].items():
        require(sha((ROOT / path).read_bytes()) == pin, 'Tested host checker source')
    receipts = json.loads((ROOT / (ARTIFACT + 'actual-final-guard-tool-receipts.json')).read_text())
    require([r['result']['exit_code'] for r in receipts] == [1, 1, 0], 'Two expected refusals and host controls')
    missing = ['umc_status_read', 'umc_source_started', 'umc_cleanup_returned', 'umc_kick', 'ui_music_control_api']
    for version in ('v2', 'v3'):
        checked = json.loads((ROOT / (ARTIFACT + version + '-final-contract-check.json')).read_text())
        require(checked['missing_entries'] == missing and not checked['metadata_contract_satisfied'], 'Missing entries')
    controls = json.loads((ROOT / (ARTIFACT + 'host-final-controls.json')).read_text())
    require(controls['host_controls_passed'] == 16 and controls['positive_case_is_synthetic_metadata_only'], 'Host control scope')
    before = {name: (ROOT / name).read_bytes() for name in FILES}
    state, task, public = [json.loads(before[name]) for name in FILES[:3]]
    web = json.loads(before[FILES[4]])
    require(state == public['deep_research'], 'Canonical state initially equal')
    require(all(d['current_goal_priority'] == 'bluetooth_music' and d['goal_status'] == 'active'
                and not d['goal_complete'] for d in (state, task, public, web)), 'Latest music priority')
    require(state['navigation_repair']['status'] == 'stopped_by_user'
            and task['user_away'] and not state['audio']['audible_tests_allowed']
            and not web['current_physical_test_requested'], 'No navigation or physical action')
    old_native = copy.deepcopy(state['native_app_music'])
    old_audio, old_nav = copy.deepcopy(state['audio']), copy.deepcopy(state['navigation_repair'])
    estimates = [public['research_progress']['estimate_percent'], [p['estimate_percent'] for p in public['research_progress']['phases']]]
    current_service = service()
    require(http(web['url'])[0] == before[FILES[3]], 'Prior exact served report')
    now = datetime.now(timezone.utc); local = now.astimezone(ZoneInfo('Asia/Taipei'))
    stamp = local.isoformat(timespec='seconds')
    checkpoint = {
        'updated_utc': now.isoformat(), 'provenance_path': ARTIFACT + 'provenance.json',
        'provenance_sha256': args.provenance_sha, 'scope': 'finite own C/H and JSON, host-only metadata checks',
        'source_hash_declarations_match_captured_snapshots': True,
        'public_API_kind': 'const struct object, not getter', 'source_ARM32_table_bytes': 36,
        'compile_and_three_link_receipts_declare_section_GC': True,
        'earliest_source_stage_already_missing_public_object_and_four_functions': True,
        'exact_GC_cause_proven': False, 'fresh_native_binary_verified': False,
        'missing_required_declarations': missing, 'metadata_contract_satisfied': False,
        'host_guard_controls_passed': 16, 'historical_candidates_refused': ['v2', 'v3'],
        'device_IO': False, 'native_install_candidate': False, 'full_goal_complete': False,
    }
    next_actions = [
        '原機音樂控制入口：保留四個必要函式及公開介面物件，再做同映像宣告核對；現兩候選被完整性檢查拒絕。只做有限FILE研究，沒有原機編譯／執行或安裝。',
        'Android手機端實驗APK已存在；正處理本機音檔provider阻塞主執行緒的問題。修改後須重新編譯與簽章核對，再等使用者通知可實測來電／端點／短音檔。',
        '來源所有權、停止後清理／重啟、真正A2DP端點及Garmin菜單App仍未完成；不把Pi轉送或手機HFP原型算成原機直連成功。',
        '導航／麥克風停止，Android Auto／Google Maps延後；目前不要求接線、配對或人在場。',
    ]
    state.update(updated_utc=now.isoformat(), next_actions=copy.deepcopy(next_actions))
    state[FIELD] = copy.deepcopy(checkpoint)
    state['native_app_music'][FIELD] = copy.deepcopy(checkpoint)
    work = state['offline_24h_work_order']; work[FIELD] = copy.deepcopy(checkpoint)
    work['current_offline_line_status']['native_control_retention'] = 'Partial: host JSON gate rejects two candidate manifests; missing four functions and public object; no binary execution'
    turn = {'classification': 'native_music_host_metadata_guard_and_source_provenance_progress',
            'previous_goal_turn_classification': 'progress', 'validated_utc': now.isoformat(),
            'goal_status': 'active', 'full_goal_complete': False, 'required_work_remaining': True,
            'device_files_written': False,
            'reason': 'Actual guarded refusals replace unchecked all_passed declarations; source/compile provenance narrows the retention investigation without claiming native execution.'}
    state['last_goal_turn'] = copy.deepcopy(turn)
    for key in ('updated_utc', 'next_actions', 'offline_24h_work_order', FIELD, 'last_goal_turn'):
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state),
                  offline_24h_work_order=copy.deepcopy(work), last_goal_turn=copy.deepcopy(turn))
    public[FIELD] = copy.deepcopy(checkpoint)
    public['research_progress'].update(research_updated_utc=now.isoformat(), next=next_actions[0])
    report = before[FILES[3]].decode()
    card = ('<section class="card" id="native-music-control-retention-checkpoint-v1"><h2>原機藍牙音樂：控制入口完整性核對</h2>'
            f'<p>更新：<time datetime="{stamp}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>（台灣時間）</p>'
            '<p>已確認控制器原始碼存在，但兩份既有映像宣告均缺四個必要函式及公開介面表。新的主機檢查工具已拒絕這兩份候選，避免把編譯成功當作功能入口齊全。</p><ul>'
            '<li><strong>新證據：</strong>原編譯階段已缺同樣五個宣告，C／H快照雜湊與各階段紀錄一致；三筆連結紀錄皆啟用section GC。未新讀物件／ELF或執行原機程式。</li>'
            '<li><strong>名稱更正：</strong>ui_music_control_api是const struct介面物件，ARM32來源布局為36 bytes；前輪getter字樣不正確。</li>'
            '<li><strong>工具驗證：</strong>16項主機控制通過，涵蓋缺入口、錯誤物件型別、舊40-byte布局、舊來源雜湊、未定義符號及不同硬體；完整案例是合成JSON，不是原機載入成功。</li>'
            '<li><strong>原因仍待確認：</strong>連結器刪除未引用區段與現象相符；'
            '<a href="https://gcc.gnu.org/onlinedocs/gcc-14.3.0/gcc/Common-Variable-Attributes.html">GCC used保證編譯器產出</a>，'
            '而<a href="https://sourceware.org/binutils/docs/ld/Input-Section-Keep.html">linker保留需另外確認</a>。未核對完整linker script／map／物件，不能宣稱已證明或修復GC原因。</li>'
            '<li><strong>尚未達成：</strong>Garmin原機A2DP、手機直接出聲、菜單App、來源所有權與停止／重啟；没有可安裝原機包。</li></ul>'
            '<p>Android實驗APK仍供之後測試；導航與麥克風停止。目前不用接線或配對。工程估計不提高。</p></section>')
    marker = '<section class="card" id="native-music-control-retention-checkpoint-v1">'
    if marker in report:
        report, count = re.subn(re.escape(marker) + r'.*?</section>', lambda _: card, report, count=1, flags=re.S)
        require(count == 1, 'Native card replaced')
    else:
        anchor = '<section class="card" id="bluetooth-music-current-checkpoint-v1">'
        require(report.count(anchor) == 1, 'Current Android card anchor')
        report = report.replace(anchor, card + anchor, 1)
    report = report.replace('兩版控制器建置宣告缺四個函式與getter', '兩版控制器建置宣告缺四個函式與公開介面表')
    report, count = re.subn(r'<p id="offline-frontier-latest-v1">.*?</p>',
        lambda _: '<p id="offline-frontier-latest-v1">最新：原機控制入口檢查已拒絕缺函式的兩候選；介面物件名稱更正。Android實驗APK保留，音檔背景載入改善中；所有手機／車機直接出聲仍未驗證。</p>', report, count=1, flags=re.S)
    require(count == 1, 'Frontier updated')
    for name in ('report-updated-time', 'research-updated-time'):
        report, count = re.subn(r'<time id="' + name + r'" datetime="[^"]+">[^<]+</time>',
            lambda _: f'<time id="{name}" datetime="{stamp}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>', report, count=1)
        require(count == 1, 'Visible timestamp')
    expected_native = copy.deepcopy(old_native); expected_native[FIELD] = copy.deepcopy(checkpoint)
    require(state['native_app_music'] == expected_native and state['audio'] == old_audio
            and state['navigation_repair'] == old_nav, 'Historical/native status preserved')
    require(estimates == [public['research_progress']['estimate_percent'], [p['estimate_percent'] for p in public['research_progress']['phases']]], 'No inflated estimate')
    out = ROOT / 'staging' / ('native-music-retention-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(mode=0o700)
    for path, data in before.items():
        (out / (path.replace('/', '__') + '.gz')).write_bytes(gzip.compress(data, mtime=0))
    for path, value in zip(FILES[:4], (state, task, public, report)):
        replace(path, value)
    served, response = http(web['url'])
    require(served == report.encode() and service() == current_service, 'Fresh exact report, server unchanged')
    web.update(updated_utc=now.isoformat(), HTTP_status=response['status'], local_report_sha256=sha(served),
               served_report_sha256=sha(served), report_bytes=len(served), service=current_service,
               service_not_restarted=True, offline_24h_work_order=copy.deepcopy(work), last_goal_turn=copy.deepcopy(turn))
    web[FIELD] = copy.deepcopy(checkpoint)
    web['progress_display_verified'].update(report_updated_time=stamp, research_updated_time=stamp)
    replace(FILES[4], web)
    fresh = [json.loads((ROOT / path).read_bytes()) for path in (FILES[0], FILES[1], FILES[2], FILES[4])]
    require(fresh[0] == fresh[2]['deep_research'] and all(d[FIELD] == checkpoint and not d['goal_complete'] for d in fresh), 'Canonical equality after publication')
    create(out / 'fresh-readback.json', {'all_passed': True, 'updated_at_Taiwan': stamp,
           'report_url': web['url'], 'service': current_service, 'device_IO': False, 'full_goal_complete': False})
    print(json.dumps({'all_passed': True, 'snapshot': str(out.relative_to(ROOT)),
                      'updated_at_Taiwan': stamp, 'native_install_candidate': False, 'device_IO': False}))


if __name__ == '__main__':
    main()
