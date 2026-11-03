#!/usr/bin/env python3
"""Publish bounded decoder progress and full-linked image, preserving prior evidence."""
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from zoneinfo import ZoneInfo
import hashlib
import html
import json
import re

ROOT = Path(__file__).resolve().parents[1]
BASE = 'staging/native-player-decoder-scope/'
RUNTIME = BASE + 'runtime/'
PREFIX = 'evidence/firmware-analysis/native-decoder-cold-prefix-emulation.json'
PARTIAL = BASE + 'gui-static/decoder-native-prefix-partial-verification.json'
IMAGE = BASE + 'music-image/verification.json'
CONTRACT = BASE + 'gui-static/decoder-actor-observer-contract-v2.json'
PACKAGE = BASE + 'package-static/native-voice-code-acceptance-boundary.json'
PEER = BASE + 'fp-static/decoder-native-scope-and-image-peer-review.json'
EXTRAS = [
    BASE + 'gui-static/dispatcher-settings-2cabfa-boundary-contract.json',
    BASE + 'gui-static/runner-wiring-review-a9deadbb.json',
    BASE + 'gui-static/next-page-and-root-bounded-caller-inputs.json',
]


def read(path):
    return json.loads((ROOT / path).read_text())


@lru_cache(None)
def sha(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def registry(entries, target=None):
    for path, digest in entries.items():
        assert sha(path) == digest, path
        if target is not None:
            assert path not in target or target[path] == digest, path
            target[path] = digest


def write(path, obj):
    (ROOT / path).write_text(json.dumps(obj, ensure_ascii=False, indent=2) + '\n')


def reference(path, **fields):
    return dict(evidence=path, evidence_sha256=sha(path), **fields)


def main():
    previous = read(BASE + 'previous-audit.json')
    before = read(BASE + 'previous-state.json')
    prior_public = read(BASE + 'previous-public.json')
    for row in read(BASE + 'previous-checkpoint.json')['snapshots']:
        assert sha(row['snapshot']) == row['sha256']
    registry(previous['protected_sources'])
    assert previous['all_passed'] and len(previous['scope_checks']) == 35
    assert len(previous['protected_sources']) == 892
    state, task, public = [read(p) for p in (
        'evidence/deep-research-state.json', 'evidence/task-state.json', 'reports/findings.json')]
    app = state['native_app_music']
    assert app['static_findings'] == before['native_app_music']['static_findings']
    assert len(app['static_findings']) == 141
    assert public['research_progress']['completed'] == prior_public['research_progress']['completed']
    assert len(public['research_progress']['completed']) == 113
    docs = {p: read(p) for p in (PREFIX, PARTIAL, IMAGE, CONTRACT, PACKAGE, PEER, *EXTRAS)}
    for doc in docs.values():
        registry(doc['source_sha256'])
        for field in ('artifacts_sha256', 'verified_protected_sources', 'verified_runtime_source_dependencies'):
            if field in doc:
                registry(doc[field])
    meta, probe = read(RUNTIME + 'terminal-metadata.json'), read(RUNTIME + 'terminal-probe.json')
    assert meta['session_id'] == 44634 and meta['terminal_exit_code'] == 1
    assert meta['authoritative_terminal_result_received_from_exec']
    assert meta['error'] == 'Native raw mutex pointer/actor/storage differs'
    assert meta['cold_prefix_full_guards_passed'] and not meta['body_full_guards_passed']
    assert probe['callback_entry_seen'] and not probe['callback_return_seen']
    prefix, partial, image = docs[PREFIX], docs[PARTIAL], docs[IMAGE]
    assert prefix['all_passed'] and partial['all_passed'] and image['all_passed']
    assert prefix['native_cache_CPU_store_events'] == 356835
    assert len(partial['native_raw_operations']) == 4 and len(partial['exact_native_function_returns']) == 6
    assert image['actual_ARM_ELF']['undefined_symbols'] == []
    assert image['bounded_ARM_controls']['count'] == 11
    assert docs[PACKAGE]['all_exact_assertions_passed']
    assert docs[CONTRACT]['pure_host_controls']['passed']
    assert docs[PEER]['all_passed'] and all(docs[PEER]['assertions'].values())
    app['static_findings'].update({
        'native_decoder_actor_observer_v2_contract': reference(CONTRACT,
            pure_host_shape_cases=10, native_full_body_verified=False),
        'native_UI_music_single_bootstrap_full_linked_image': reference(IMAGE,
            ARMv6_ET_EXEC=True, unresolved_symbols=0, bounded_ARM_assertions=11,
            host_groups=8, original_TTS_interfaces_preserved=40,
            native_owner_GUI_audio_integration_verified=False, device_install_candidate=False),
        'native_voice_code_acceptance_crypto_boundary_followup': reference(PACKAGE,
            static_only=True, native_SIG_requester_identified=False,
            modified_code_accepted_on_device=False),
        'native_decoder_run_complete_cold_prefix': reference(PREFIX,
            complete_prefix_cases=1, boot_zones=5, component_zones=22,
            native_cache_CPU_events=356835, later_body_terminal_exit_code=1,
            full_Dispatcher_body_or_foreground_verified=False),
        'native_decoder_query_partial_and_MainMenu_entry': reference(PARTIAL,
            session_id=44634, actual_terminal_exit_code=1,
            raw_native_lock_operations_returned=4, original_function_returns=6,
            native_no_driver_status=8, cold_zero_driver_fixture=True,
            MainMenu_constructor_entered=True, MainMenu_constructor_returned=False,
            settings_guard_caller='0x2cabfa', settings_backend='0x148e6cc',
            next_settings_boundary=EXTRAS[0], next_settings_boundary_sha256=sha(EXTRAS[0]),
            independent_peer_review=PEER, independent_peer_review_sha256=sha(PEER),
            complete_body_foreground_or_physical_App_verified=False),
    })
    app['development_observations']['latest_decoder_query_partial'] = app['static_findings']['native_decoder_query_partial_and_MainMenu_entry']
    app['development_observations']['latest_full_linked_UI_music_image'] = app['static_findings']['native_UI_music_single_bootstrap_full_linked_image']
    app['development_observations']['full_linked_image_still_needs_native_owner_session_and_GUI_glue'] = True
    now = datetime.now(timezone.utc)
    focus = ('Recover actual Dispatcher settings lock caller2CABFA/backend148E6CC with original actor, '
        'native tag and released stale links; NEW source/namespace, no backend reset or inherited guard deletion. '
        'Continue original MainMenu40434C construction, GIR/font/cache guards, callback return and actual foreground/touch. '
        'Integrate the new fully-linked single-bootstrap image with persistent source-worker owner loop, '
        'native channel8 exclusive/session and returned cancel barrier. Independently recover native changed-package '
        'acceptance and SIG requester. Direct-phone A2DP remains unverified. Pairing first; mic canceled; '
        'fidelity deferred; Android Auto later; Maps deferred; goal active/no-achieve.')
    state.update(updated_utc=now.isoformat(),
        current_priority='Original foreground player and native owner/session integration; Bluetooth music; active goal/no-achieve.')
    state['next_actions'][0] = focus
    state['next_actions'][1] = ('Actual queued Dispatcher passed decoder query with absent-driver status8 and entered '
        'original MainMenu40434C, then stopped at settings mutex2CABFA. Still require constructor/callback return '
        'and foreground/touch; no App icon on device.')
    app['remaining_work'] = state['next_actions'][:4]
    state['parallel_research'].update(tasks=[
        'native decoder query and MainMenu settings boundary',
        'full-linked single-bootstrap music image and bounded cold loader controls',
        'package signature boundary and independent journal/image review'],
        continued_round_completed=True, agents_currently_running=False)
    state['last_goal_turn'].update(classification='progress', validated_utc=now.isoformat(),
        previous_state_snapshot=BASE + 'previous-state.json',
        previous_current_audit_snapshot=BASE + 'previous-audit.json',
        previous_turn_revalidation='35-scope141-finding checkpoint and892 protected files preserved.',
        focused_evidence=PREFIX, focused_evidence_sha256=sha(PREFIX),
        latest_dispatcher_development_evidence=RUNTIME + 'terminal-probe.json',
        latest_dispatcher_development_evidence_sha256=sha(RUNTIME + 'terminal-probe.json'),
        latest_dispatcher_runtime_session_id=44634, latest_dispatcher_terminal_exit_code=1,
        latest_dispatcher_run_full_scoped_final_guards_passed=False,
        latest_callback_body_executed=True, latest_callback_body_returned=False,
        latest_cold_prefix_full_scoped_guards_passed=True,
        first_native_C_to_D_FP_exchange_verified=True,
        complete_native_Dispatcher_FP_integration_verified=False,
        native_foreground_or_multiowner_FP_verified=False,
        native_MainMenu_constructor_entry_verified=True,
        native_MainMenu_constructor_return_verified=False,
        native_decoder_query_partial_verified=True, native_decoder_hardware_init_verified=False,
        new_music_control_prototype=IMAGE, new_music_control_prototype_sha256=sha(IMAGE),
        full_linked_single_bootstrap_image_verified_offline=True,
        native_owner_GUI_audio_integration_verified=False,
        device_io=False, device_files_written=False, automatic_calls_or_sound=False,
        native_firmware_or_research_package_written=False, next_focus=focus,
        goal_status='active', full_goal_complete=False,
        reasons=[
            'Complete cold prefix independently verified; later terminal body failure retained separately.',
            'Original decoder locks/query returned under declared cold-zero absent-driver input; MainMenu ctor entry observed.',
            'Fully-linked ARM image has zero unresolved symbols; 11 bounded loader/ARM assertions and8 host groups pass.',
            'Native GUI/audio/session integration and physical modified-package acceptance remain unverified.'])
    for key in ('updated_utc', 'current_priority', 'next_actions', 'last_goal_turn', 'parallel_research'):
        task[key] = state[key]
    public.update(updated=now.isoformat(), deep_research=state)
    progress = public['research_progress']
    details = [
        '新增的離線試跑再次完成冷啟動與十一個介面準備步驟；整個字型快取和記憶體歷史獨立核對。後續首頁建立仍停止，成功的前段和失敗的後段分開保留。',
        '原廠解碼器查詢走過四次鎖定／釋放及六個函式返回，繼續進到首頁建立程式。這次輸入是未初始化硬體驅動的冷啟動資料；原廠確實回傳無驅動狀態，沒有證明音訊硬體已啟動。',
        '首頁建立在讀取設定的原廠鎖操作停止，停止位置與實際失敗結果已封存。尚未完成首頁建立返回、前景顯示或觸控；局部記憶體核對不能當作完整 App 成功。',
        '播放器選單與啟停骨架已完成整體 ARM 編譯，十二個待接符號全部解析；十一項有界載入／ARM 檢查及八組主機測試通過，保留四十個原廠語音介面。音訊擁有權、工作程序及介面仍待整合，沒有可安裝的實機程式包。',
        '修改程式包檢查已區分語音載入、韌體更新與地圖授權的流程；尚未找出語音程式簽章的完整要求，也未證明車機會接受修改後程式。接著先完成前景播放器與原生音訊，手機直接藍牙播放仍待實現。',
    ]
    progress['completed'].extend(details)
    progress['phases'][4]['completed'].extend(details[1:3])
    progress.update(research_updated_utc=now.isoformat(),
        next='完成原廠首頁建立與前景觸控，接入已整體編譯的播放器及音訊擁有權／工作程序；同步驗證修改程式包與手機直接藍牙音樂。')
    progress['phases'][4]['next'] = progress['next']
    assert progress['estimate_percent'] == 33 and progress['phases'][4]['estimate_percent'] == 20
    card = '<div class="card"><h2>最新離線進展：播放器整體編譯完成，首頁建立流程前進</h2>'
    card += '<p><strong>播放器已完成整體 ARM 編譯：</strong>十二個待接符號全部解析；十一項有界載入／ARM 檢查及八組主機測試通過，保留四十個原廠語音介面。尚需接入原廠介面、音訊擁有權與工作程序。</p>'
    card += '<p><strong>原廠首頁流程有前進：</strong>完整冷啟動再次通過，選單程序走過原廠解碼器查詢，進到首頁建立程式；這次查詢使用未初始化硬體驅動的冷啟動輸入，原廠回傳無驅動狀態，沒有證明音訊硬體已啟動。</p>'
    card += '<p>接著在首頁讀取設定的原廠鎖操作停止，<strong>尚未完成前景顯示、觸控或實機 App 安裝。</strong>修改程式包的簽章要求與車機接受能力、手機直接連 Garmin 播音樂仍待驗證。這輪執行備份韌體的離線模擬，沒有改寫車機、發出來電或播放聲音。</p>'
    card += '<p>下一步完成首頁建立及前景觸控，再接入播放器的原生音訊資源與工作程序。整體里程碑估計維持 33%，App 整合約 20%；百分比是研究估計。目前沒有新的實機操作需求。現場配對立即優先；麥克風取消、音質精修擱置，Android Auto 排後，Google Maps 暫緩。</p></div>'
    report = (ROOT / 'reports/nuvi2565RT.html').read_text()
    report, count = re.subn(r'<div class="card"><h2>最新離線進展：完整啟動後，選單程序已接到原廠事件</h2>.*?</div>', lambda _: card, report, count=1, flags=re.S)
    assert count == 1
    report, count = re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',
        lambda m: m[1] + m[2] + ''.join('<li>' + html.escape(x) + '</li>' for x in details) + m[3], report, count=1, flags=re.S)
    assert count == 1
    report, count = re.subn(r'<p><strong>下一步：</strong>.*?</p>',
        lambda _: '<p><strong>下一步：</strong>' + html.escape(progress['next']) + ' 目前沒有新的實機操作需求。</p>', report, count=1)
    assert count == 1
    report, count = re.subn(r'<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>.*?</td></tr>',
        lambda _: '<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>' + html.escape(progress['next']) + '</td></tr>', report, count=1)
    assert count == 1
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    iso = local.isoformat(timespec='seconds')
    for name in ('report-updated-time', 'research-updated-time'):
        report, count = re.subn(r'<time id="' + name + r'" datetime="[^"]+">[^<]+</time>',
            '<time id="' + name + '" datetime="' + iso + '">' + local.strftime('%Y/%m/%d %H:%M:%S') + '</time>', report, count=1)
        assert count == 1
    assert len(app['static_findings']) == 146 and len(progress['completed']) == 118
    for path, doc in (('evidence/deep-research-state.json', state), ('evidence/task-state.json', task), ('reports/findings.json', public)):
        write(path, doc)
    (ROOT / 'reports/nuvi2565RT.html').write_text(report)
    print(json.dumps(dict(findings=146, completed_items=118, estimate_percent=33, App_estimate_percent=20, updated_Taiwan=iso)))


if __name__ == '__main__':
    main()
