#!/usr/bin/env python3
"""Publish exact cold-prefix success and separately failed native body attempt."""
from pathlib import Path
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from functools import lru_cache
import hashlib, html, json, re

ROOT = Path(__file__).resolve().parents[1]
BASE = 'staging/native-player-dispatcher-native-body/'
RUNTIME = BASE + 'runtime/'
PREFIX = 'evidence/firmware-analysis/native-dispatcher-cold-prefix-emulation.json'
STATIC = {
    'native_Dispatcher_multiowner_FP_integrated_observer': BASE + 'fp-static/native-dispatcher-vfp-integration-contract-5dbe3df3dc3f.json',
    'native_Dispatcher_actor_observer_and_boundary': BASE + 'gui-static/dispatcher-actor-observer-integration-review.json',
    'native_UI_music_single_bootstrap_REL_preflight': BASE + 'music-static/verification.json',
}
PEERS = [
    BASE + 'fp-static/runner-peer-review-a0315e.json',
    BASE + 'fp-static/first-native-Dispatcher-FP-exchange.json',
    BASE + 'gui-static/runner-prefix-peer-review-a0315e.json',
    BASE + 'music-static/single-image-link-binding-review.json',
]

def read(p):
    return json.loads((ROOT / p).read_text())

@lru_cache(None)
def sha(p):
    return hashlib.sha256((ROOT / p).read_bytes()).hexdigest()

def registry(d):
    for p, s in d.items():
        assert sha(p) == s, p

def write(p, d):
    (ROOT / p).write_text(json.dumps(d, ensure_ascii=False, indent=2) + '\n')

def main():
    before = read(BASE + 'previous-state.json')
    previous = read(BASE + 'previous-audit.json')
    for row in read(BASE + 'previous-checkpoint.json')['snapshots']:
        assert sha(row['snapshot']) == row['sha256']
    registry(previous['protected_sources'])
    assert previous['all_passed'] and len(previous['scope_checks']) == 33
    assert len(previous['protected_sources']) == 781
    state, task, public = [read(p) for p in ['evidence/deep-research-state.json', 'evidence/task-state.json', 'reports/findings.json']]
    app = state['native_app_music']
    assert app['static_findings'] == before['native_app_music']['static_findings']
    assert len(app['static_findings']) == 136 and len(public['research_progress']['completed']) == 108
    meta, probe, prefix = read(RUNTIME + 'terminal-metadata.json'), read(RUNTIME + 'terminal-probe.json'), read(PREFIX)
    assert meta['session_id'] == 67576 and meta['terminal_exit_code'] == 1
    assert meta['authoritative_terminal_result_received_from_exec']
    assert not meta['completed'] and not meta['body_full_guards_passed']
    assert probe['callback_entry_seen'] and not probe['callback_return_seen']
    assert '0x396b4e' in meta['error']
    assert prefix['all_passed'] and prefix['case_count'] == 1
    assert prefix['subsequent_body_terminal_exit_code'] == 1
    registry(prefix['source_sha256'])
    for k, p in STATIC.items():
        d = read(p)
        registry(d['source_sha256'])
        if 'verified_protected_sources' in d:
            registry(d['verified_protected_sources'])
        app['static_findings'][k] = dict(evidence=p, evidence_sha256=sha(p),
            native_full_body_or_foreground_or_device_App_verified=False, device_io=False, sounds_emitted=False)
    for p in PEERS:
        registry(read(p)['source_sha256'])
    app['static_findings']['native_Dispatcher_multiowner_FP_integrated_observer'].update(
        peer_review=PEERS[0], peer_review_sha256=sha(PEERS[0]),
        partial_native_exchange_proof=PEERS[1], partial_native_exchange_proof_sha256=sha(PEERS[1]),
        first_native_C_to_D_save_and_retry_verified=True, three_stage_native_exchange_verified=False)
    app['static_findings']['native_Dispatcher_actor_observer_and_boundary'].update(
        peer_review=PEERS[2], peer_review_sha256=sha(PEERS[2]),
        next_native_mutex_caller='0x396b4e', original_mutex_scope_not_yet_admitted=True)
    music = read(STATIC['native_UI_music_single_bootstrap_REL_preflight'])
    assert music['all_passed'] and music['host_tests']['group_count'] == 8 and music['host_ASan_UBSan']
    app['static_findings']['native_UI_music_single_bootstrap_REL_preflight'].update(
        compiled_ARMv6_REL=True, complete_host_scenarios=1, host_control_groups=8,
        remaining_external_symbols=12, link_binding_review=PEERS[3], link_binding_review_sha256=sha(PEERS[3]),
        device_install_candidate=False)
    app['static_findings']['native_Dispatcher_complete_cold_prefix_verified'] = dict(
        evidence=PREFIX, evidence_sha256=sha(PREFIX), cases=1, all11_helpers_returned=True,
        boot_zones=5, component_zones=22, whole_cache_bytes=786432, native_cache_CPU_events=356834,
        subsequent_body_exit_code=1, full_body_or_foreground_verified=False)
    attempt = dict(evidence=RUNTIME + 'terminal-metadata.json', evidence_sha256=sha(RUNTIME + 'terminal-metadata.json'),
        probe=RUNTIME + 'terminal-probe.json', probe_sha256=sha(RUNTIME + 'terminal-probe.json'),
        actual_terminal_exit_code=1, session_id=67576, cold_prefix_full_guards_passed=True,
        queued_original_Dispatcher_entered=True, original_first_C_to_D_FP_save_and_retry_passed=True,
        callback_returned=False, full_body_guards_passed=False, error=meta['error'],
        native_App_direct_phone_music_or_modified_package_acceptance_verified=False,
        partial_zone_guards_are_not_full_body_guards=True, device_io=False, sounds_emitted=False)
    app['static_findings']['native_Dispatcher_body_terminal_first_FP_exchange'] = attempt
    app['development_observations']['native_Dispatcher_body_terminal_first_FP_exchange'] = attempt
    now = datetime.now(timezone.utc)
    focus = ('Recover strict original mutex actor396B3E/39720C backend2D1654C and the subsequent36944A bus-slot/driver callback scope, '
        'using sealed67576 cold prefix and actual first C→D save/noDrestore evidence. Run a NEW complete cold Dispatcher attempt; '
        'preserve all source/terminal guards. Still require D→C save+clone40/restoreC, C→D restoreD, callback return and full body guards. '
        'Then foreground/touch and single-bootstrap UI+music relink with exact data/BSS placement and owned-anchor accessor. '
        'Native package acceptance and direct-phone A2DP remain unverified. Pairing first; mic canceled; fidelity deferred; AA later; Maps deferred; goalactive/no-achieve.')
    state.update(updated_utc=now.isoformat(), current_priority='Original Dispatcher mutex/driver scope, foreground player and native Bluetooth music; active goal/no-achieve.')
    state['next_actions'][0] = focus
    state['next_actions'][1] = 'Complete original foreground/canvas/touch and native Dispatcher callback return. New67576 enters405340 and first native D floating-point use, but stops at396B4E; no visible App or menu icon on device.'
    app['remaining_work'] = state['next_actions'][:4]
    state['parallel_research'].update(tasks=['native FP integration and independent first-exchange replay',
        'native Dispatcher actor and next mutex/driver scope', 'single-bootstrap music REL and exact next-image link requirements'],
        continued_round_completed=True, agents_currently_running=False)
    state['last_goal_turn'].update(classification='progress', validated_utc=now.isoformat(),
        previous_state_snapshot=BASE+'previous-state.json', previous_current_audit_snapshot=BASE+'previous-audit.json',
        previous_turn_revalidation='Fresh33-scope136-finding checkpoint/781 protected sources snapshotted.',
        focused_evidence=PREFIX, focused_evidence_sha256=sha(PREFIX),
        latest_dispatcher_development_evidence=RUNTIME+'terminal-probe.json',
        latest_dispatcher_development_evidence_sha256=sha(RUNTIME+'terminal-probe.json'),
        latest_dispatcher_runtime_session_id=67576, latest_dispatcher_terminal_exit_code=1,
        latest_dispatcher_run_full_scoped_final_guards_passed=False, latest_callback_body_executed=True,
        latest_callback_entry_full_scoped_guards_passed=True, latest_callback_body_returned=False,
        latest_cold_prefix_full_scoped_guards_passed=True, first_native_C_to_D_FP_exchange_verified=True,
        complete_native_Dispatcher_FP_integration_verified=False, native_foreground_or_multiowner_FP_verified=False,
        new_music_control_prototype=STATIC['native_UI_music_single_bootstrap_REL_preflight'],
        new_music_control_prototype_sha256=sha(STATIC['native_UI_music_single_bootstrap_REL_preflight']),
        device_io=False, device_files_written=False, automatic_calls_or_sound=False,
        native_firmware_or_research_package_written=False, next_focus=focus, goal_status='active', full_goal_complete=False,
        reasons=['Complete cold prefix independently replayed before the later failed body, retaining all11 helpers and full memory guards.',
            'Original queued Dispatcher actually performs first native C→D FP save and retry; terminal396B4E boundary preserved.',
            'Single-bootstrap UI/music REL and8 host control groups pass, with12 external link boundaries and no native App installation claim.'])
    for k in ['updated_utc','current_priority','next_actions','last_goal_turn','parallel_research']:
        task[k]=state[k]
    public.update(updated=now.isoformat(), deep_research=state)
    progress = public['research_progress']
    details = [
        '完整冷啟動與十一個介面準備步驟再次通過；五個啟動區域、二十二個元件區域及 786,432 位元組字型快取獨立核對。證據在後續選單程式開始前封存，後段停止不會混入這份成功結果。',
        '原廠事件建立、註冊、排隊與等待流程確實進入選單派送程式；第一次改由選單工作程序使用浮點運算時，原廠指令保存上一個程序的資料並正確返回。仍未完成後續往返恢復與完整選單功能。',
        '選單派送測試在新的原廠鎖呼叫 0x396B4E 停止，已保留實際失敗結果。停止前浮點、堆疊與記憶體的局部核對通過，但程式尚未完整返回，不能當作前景介面或實機 App 成功。',
        '單一啟動入口的播放器選單與啟停骨架已編譯為 ARMv6 程式；八組主機控制及記憶體檢查通過。尚有十二個外部接線符號，沒有在 Garmin 執行、顯示或接受修改程式包。',
        '下一個整合映像的接線條件已列清：啟動記號需放在初始化清零範圍之外、音訊資源需有真正的擁有權存取入口；停止需等待取消完成及資源釋放，不能以函式回傳成功代替。',
    ]
    progress['completed'].extend(details)
    progress['phases'][4]['completed'].extend(details[:2])
    progress.update(research_updated_utc=now.isoformat(), next='還原選單程序新鎖與後續驅動呼叫，完成派送返回與前景觸控，再把單一啟動播放器接入；同步驗證修改程式包與手機直接藍牙音樂。')
    progress['phases'][4]['next']=progress['next']
    assert progress['estimate_percent']==33 and progress['phases'][4]['estimate_percent']==20
    card='<div class="card"><h2>最新離線進展：完整啟動後，選單程序已接到原廠事件</h2>'
    card+='<p><strong>完整冷啟動與十一個介面準備步驟通過：</strong>啟動資料、元件記憶體及整個字型快取已獨立核對。接著由原廠事件排隊與等待流程進入選單程序，第一次工作切換的浮點保存與返回也通過。</p>'
    card+='<p>後續在尚未還原的原廠鎖操作停止，<strong>選單程序還沒有完整返回，沒有前景播放器或可安裝到車機的 App。</strong>這輪是執行備份韌體的離線模擬；沒有改寫車機、發出來電或播放聲音。完整啟動成功與後段停止各自保留。</p>'
    card+='<p>播放器選單與啟動／停止骨架已編譯，八組主機控制與記憶體檢查通過；尚有十二個外部接線符號與原生介面待接。手機直接連 Garmin 播音樂、修改程式包接受及正常導航共存仍待驗證。</p>'
    card+='<p>下一步還原新的鎖與驅動流程，再完成前景觸控及播放器整合。整體里程碑估計維持 33%，App 整合約 20%；百分比是研究估計。目前沒有新的實機操作需求。現場配對立即優先；麥克風取消、音質精修擱置，Android Auto 排後，Google Maps 暫緩。</p></div>'
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    report,n=re.subn(r'<div class="card"><h2>最新離線進展：原廠浮點保存與恢復小型測試通過</h2>.*?</div>', lambda _:card,report,count=1,flags=re.S)
    assert n==1
    report,n=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda m:m[1]+m[2]+''.join('<li>'+html.escape(x)+'</li>' for x in details)+m[3],report,count=1,flags=re.S)
    assert n==1
    report,n=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda _:'<p><strong>下一步：</strong>'+html.escape(progress['next'])+' 現場配對立即優先，目前沒有新的實機操作需求。</p>',report,count=1)
    assert n==1
    report,n=re.subn(r'<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>.*?</td></tr>',lambda _:'<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>'+html.escape(progress['next'])+'</td></tr>',report,count=1)
    assert n==1
    local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds')
    for name in ['report-updated-time','research-updated-time']:
        report,n=re.subn(r'<time id="'+name+r'" datetime="[^"]+">[^<]+</time>','<time id="'+name+'" datetime="'+iso+'">'+local.strftime('%Y/%m/%d %H:%M:%S')+'</time>',report,count=1)
        assert n==1
    assert len(app['static_findings'])==141 and len(progress['completed'])==113
    for p,d in [('evidence/deep-research-state.json',state),('evidence/task-state.json',task),('reports/findings.json',public)]:write(p,d)
    (ROOT/'reports/nuvi2565RT.html').write_text(report)
    print(json.dumps(dict(findings=141,completed_items=113,estimate_percent=33,App_estimate_percent=20,updated_Taiwan=iso)))

if __name__=='__main__':main()
