#!/usr/bin/env python3
"""Publish scoped dispatcher construction and the distinct-timer context boundary."""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import hashlib, html, json, re
from analyze_native_sections import ROOT

BASE = 'staging/native-player-reacquire/'
PROOF = 'evidence/firmware-analysis/native-dispatcher-reacquire-emulation.json'

def read(path): return json.loads((ROOT / path).read_text())
def sha(path): return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
def write(path, value): (ROOT / path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')

def main():
    previous = read(BASE + 'previous-checkpoint.json')
    before, prior = read(previous['state']['path']), read(previous['audit']['path'])
    for row in previous.values(): assert sha(row['path']) == row['sha256']
    assert prior['all_passed'] and len(prior['scope_checks']) == 22
    assert prior['state_sha256'] == previous['state']['sha256']
    state, task, public = [read(p) for p in ['evidence/deep-research-state.json', 'evidence/task-state.json', 'reports/findings.json']]
    app = state['native_app_music']
    assert app['static_findings'] == before['native_app_music']['static_findings'] and len(app['static_findings']) == 93
    assert not state['user_resting'] and state['attended_testing']['user_present'] and not task['user_away']
    proof = read(PROOF)
    static_path = BASE + 'condition-timer-owner-static-preflight.json'
    index_path = BASE + 'preserved-development-evidence-index.json'
    static, index = read(static_path), read(index_path)
    for doc in [proof, static]:
        for p, digest in doc['source_sha256'].items(): assert sha(p) == digest, p
    for p, digest in index['source_artifact_sha256'].items(): assert sha(p) == digest, p
    assert proof['all_passed'] and proof['case_count'] == 6 and len(proof['source_sha256']) == 102
    assert static['complete_bounded_CFG_count'] == 5
    meta_path = BASE + 'native-timer-context-boundary-terminal-metadata.json'
    meta = read(meta_path); probe = read(meta['probe'])
    assert meta['session_id'] == 80740 and probe['registers']['pc'] == '0x358ec4'
    assert not probe['completed'] and not probe['full_scoped_final_guards_passed']
    assert probe['original_timer_initialization']['F090A0_distinct_from_F09090']
    app['static_findings']['native_dispatcher_reacquisition'] = dict(
        evidence=PROOF, evidence_sha256=sha(PROOF), all_passed=True, case_count=6, source_artifact_count=102,
        memory_construction_on_equal_fictional_thread_only=True,
        original_reacquire_entry='0x3009a0', original_reacquire_caller='0x3ec692',
        original_release='0x300bb8', original_singleton='0x5d2130', native_singleton_allocation_bytes=0x4ba8,
        actual_wait_return_observed=True, lower_wait_recursive_immediate_return=True,
        resident_condition_native_recursion_after=1, condition_token_retained=True,
        real_blocking_wakeup_scheduler_foreground_safe_lifetime_or_device_App_verified=False,
        preserved_development_evidence=index_path, preserved_development_evidence_sha256=sha(index_path),
        device_io=False, sounds_emitted=False, limits=proof['limits'])
    app['development_observations']['dispatcher_with_distinct_native_timer_owner'] = dict(
        static_evidence=static_path, static_evidence_sha256=sha(static_path), complete_bounded_CFG_count=5,
        terminal_metadata=meta_path, terminal_metadata_sha256=sha(meta_path),
        development_evidence=meta['probe'], development_evidence_sha256=sha(meta['probe']),
        preserved_development_evidence=index_path, preserved_development_evidence_sha256=sha(index_path),
        session_id=80740, terminal_exit_code=1, original_timer_TCB='0x2d227c8',
        original_timer_builder='0x358bf8', host_seeded_timer_owner_pointer=False,
        native_condition_owner_transfer_to_distinct_timer_verified=True,
        original_context_restore_boundary_reached='0x358ec4', original_context_restore_executed=False,
        original_wait_returned=False, original_singleton_returned=False, full_scoped_final_guards_passed=False,
        inherited_raw_same_owner_literal_not_authoritative=True,
        real_event_delivery_controller_foreground_or_device_App_verified=False, device_io=False, sounds_emitted=False)
    now = datetime.now(timezone.utc)
    focus = ('Restore original task/ready/idle/controller inventory and kernel context restore358EC4 before actual timer/dispatcher event delivery. '
        'OriginalF6E48/353D3C/358BF8 create timer TCB2D227C8, distinct from current fictional TCB8800260; original300AE4 transfers condition owner to timer. '
        '80740 executes original releases, then original300A14 contention reaches358EC4 and stops before context restoration; no original wait/singleton return or final guards. '
        '6649 six complete memory-construction controls102 dependencies remain scoped to equal fictional current/constructor owner; lower wait is recursive immediate0 with recursion1 and retained condition token, not blocking/waking. '
        'Reuse exact prior timer/media-worker sources, preserve original MAIN and explicit fixtures; original2FCF44 wake is still ret0 fixture. '
        'Then complete singleton, original405340/controller/root foreground and safe lifecycle. Do not return fake wait success, host-write owner fields, or claim visible/device App.')
    state['next_actions'][0] = focus
    state.update(updated_utc=now.isoformat(), current_priority='Native player/menu App and direct phone Bluetooth music; scoped event-object construction passes, distinct native timer owner exposes original kernel context boundary. User present; pairing immediately preempts research. Goal active/no-achieve.')
    app['remaining_work'] = state['next_actions'][:4]
    state['attended_testing'].update(recorded_utc=now.isoformat(), current_attended_test='No new physical test needed now; recover original context/event scheduling offline.')
    turn = state['last_goal_turn']
    turn.update(classification='progress', previous_goal_turn_classification='progress', validated_utc=now.isoformat(),
        previous_state_snapshot=previous['state']['path'], previous_current_audit_snapshot=previous['audit']['path'],
        previous_turn_revalidation='Fresh22-scope checkpoint preserved;93 previous findings and35 selected frozen suites unchanged.',
        focused_evidence=PROOF, focused_evidence_sha256=sha(PROOF),
        latest_dispatcher_memory_controls_full_scoped_final_guards_passed=True,
        latest_dispatcher_development_evidence=meta['probe'], latest_dispatcher_development_evidence_sha256=sha(meta['probe']),
        latest_dispatcher_run_full_scoped_final_guards_passed=False,
        latest_native_timer_owner_initialized=True, latest_context_restore_boundary_reached='0x358ec4',
        latest_context_restore_executed=False, next_focus=focus, goal_status='active', full_goal_complete=False)
    turn['reasons'] = [
        'Six complete original bootstrap/RAII/diagnostic-registration/singleton memory controls102 exact dependencies, observed300BB8 release and native3009A0 caller3EC692 reacquire, all scoped final guards pass. Failed92146 retains full six-group intent and terminal proof.',
        'Equal fictional TCB control lower wait300A14 returns recursively with native recursion1 and retained condition token. No actual event delivery, real blocking/waking, cleanup, foreground or App success.',
        'Five bounded timer CFGs and two prior timer routes25 verified dependencies connect condition owner F090A0 to native timer producer. New80740 executes original timer creation and distinct-owner transfer, reaches358EC4 context boundary without executing context restore or completing singleton. Partial evidence and misleading inherited literal journal fields explicitly preserved.',
        'All93 previous findings and35 frozen suites retained. User present; no physical question/device I/O/write/install/call/sound or goal completion.']
    for key in ['updated_utc', 'current_priority', 'next_actions', 'last_goal_turn', 'attended_testing']: task[key] = state[key]
    public.update(deep_research=state, updated=now.isoformat())
    progress = public['research_progress']
    assert progress['estimate_percent'] == 32 and len(progress['completed']) == 65
    details = [
        '事件物件記憶體建立：補上原廠完整釋放與等待後重新鎖定，六組離線控制全數通過，原始事件物件配置與重用可返回；102 項來源與資料、程式區、配置邊界及備份資料庫檢查通過。此組使用相同模擬執行緒，等待是立即返回，尚不代表事件功能完成。',
        '原廠計時器依賴：五個完整函式核對後，試跑以原始流程建立不同的計時器執行緒，觀察同步鎖轉交；真正等待接著走到尚未模擬的核心切換入口。這次未完成物件建立，也未通過最終檢查；事件喚醒與排程仍在研究。']
    progress['completed'].extend(details)
    progress.update(research_updated_utc=now.isoformat(), next='補齊原廠核心的執行緒切換與事件傳送，再完成首頁前景顯示、操作和安全清理；之後驗證原機 App 與手機直接藍牙音樂。')
    progress['phases'][4]['next'] = '六組事件物件記憶體建立控制通過；不同計時器執行緒的等待走到核心切換入口，接事件喚醒與排程，再接前景顯示、操作與原機載入。'
    assert len(progress['completed']) == 67 and sum(p['weight'] * p['estimate_percent'] / 100 for p in progress['phases']) == 32
    card = '''<div class="card"><h2>最新離線進展：事件物件建立與原廠計時器依賴</h2>
<p><strong>六組事件物件記憶體建立控制全數通過。</strong>補上原廠釋放和重新鎖定指令後，原始初始化、鎖定、解鎖、登錄與物件配置能完成，重複取得可回傳同一物件。102 項來源與資料核對，以及原廠語音介面、程式區、配置邊界和備份資料庫檢查通過。</p>
<p>這六組使用相同的模擬執行緒，底層等待會立即返回，且同步鎖仍有保留狀態；它們驗證記憶體建立，尚未驗證真正的阻塞、喚醒、事件傳送與安全清理。先前失敗試跑與更正過的檢查條件均保留，沒有縮減失敗控制的數量。</p>
<p><strong>新的不同執行緒試跑，已走到核心切換入口。</strong>五個原廠函式核對後，用原始流程建立計時器執行緒，觀察同步鎖轉交給它；原始等待接著需要核心切換。模擬器目前在此入口停止，尚未執行切換，物件建立未返回、最終檢查未通過。接下來補齊執行緒、事件及排程依賴。</p>
<p><strong>播放器已接入原廠首頁初始化；頁面目前仍是隱藏、零尺寸。</strong>十五格菜單整合的既有離線結果仍有效；前景顯示、觸控、畫面提交、停止與清理、原機套件載入及手機直接藍牙音樂仍待驗證。研究套件僅供模擬，未安裝到車機。</p>
<p>整體約 32%，是研究里程碑的加權估計。目前無需插機或重做音訊測試；有具體測試時會提供步驟，現場藍牙配對立即優先。麥克風取消、音質精修擱置，Android Auto 排後、Google Maps 暫緩。</p></div>'''
    report = (ROOT / 'reports/nuvi2565RT.html').read_text()
    report, count = re.subn(r'<div class="card"><h2>最新離線進展：原廠鎖定與同步初始化已驗證</h2>.*?</div>', lambda m: card, report, count=1, flags=re.S); assert count == 1
    report, count = re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)', lambda m: m[1] + m[2] + ''.join('<li>' + html.escape(d) + '</li>' for d in details) + m[3], report, count=1, flags=re.S); assert count == 1
    report, count = re.subn(r'<p><strong>下一步：</strong>.*?</p>', lambda m: '<p><strong>下一步：</strong>' + html.escape(progress['next']) + ' 現場配對立即優先，目前無需實機操作。</p>', report, count=1); assert count == 1
    report, count = re.subn(r'<tr><td>原生 App 入口與功能整合</td><td>10%</td><td>.*?</td></tr>', lambda m: '<tr><td>原生 App 入口與功能整合</td><td>10%</td><td>' + html.escape(progress['phases'][4]['next']) + '</td></tr>', report, count=1); assert count == 1
    local = now.astimezone(ZoneInfo('Asia/Taipei')); iso = local.isoformat(timespec='seconds'); display = local.strftime('%Y/%m/%d %H:%M:%S')
    for ident in ['report-updated-time', 'research-updated-time']:
        report, count = re.subn(r'<time id="' + ident + r'" datetime="[^"]+">[^<]+</time>', '<time id="' + ident + '" datetime="' + iso + '">' + display + '</time>', report, count=1); assert count == 1
    write('evidence/deep-research-state.json', state); write('evidence/task-state.json', task); write('reports/findings.json', public)
    (ROOT / 'reports/nuvi2565RT.html').write_text(report)
    print(json.dumps(dict(findings=94, memory_groups=6, estimate_percent=32, completed_items=67, updated_Taiwan=iso)))

if __name__ == '__main__': main()
