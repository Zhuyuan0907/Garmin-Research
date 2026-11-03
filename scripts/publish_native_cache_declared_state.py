#!/usr/bin/env python3
"""Publish the sealed native component endpoint and separately scoped static work."""
from pathlib import Path
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from functools import lru_cache
import hashlib, html, json, re

ROOT = Path(__file__).resolve().parents[1]
BASE = 'staging/native-player-cache-declared-followup/'
RUNTIME = 'staging/native-player-controller-gir-integration/runtime-cache-declared/'
PROOF = 'evidence/firmware-analysis/native-controller-gir-cache-declared-emulation.json'
STATIC = {
    'native_controller_GIR_cache_declared_review': BASE+'gui-static/cache-declared-review-3b190aa2cd83.json',
    'native_multiowner_FP_cold_boot_exchange_recipe': BASE+'fp-static/native-multiowner-fp-input-and-journal-recipe.json',
    'native_voice_SIG_OpenPGP_format': BASE+'package-static/vpm-sig-format-and-gate-preflight.json',
}
SUPPLEMENT = BASE+'fp-static/controller-terminal14246-fp-recipe-supplement.json'

def read(path): return json.loads((ROOT/path).read_text())
@lru_cache(None)
def sha(path): return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
def registry(values):
    for path, digest in values.items(): assert sha(path) == digest, path
def write(path, doc): (ROOT/path).write_text(json.dumps(doc, ensure_ascii=False, indent=2)+'\n')

def main():
    previous = read(BASE+'previous-checkpoint.json')
    for row in previous['snapshots']: assert sha(row['snapshot']) == row['sha256']
    prior, before = read(BASE+'previous-audit.json'), read(BASE+'previous-state.json')
    assert prior['all_passed'] and len(prior['scope_checks']) == 30 and len(prior['protected_sources']) == 665
    registry(prior['protected_sources'])
    state, task, public = [read(p) for p in ['evidence/deep-research-state.json', 'evidence/task-state.json', 'reports/findings.json']]
    app = state['native_app_music']
    assert app['static_findings'] == before['native_app_music']['static_findings'] and len(app['static_findings']) == 124
    assert len(public['research_progress']['completed']) == 96
    proof, meta = read(PROOF), read(RUNTIME+'terminal-metadata.json')
    registry(proof['source_sha256']); registry(proof['artifacts_sha256'])
    assert proof['all_passed'] and proof['case_count'] == 1 and proof['cases'][0]['passed']
    assert meta['session_id'] == 14246 and meta['terminal_exit_code'] == 0 and meta['full_scoped_final_guards_passed']
    assert meta['component_native_original_helpers_returned'] == 11 and not meta['device_io'] and not meta['sounds_emitted']
    for key, path in STATIC.items():
        doc = read(path); registry(doc['source_sha256'])
        for field in ['verified_protected_sources', 'rechecked_existing_source_registry']:
            if field in doc: registry(doc[field])
        app['static_findings'][key] = dict(evidence=path, evidence_sha256=sha(path), static_only=True,
            new_guest_execution=False, device_io=False, sounds_emitted=False,
            physical_App_or_package_acceptance_verified=False)
    registry(read(SUPPLEMENT)['source_sha256'])
    app['static_findings']['native_multiowner_FP_cold_boot_exchange_recipe'].update(
        terminal14246_supplement=SUPPLEMENT, terminal14246_supplement_sha256=sha(SUPPLEMENT),
        fresh_cold_input_and_original_FP_boot_required=True, multiowner_FP_exchange_executed=False,
        live_TCB_patch_or_FP_owner_reset_allowed=False)
    app['static_findings']['native_controller_GIR_cache_declared_full'] = dict(
        evidence=PROOF, evidence_sha256=sha(PROOF), terminal_metadata=RUNTIME+'terminal-metadata.json',
        terminal_metadata_sha256=sha(RUNTIME+'terminal-metadata.json'), session_id=14246, terminal_exit_code=0,
        full_scoped_final_guards_passed=True, native_original_helpers_returned=11,
        cold_component_scenario_count=1, whole_cache_bytes=786432, native_cache_CPU_store_events=356833,
        original_cache_allocations=280, original_cache_frees=59, original_font_read_bindings=112,
        independent_whole_zone_replays=19, readonly_raw_backup_font_inputs=True,
        native_menu_foreground_or_physical_App_verified=False, device_io=False, sounds_emitted=False)
    signature = read(STATIC['native_voice_SIG_OpenPGP_format'])
    app['package_signature'] = dict(latest_evidence=STATIC['native_voice_SIG_OpenPGP_format'],
        latest_evidence_sha256=sha(STATIC['native_voice_SIG_OpenPGP_format']),
        signature_file_format_identified=True, declared_algorithm='OpenPGP v4 DSA/SHA1',
        original_document_left16_digest_associations=3, compared_digest_bits=16,
        public_key_identified=False, full_DSA_verification=False, native_SIG_requester_or_enforcement_identified=False,
        modified_package_or_DLL_code_accepted_on_device=False,
        earlier_algorithm_unknown_artifacts_are_preserved_historical_observations=True)
    assert signature['acceptance_gate_status']['signature_file_format_identified']
    app['development_observations']['native_controller_GIR_cache_declared'] = app['static_findings']['native_controller_GIR_cache_declared_full']
    now = datetime.now(timezone.utc)
    focus = ('Create a new cold source and namespace: declare typed controller descriptor/metadata/pool before original358BF8; '
        'initialize original exit list and FP boot20ED68 once before first restore, keep native listener chain and task-specific pool/UND/FP journals. '
        'Repeat the complete sealed14246 native component endpoint with new prerequisites, then use original Signal/queue/controller wait '
        'to enter actual Dispatcher405340 and original MainMenu. Do not patch liveTCB or clear liveFPowner; no host Dispatcher call. '
        'Manager/clock actor, first true cross-owner FP restore, foreground/touch, single-bootstrap music/callback lifecycle, '
        'native SIG requester/enforcement and physical modified-code acceptance remain required. Preserve all terminal sources and old findings. '
        'Pairing first; microphone canceled; fidelity deferred; Android Auto later; Maps deferred.')
    state.update(updated_utc=now.isoformat(), current_priority='Native App foreground via original Dispatcher and cold task/FP inputs; active goal/no-achieve.')
    state['next_actions'][0] = focus; app['remaining_work'] = state['next_actions'][:4]
    state['parallel_research'].update(tasks=['native cache observer and full endpoint review',
        'native task/FP cold boot and cross-owner exchange recipe', 'original VPM signature format and native acceptance gate'],
        continued_round_completed=True, agents_currently_running=False)
    state['last_goal_turn'].update(classification='progress', previous_goal_turn_classification='progress', validated_utc=now.isoformat(),
        previous_state_snapshot=BASE+'previous-state.json', previous_current_audit_snapshot=BASE+'previous-audit.json',
        previous_turn_revalidation='Fresh30-scope124-finding checkpoint and665 protected sources verified and snapshotted before14246.',
        focused_evidence=PROOF, focused_evidence_sha256=sha(PROOF), latest_component_runtime_session_id=14246,
        latest_component_terminal_exit_code=0, latest_component_helpers_returned=11,
        latest_component_run_full_scoped_final_guards_passed=True, native_foreground_or_multiowner_FP_verified=False,
        original_signature_declared_format_identified=True, native_signature_enforcement_verified=False,
        next_focus=focus, goal_status='active', full_goal_complete=False,
        reasons=['Compiled component completed all11 original helpers on actual resident controller with full scoped endpoint guards.',
            'Whole786432-byte cache and19 guarded zones independently replayed; raw112 font inputs retain exact backup provenance.',
            'Three original SIGs declare OpenPGP v4 DSA/SHA1; left16 digest association is not public-key authentication or native enforcement.',
            'Cold multiowner FP inputs/boot are statically specified, not executed; no visible App, installation or direct-phone music claim.'])
    for key in ['updated_utc', 'current_priority', 'next_actions', 'last_goal_turn', 'parallel_research']: task[key] = state[key]
    public.update(deep_research=state, updated=now.isoformat())
    progress = public['research_progress']
    details = [
        '新增介面準備元件在原廠執行緒上完整返回：十一個初始化步驟全部完成，包含設定、圖形資源、外部字型、選單資料與 SQL 敘述收尾；這是離線執行結果，尚未顯示 App 前景或在實機安裝。',
        '完整元件終點的記憶體檢查通過：獨立重播十九個區域及 786432 位元組的原廠字型快取，核對 356833 次原指令寫入、280 次配置、59 次釋放及 112 次原始字型讀取；八份常駐字型串流保留，兩份缺少的字型維持原廠錯誤狀態。',
        '下一步跨執行緒浮點狀態測試已備妥冷啟動輸入與原指令觀察規則：需從新試跑建立合法的執行緒描述、記憶體池與原廠浮點啟動流程；不能直接修改上一輪仍存活的執行緒。這份計畫尚未執行。',
        '已解析三份原廠程式包的完整簽章格式：OpenPGP v4 宣告 DSA／SHA1，三份原始程式各自的摘要前 16 位吻合；完整公鑰驗證、車機簽章讀取者與強制政策仍未知，未製作或安裝修改包。',
    ]
    progress['completed'].extend(details)
    progress['phases'][4]['estimate_percent'] = 20
    progress['phases'][4]['completed'].append(details[0])
    weighted = sum(p['weight']*p['estimate_percent']/100 for p in progress['phases'])
    assert weighted == 33
    progress.update(estimate_percent=33, weighted_estimate_percent=weighted, research_updated_utc=now.isoformat(),
        next='以新冷啟動試跑驗證跨執行緒浮點狀態，再由原廠派送執行緒進入真正的選單畫面；同步追原機程式包簽章接受流程。')
    progress['phases'][4]['next'] = progress['next']
    card = '<div class="card"><h2>最新離線進展：新增元件完成原廠資源與字型準備</h2>'
    card += '<p><strong>完整初始化通過：</strong>新增元件在原廠執行緒上完成全部十一個步驟，外部字型、圖形資源、選單資料和資料庫處理都正常返回；十九個區域及整個字型快取的最終檢查通過。原廠指令由模擬器執行，字型資料來自已核對的實機備份。</p>'
    card += '<p><strong>目前還沒有能安裝到車機的整合 App。</strong>真正的選單前景、觸控、跨執行緒浮點狀態、程式包接受與安全回呼尚待驗證；手機直接藍牙音樂未實現。下一步從新的冷啟動輸入接入原廠派送流程。</p>'
    card += '<p>三份原廠程式包的簽章已辨識為 OpenPGP v4，宣告 DSA／SHA1，摘要前 16 位與各自原程式吻合。這項格式檢查尚未完成公鑰驗證，也未證明車機接受修改程式。格式依據：<a href="https://www.rfc-editor.org/rfc/rfc4880.html">RFC 4880</a>。</p>'
    card += '<p>整體里程碑估計 33%，App 整合約 20%；百分比是研究里程碑估計，不是安裝成功率。三路平行研究已完成本輪查核，目前沒有新的實機操作需求。現場配對立即優先；麥克風取消、音質精修擱置，Android Auto 排後，Google Maps 暫緩。</p></div>'
    report = (ROOT/'reports/nuvi2565RT.html').read_text()
    report, n = re.subn(r'<div class="card"><h2>最新離線進展：新增元件已進入原廠資源與字型流程</h2>.*?</div>', lambda _:card, report, count=1, flags=re.S); assert n == 1
    report, n = re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)', lambda m:m[1]+m[2]+''.join('<li>'+html.escape(x)+'</li>' for x in details)+m[3], report, count=1, flags=re.S); assert n == 1
    report, n = re.subn(r'<p><strong>下一步：</strong>.*?</p>', lambda _:'<p><strong>下一步：</strong>'+html.escape(progress['next'])+' 現場配對立即優先，目前沒有新的實機操作需求。</p>', report, count=1); assert n == 1
    report, n = re.subn(r'<tr><td>原生 App 入口與功能整合</td><td>10%</td><td>.*?</td></tr>', lambda _:'<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>'+html.escape(progress['next'])+'</td></tr>', report, count=1); assert n == 1
    report, n = re.subn(r'(<div class="progress-total">約 <strong>)32%(</strong>)', r'\g<1>33%\g<2>', report, count=1); assert n == 1
    report, n = re.subn(r'(<progress id="research-progress" max="100" value=")32("[^>]*>)32%(</progress>)', r'\g<1>33\g<2>33%\g<3>', report, count=1); assert n == 1
    local = now.astimezone(ZoneInfo('Asia/Taipei')); iso = local.isoformat(timespec='seconds')
    for name in ['report-updated-time', 'research-updated-time']:
        report, n = re.subn(r'<time id="'+name+r'" datetime="[^"]+">[^<]+</time>', '<time id="'+name+'" datetime="'+iso+'">'+local.strftime('%Y/%m/%d %H:%M:%S')+'</time>', report, count=1); assert n == 1
    assert len(app['static_findings']) == 128 and len(progress['completed']) == 100
    for path, data in [('evidence/deep-research-state.json', state), ('evidence/task-state.json', task), ('reports/findings.json', public)]: write(path, data)
    (ROOT/'reports/nuvi2565RT.html').write_text(report)
    print(json.dumps(dict(findings=128, estimate_percent=33, App_estimate_percent=20, completed_items=100, updated_Taiwan=iso, native_component_session=14246, full_guards_passed=True)))

if __name__ == '__main__': main()
