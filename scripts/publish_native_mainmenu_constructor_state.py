#!/usr/bin/env python3
"""Publish complete offline metadata and general-menu ctor evidence separately."""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import hashlib, html, json, re
from analyze_native_sections import ROOT

def read(p): return json.loads((ROOT/p).read_text())
def sha(p): return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def write(p, d): (ROOT/p).write_text(json.dumps(d, ensure_ascii=False, indent=2)+'\n')

def main():
    prefix='staging/native-player-mainmenu-metadata/'
    previous=read(prefix+'previous-checkpoint.json')
    before, prior=read(previous['state']), read(previous['audit'])
    assert prior['all_passed'] and len(prior['scope_checks'])==12
    assert prior['state_sha256']==sha(previous['state'])==previous['state_sha256']
    assert sha(previous['audit'])==previous['audit_sha256']
    state,task=read('evidence/deep-research-state.json'),read('evidence/task-state.json')
    app=state['native_app_music']
    assert state['user_resting'] and not state['attended_testing']['user_present']
    assert app['static_findings']==before['native_app_music']['static_findings'] and len(app['static_findings'])==89
    paths=['evidence/firmware-analysis/native-mainmenu-metadata-emulation.json',
           'evidence/firmware-analysis/native-mainmenu-constructor-emulation.json']
    proofs=[read(p) for p in paths]
    for proof,count,deps in zip(proofs,[5,3],[94,101]):
        assert proof['all_passed'] and proof['case_count']==count and len(proof['source_sha256'])==deps
        for p,s in proof['source_sha256'].items(): assert sha(p)==s,p
    staticpath=prefix+'consumer-metadata-static-preflight.json'
    assert read(staticpath)['complete_bounded_CFG_count']==7
    indexes=[prefix+'preserved-development-evidence-index.json',
             'staging/native-player-mainmenu-full/preserved-development-evidence-index.json']
    for p in indexes:
        for path,s in read(p)['source_artifact_sha256'].items(): assert sha(path)==s,path
    app['static_findings']['native_mainmenu_metadata']=dict(
        evidence=paths[0],evidence_sha256=sha(paths[0]),case_count=5,all_passed=True,source_artifact_count=94,
        static_evidence=staticpath,static_evidence_sha256=sha(staticpath),complete_static_CFG_count=7,
        original_consumer_reader='0x35d430',original_presence_getter='0x2363b0',
        original_generic_reader='0x26a300',original_profile_lookup='0x26a240',
        native_missing_profile_status=11,host_returned_generic_read_success=False,
        fictional_driver_inventory_and_storage_geometry=True,
        actual_factory_schema_driver_boot_and_default_object_ctor_verified=False,
        preserved_development_evidence=indexes[0],preserved_development_evidence_sha256=sha(indexes[0]),
        device_io=False,sounds_emitted=False,limits=proofs[0]['limits'])
    app['static_findings']['native_mainmenu_constructor']=dict(
        evidence=paths[1],evidence_sha256=sha(paths[1]),case_count=3,all_passed=True,source_artifact_count=101,
        previous_checkpoint=previous,original_entry='0x40434c',original_vtable='0xc03f98',
        compiled_player_loaded_by_original_loader=True,host_seeded_player_catalog=False,
        embedded_Grid_rows=15,loaded_player_caption='Pi 播放器',
        original_default_calculation_and_121E_setter_and_reader_executed=True,
        full_scoped_general_MainMenu_constructor_final_guards_passed=True,
        native_frame=[0,0,0,0],native_visibility_flags=[0,0],
        general_MainMenu_controller_root_foreground_and_recreation_verified=False,
        accepted_modified_VPM_or_device_App_direct_audio_and_safe_lifetime_verified=False,
        SQL_history_retained_but_all_statements_closed=True,
        preserved_development_evidence=indexes[1],preserved_development_evidence_sha256=sha(indexes[1]),
        device_io=False,sounds_emitted=False,limits=proofs[1]['limits'])
    app['development_observations']['general_MainMenu_loaded_player_constructor']=dict(
        original_ctor_returned=True,complete_scoped_final_guards_passed=True,
        compiled_loader_catalog_contains_player_in_embedded_Grid=True,
        native_121E_default_bytes=proofs[1]['original_main_default_writes'][0]['bytes_from_original_default_calculation'],
        default_native_caller='0x405314',native_frame=[0,0,0,0],visibility_flags=[0,0],
        controller_root_UI_thread_touch_display_and_recreation_unverified=True,
        explicit_native_settings19B_value1_and_in_memory_DB_cell12_selection_controls=True,
        safe_lifetime_and_accepted_loading_and_physical_App_not_proven=True)
    actions=[
        'Execute original405340 general-menu controller without treating it as an object method. Recover original root lookup, new40434C allocation/constructor and38E696 manager registration, then verify native frame/visibility, exact GUI writes, DB/SQL, font/GIR, whole voice/code/canary and callback guards. Existing121E may reach121F on recreation; do not infer lifetime cleanup.',
        'Recover true boot/GIR/settings/kernel/UI-thread and foreground path for a visible player with normal touch/canvas/display submission. General ctor now returns but frame0,0,0,0 and flags0,0 remain hidden; prior custom root remains offscreen. Neither is a visible device App.',
        'Execute original388746 callback dispatch and388676 core release; recover sourceID9 stop/repeat/cleanup and safe detach/unregister/reload/unload plus font/cache/stream reclamation. Callback0 with flags6 is not safe unregister.',
        'Verify actual accepted modified VPM/SIG loading, native continuous audio and direct phone Bluetooth with navigation coexistence/recovery. Packages remain EMULATION-ONLY. Microphone canceled, fidelity tuning deprioritized; Android Auto later, Maps deferred.',
        'User still sleeping: offline only, no USB/Bluetooth/device I/O, real device or backup writes, calls/sound or physical questions. On explicit return prepare live audio/agent and immediately prioritize pairing. Goal active/no-achieve.']
    now=datetime.now(timezone.utc)
    state.update(updated_utc=now.isoformat(),next_actions=actions);app['remaining_work']=actions[:4]
    state['last_goal_turn']=dict(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),
        previous_state_snapshot=previous['state'],previous_current_audit_snapshot=previous['audit'],
        previous_turn_revalidation='Fresh12-scope settings checkpoint preserved;89 prior findings and31 selected frozen suites retained.',
        reasons=[
            'Seven bounded CFGs and five complete controls execute original consumer read/profile lookup/missing11/fallback plus bounded fictional lower driver inventory; full guards pass.',
            'Original loader registers compiled Pi player; original40434C returns with15-row embedded Grid and native caption, original2C7DE0/2CA82C compute and store121E read back unchanged.',
            'Three complete general constructor controls pass exact seven native GUI writes, whole original voice40/code, loaded private12/player2, canary/font/GIR/DB and closed SQL checks.',
            'Constructor page remains zero-size and hidden. Controller/root/foreground/recreation/safe lifetime/real boot/kernel/accepted loading/device App/direct audio unverified.',
            'Failed prototypes, incomplete general run and incorrect SQL-history guard preserved separately; no device I/O/write/install/call/sound or goal completion while user rests.'],
        focused_evidence=paths[0],focused_evidence_sha256=sha(paths[0]),
        general_menu_constructor_evidence=paths[1],general_menu_constructor_evidence_sha256=sha(paths[1]),
        full_general_MainMenu_constructor_final_guards_passed=True,
        general_MainMenu_controller_or_visible_App_verified=False,device_io=False,device_files_written=False,
        native_firmware_or_research_package_written=False,automatic_calls_or_sound=False,attended_calls_or_sound=False,
        automatic_calls_or_sound_while_away=False,next_focus=actions[0],goal_status='active',full_goal_complete=False)
    for k in ['updated_utc','last_goal_turn','next_actions','current_priority','latest_user_instruction','attended_testing','ordered_priorities','user_resting']: task[k]=state[k]
    task.update(user_away=True,current_connection_not_rechecked_this_offline_turn=True,current_device_connection_verified=False)
    public=read('reports/findings.json');public.update(deep_research=state,updated=now.isoformat());progress=public['research_progress']
    assert progress['estimate_percent']==31 and len(progress['completed'])==59
    details=[
        '首頁儲存資料：七個原始函式流程與五組離線控制通過，執行原廠資料讀取、資料來源查詢、缺資料及長度處理分支；底層內容仍為明示的模擬輸入，沒有讀取實機原廠資料或更改車機。',
        '播放器首頁整合：由原廠載入器載入編譯的 Pi 播放器，原廠首頁初始化成功返回，十五格菜單內含播放器名稱及按鈕；預設設定由原始程式計算並寫入讀回，三組完整檢查通過。頁面仍隱藏、零尺寸，控制器與實機 App 尚待完成。']
    for detail in details: assert detail not in progress['completed'];progress['completed'].append(detail)
    phase=progress['phases'][4];assert phase['estimate_percent']==0 and not phase['completed']
    phase.update(estimate_percent=10,next='原廠首頁初始化及播放器菜單資料已通過離線整合；接控制器、前景顯示、正常操作、安全清理與原機載入。')
    phase['completed'].append('編譯的播放器經原廠載入器接入首頁菜單初始化，完整離線檢查通過；尚未前景顯示或實機載入。')
    weighted=sum(p['weight']*p['estimate_percent']/100 for p in progress['phases'])
    assert weighted==32.0 and len(progress['completed'])==61
    progress.update(estimate_percent=32,weighted_estimate_percent=weighted,research_updated_utc=now.isoformat(),
        next='執行原廠首頁控制器，確認前景頁面與播放器操作；接著補安全清理、實機 App 載入及手機直接藍牙音樂。')
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    card='''<div class="card"><h2>最新離線進展：播放器已接入原廠首頁初始化</h2>
<p><strong>編譯的 Pi 播放器已接入原廠首頁的離線初始化，三組完整檢查通過。</strong>原廠載入器載入播放器後，原廠首頁初始化成功返回；十五格菜單資料中包含「Pi 播放器」名稱與按鈕。首頁預設設定也由原始程式計算、寫入並讀回，未用測試程式代填預設值。</p>
<p>原廠語音完整記憶體與 40 個介面、原廠與載入程式區、配置邊界、字型、圖形資源及備份資料庫檢查通過。SQL 查詢保留歷史，但各筆已由原廠流程關閉；首頁初始化的七筆資料寫入逐筆核對，未以修改原始指令避開檢查。</p>
<p>另外，首頁的儲存資料讀取通過五組控制與七個原始函式流程核對。原廠查詢、缺資料與長度處理均實際執行；底層儲存內容、記憶體配置、同步及硬體狀態仍有明示的模擬輸入，不能當作真實開機或實機圖形環境。</p>
<p><strong>頁面目前仍是隱藏、零尺寸；實機 App 尚未完成。</strong>下一步執行原廠控制器，接上前景頁面、正常觸控與畫面提交。App 實機載入、停止／清理／卸載、手機直接藍牙音樂仍待驗證。研究套件僅供模擬，未安裝到車機。</p>
<p>整體進度約 32%，是各研究里程碑加權估計，並非 App 完成度。麥克風已取消、聲道／音質精修擱置，Android Auto 排後、Google Maps 暫緩；使用者休息期間沒有車機操作、來電或播放聲音。</p></div>'''
    report,n=re.subn(r'<div class="card"><h2>最新離線進展：原廠設定儲存流程已驗證</h2>.*?</div>',lambda m:card,report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'(<div class="progress-total">約 <strong>)31%(</strong>)',r'\g<1>32%\2',report,count=1);assert n==1
    report,n=re.subn(r'(<progress id="research-progress" max="100" value=")31("[^>]*>)31%(</progress>)',lambda m:m[1]+'32'+m[2]+'32%'+m[3],report,count=1);assert n==1
    report,n=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda m:m[1]+m[2]+''.join('<li>'+html.escape(d)+'</li>'for d in details)+m[3],report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda m:'<p><strong>下一步：</strong>'+html.escape(progress['next'])+' 現場配對要求立即優先；休息期間只做離線研究。</p>',report,count=1);assert n==1
    report,n=re.subn(r'<tr><td>原生 App 入口與功能整合</td><td>0%</td><td>.*?</td></tr>',lambda m:'<tr><td>原生 App 入口與功能整合</td><td>10%</td><td>'+html.escape(phase['next'])+'</td></tr>',report,count=1);assert n==1
    local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds');display=local.strftime('%Y/%m/%d %H:%M:%S')
    for ident in ['report-updated-time','research-updated-time']:
        report,n=re.subn(r'<time id="'+ident+r'" datetime="[^"]+">[^<]+</time>','<time id="'+ident+'" datetime="'+iso+'">'+display+'</time>',report,count=1);assert n==1
    write('evidence/deep-research-state.json',state);write('evidence/task-state.json',task);write('reports/findings.json',public)
    (ROOT/'reports/nuvi2565RT.html').write_text(report)
    print(json.dumps(dict(findings=len(app['static_findings']),metadata_groups=5,constructor_groups=3,estimate_percent=32,completed_items=61,updated_Taiwan=iso)))

if __name__=='__main__': main()
