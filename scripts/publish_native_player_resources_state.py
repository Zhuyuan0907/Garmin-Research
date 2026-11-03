#!/usr/bin/env python3
"""Publish checked resource ABI and native icon/caption canvas evidence."""
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
from pathlib import Path
import base64,html,json,re
from check_native_music_stream_checkpoint import ROOT,read,sha,artifacts

def write(path,value):(ROOT/path).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')

def main():
    previous=read('staging/native-player-resources/previous-checkpoint.json')
    before,audit=read(previous['state']),read(previous['audit'])
    assert audit['all_passed'] and audit['state_sha256']==sha(previous['state'])
    state,task=read('evidence/deep-research-state.json'),read('evidence/task-state.json')
    assert state['user_resting']and not state['attended_testing']['user_present']
    for name,value in before['native_app_music']['static_findings'].items():assert state['native_app_music']['static_findings'][name]==value,name
    path='evidence/firmware-analysis/native-player-resources-emulation.json';proof=read(path)
    abi_path='evidence/firmware-analysis/native-resource-reference-ABI-emulation.json';abi=read(abi_path)
    assert proof['all_passed']and proof['case_count']==6 and abi['all_passed']and abi['case_count']==4
    for p in [proof,abi]:
        for source,expected in p['source_sha256'].items():assert sha(source)==expected,source
    artifacts(read(proof['build_manifest']))
    static=read('staging/native-player-resources/resource-ABI-and-MainMenu-preflight.json')
    root=read('staging/native-player-resources/resource-cache-and-MainMenu-caller-preflight.json')
    correction_path='staging/native-player-resources/canvas-artifact-label-correction.json'
    correction=read(correction_path)
    assert correction['original_proof_sha256']==sha(path)
    assert sha(correction['correct_raw_canvas_artifact'])==proof['cases'][1]['paint']['canvas_sha256']
    player=proof['cases'][2]['paint'];whole=proof['cases'][1]['paint']
    preview='staging/native-player-resources/loaded-player-RGB565-preview.png';assert(ROOT/preview).is_file()
    app=state['native_app_music']
    item={k:proof[k]for k in ['MAIN_sha256','build_manifest','build_manifest_sha256','case_count','all_passed',
        'native_software_canvas_pixels_verified','native_nonempty_icon_rendering_verified','host_wrote_pixel_buffer',
        'actual_display_framebuffer_submission_verified','actual_UI_thread_root_touch_verified','device_io','sounds_emitted',
        'device_install_candidate','actual_package_acceptance_verified','native_App_running_on_device','phone_direct_music_verified','limits']}
    item.update(evidence=path,evidence_sha256=sha(path),source_artifact_count=len(proof['source_sha256']),
        reference_ABI_evidence=abi_path,reference_ABI_evidence_sha256=sha(abi_path),reference_ABI_case_count=4,
        previous_checkpoint=previous,ResourceRef_fields=static['ResourceRef_fields'],borrowed_stock_icon_hash='0x8a56eac',
        stock_icon_preview_identity='Gray X/stop-shaped stock icon; borrowed test resource, not a custom music icon',
        stock_resource_directory_bytes=static['appended_GIR']['directory_bytes'],
        stock_resource_source_bytes=static['appended_GIR']['source_bytes'],
        stock_image_entries_declared=static['appended_GIR']['image_entry_count_declared'],
        stock_image_entries_bucket_reachable=static['appended_GIR']['image_entry_count_bucket_reachable'],
        complete_static_CFG_count=static['complete_bounded_CFG_count']+root['complete_bounded_CFG_count'],
        corrected_PageMainMenu_constructor='0x40434c',embedded_Grid_call_site_not_entry='0x404c36',
        original_MainMenu_Page_allocation_bytes=root['original_Page_allocation_bytes'],
        actual_MainMenu_constructor_or_controller_executed=False,
        corrected_player_canvas_changed_pixels=player['changed_pixel_count'],
        entire_Grid_canvas_changed_pixels=whole['changed_pixel_count'],native_player_preview=preview,
        actual_boot_GIR_map_or_inventory_verified=False,custom_music_icon_created=False,
        raw_canvas_artifact=correction['correct_raw_canvas_artifact'],
        raw_canvas_artifact_label_correction=correction_path,raw_canvas_artifact_label_correction_sha256=sha(correction_path))
    app['static_findings']['native_player_resources']=item;app['current_player_variant']=proof['build_manifest']
    app['native_nonempty_icon_software_canvas_rendering_offline']=True
    app['development_observations']['corrected_resource_player']=dict(
        ResourceRef_word0_is_numeric_hash_not_string_pointer=True,
        previous_blank_icon_description_corrected_historical_proofs_preserved=True,
        whole_stock_resource_bytes_mapped_readonly_explicit_fixture_not_boot_map=True,
        original_GIR_registration_and_resolve_no_host_catalog_seed=True,
        original_compressed_resource_stream_buffers_guarded_fixture=True,
        native_icon_label_layout_changed_from_previous_text_only_variant=True,
        actual_device_App_loading_UI_root_display_direct_music_and_safe_release_open=True)
    actions=[
        'Execute original PageMainMenu40434C/controller405340/root registration38E696 with recovered boot/resource/settings context. Corrected resource player now paints a borrowed stock icon and CJK label; actual framebuffer submission/display/UI thread/touch still open.',
        'Recover real boot GIR mapping, settings19B and catalog registration/selection timing; native resource streams/decompression/cache ownership and complete UI root need verification.',
        'Establish accepted modified VPM loading and sourceID9 repeat/stop/cleanup, safe detach/unregister/reload/unload including fonts/cache/streams. Current54976-byte resource player remains EMULATION-ONLY; do not install.',
        'Connect native player controls to direct phone Bluetooth and continuous native/kernel audio with recovery/navigation coexistence. Fidelity/stereo deprioritized; microphone canceled; Android Auto later, Maps deferred.',
        'User asleep: offline only, no USB/Bluetooth/device writes, calls/sounds or physical questions. Explicit return: prepare live audio/agent and pairing first. Goal active/no-achieve.']
    now=datetime.now(timezone.utc);state.update(updated_utc=now.isoformat(),next_actions=actions);app['remaining_work']=actions[:4]
    state['last_goal_turn']=dict(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),
        previous_state_snapshot=previous['state'],previous_current_audit_snapshot=previous['audit'],
        previous_turn_revalidation='Fresh16-scope rendering audit saved; all83 prior findings and25 frozen suites preserved.',
        reasons=['Corrected8-byte resource ABI through original hash/name/deep-copy/destructor/resolver controls4 groups.',
            'Unchanged29MB appended stock GIR registered by original code; explicit read-only guest placement is not a boot mapping claim.',
            'Six full loader/native icon-label layout/paint/clip/events groups and final voice/code/regions/canary/DB guards passed.',
            'General PageMainMenu true constructor40434C, allocation3F04 and controller/root call identified statically, not executed.',
            'Native App/direct-phone music/accepted package/physical UI and safe lifecycle remain open; user asleep, no device I/O or sound.'],
        build_manifest=proof['build_manifest'],build_manifest_sha256=proof['build_manifest_sha256'],
        integration_evidence=path,integration_evidence_sha256=sha(path),offline_integration_device_io=False,
        device_io=False,device_files_written=False,native_firmware_or_research_package_written=False,
        automatic_calls_or_sound=False,attended_calls_or_sound=False,automatic_calls_or_sound_while_away=False,
        next_focus=actions[0],goal_status='active',full_goal_complete=False)
    for key in ['updated_utc','last_goal_turn','next_actions','current_priority','latest_user_instruction','attended_testing','ordered_priorities','user_resting']:task[key]=state[key]
    task.update(native_nonempty_icon_software_canvas_rendering_offline=True,user_away=True,current_player_variant=proof['build_manifest'],
        current_connection_not_rechecked_this_offline_turn=True,current_device_connection_verified=False)
    public=read('reports/findings.json');public.update(deep_research=state,updated=now.isoformat());progress=public['research_progress']
    progress['research_updated_utc']=now.isoformat()
    details=[
        '修正原廠圖示資源 ABI：原欄位為識別碼與自有名稱指標；四組原廠程式驗證涵蓋雜湊、複製、釋放、兩個圖像版本及空／不存在資源對照，保留前輪證據。',
        '有圖示播放器離線原型：原廠載入器讀入修正元件，借用原廠 64×64 圖示，再由原廠解壓、佈局與繪圖顯示圖示及 Pi 播放器文字；六組完整驗證與最後邊界檢查通過，尚未安裝原機。',
        '一般主選單入口定位：找出真正 PageMainMenu 建構函式、原配置大小及控制器掛接呼叫；先前位址為內部格位建構呼叫，已補正。尚未執行一般主選單控制器。']
    for detail in details:assert detail not in progress['completed'];progress['completed'].append(detail)
    progress['next']='圖示與繁中文字已由原廠程式畫入模擬畫布；接著接一般主選單控制器、實際畫面提交與可接受的原機載入，再整合直接藍牙音樂。'
    progress['phases'][4]['next']='非空圖示與繁中文標籤已離線繪出；接一般菜單控制器／螢幕提交、實機元件接受及資源釋放。'
    report=(ROOT/'reports/nuvi2565RT.html').read_text();old='<div class="card"><h2>最新離線進展：播放器文字已畫入模擬畫布</h2>';assert report.count(old)==1
    png=base64.b64encode((ROOT/preview).read_bytes()).decode()
    card=f'''<div class="card"><h2>最新離線進展：播放器圖示與文字已畫入模擬畫布</h2>
<p><strong>六組完整流程與四組資源欄位驗證通過。</strong>修正原型的圖示識別碼後，原廠載入器讀入元件，原廠菜單建立按鈕，再用原廠資源解析、解壓縮、佈局及畫布程式畫出圖示與「Pi 播放器」。這次借用原廠 64×64 灰色叉號圖示作驗證，還沒有製作正式音樂圖示。</p>
<figure><img style="max-width:100%;width:480px;height:auto" src="data:image/png;base64,{png}" alt="原廠程式繪出的圖示與 Pi 播放器標籤，模擬畫布局部放大"><figcaption>模擬畫布的播放器區域放大；不是車機截圖。像素由原廠指令繪出，未由主機補畫。</figcaption></figure>
<p>播放器範圍有 <strong>{player['changed_pixel_count']} 個像素</strong>變化。原廠裁切保留完整畫布中的相同子集與色階；恢復裁切後重畫一致，按鈕事件仍送出播放請求。原語音、40 個介面、程式區、配置邊界與資料庫最後檢查通過，備份未改動。</p>
<p>這輪也修正圖示欄位的解讀：它存資源識別碼或自有名稱；之前的原型把識別碼欄位誤當字串指標，所以未找到圖示。已找到一般主選單真正入口及控制器掛接流程，目前只有靜態定位。</p>
<p><strong>尚未在原機安裝播放器 App。</strong>原廠圖像資源在模擬記憶體中的位置、白色背景、外框及事件是明示測試輸入；實際啟動資源位置、一般主選單控制、真螢幕提交、UI 執行緒、觸控、修改封裝的實機接受、停止／重播與安全清理仍待研究。手機直接連原機播放音樂也尚未完成。</p>
<p>進度維持約 {progress['estimate_percent']}% 的里程碑估計。優先接一般菜單与實機元件載入，再做直接藍牙音樂；麥克風已取消，Android Auto 排後，Google Maps 暫緩。使用者休息期間沒有操作車機或播放聲音。</p></div>'''.replace('菜單与','菜單與')
    report=report.replace(old,card+'<div class="card"><h2>前輪紀錄：播放器文字已畫入模擬畫布</h2>')
    report,n=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda m:m[1]+m[2]+''.join('<li>'+html.escape(d)+'</li>'for d in details)+m[3],report,count=1,flags=re.S);assert n==1
    local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds');display=local.strftime('%Y/%m/%d %H:%M:%S')
    for ident in ['report-updated-time','research-updated-time']:
        report,n=re.subn(r'<time id="'+ident+r'" datetime="[^"]+">[^<]+</time>','<time id="'+ident+'" datetime="'+iso+'">'+display+'</time>',report,count=1);assert n==1
    write('evidence/deep-research-state.json',state);write('evidence/task-state.json',task);write('reports/findings.json',public);(ROOT/'reports/nuvi2565RT.html').write_text(report)
    print(json.dumps(dict(finding='native_player_resources',complete_groups=6,ABI_groups=4,completed_items=len(progress['completed']),estimate_percent=progress['estimate_percent'],updated_Taiwan=iso,device_io=False)))

if __name__=='__main__':main()
