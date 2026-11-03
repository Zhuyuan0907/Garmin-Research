#!/usr/bin/env python3
"""Publish original fonts/native geometry/state updater proof with physical boundaries."""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import html
import json
import re
from check_native_music_stream_checkpoint import ROOT, read, sha, artifacts


def write(path,value):
    (ROOT/path).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')


def main():
    previous=read('staging/native-player-text/previous-checkpoint.json')
    before,prior=read(previous['state']),read(previous['audit'])
    assert prior['all_passed'] and prior['state_sha256']==sha(previous['state'])
    state,task=read('evidence/deep-research-state.json'),read('evidence/task-state.json')
    for name,value in before['native_app_music']['static_findings'].items():
        assert state['native_app_music']['static_findings'][name]==value,name
    evidence='evidence/firmware-analysis/native-player-text-emulation.json'
    proof=read(evidence)
    assert proof['all_passed'] and proof['case_count']==4 and not proof['device_io']
    for path,expected in proof['source_sha256'].items():assert sha(path)==expected,path
    assert sha(proof['build_manifest'])==proof['build_manifest_sha256']
    artifacts(read(proof['build_manifest']))
    candidate_path='staging/native-player-external-fonts/candidate-inventory.json'
    candidate=read(candidate_path)
    for path,expected in candidate['source_sha256'].items():assert sha(path)==expected,path
    assert candidate['candidate_count']==8 and not candidate['native_external_font_loading_verified']
    assert state['user_resting'] and not state['attended_testing']['user_present']
    app=state['native_app_music']
    item={k:v for k,v in proof.items()if k not in ['source_sha256','cases','load','snapshot']}
    item.update(evidence=evidence,evidence_sha256=sha(evidence),
        source_artifact_count=len(proof['source_sha256']),case_names=[r['name']for r in proof['cases']],
        original_embedded_font_initialization_and_native_glyph_lookup_offline=True,
        original_Widget_geometry_from_outer_frames_offline=True,
        original_normal_Grid_state_refresh_through_compiled_updater_offline=True,
        host_Widget_frame_writes_or_enable0_calls=False,
        actual_CJK_fonts_render_touch_and_accepted_install_verified=False,previous_checkpoint=previous,
        prepared_external_font_candidate_inventory=candidate_path,
        prepared_external_font_candidate_inventory_sha256=sha(candidate_path))
    app['static_findings']['native_player_text']=item
    app['stock_native_Grid_geometry_and_state_refresh_offline']=True
    app['development_observations']['font_geometry_state']={
        'stock_static4DF248_runtime4DE236_initialize13_records':True,
        'test_parameter0_skips_external_fonts_three_embedded_sfnt_loaded':True,
        'native_glyph_query_matches_sfnt_cmap_Pi_present_CJK_caption_absent':True,
        'real_boot_inventory_and_external_font_loading_not_recovered':True,
        'no_metrics_glyph_context_success_fixture':True,
        'original_geometry377AB8_547020_computes_two_Widget_frames':True,
        'Widget_frames_not_written_directly_by_test':True,
        'registered_compiled_state_updater_invoked_by_factory315BA8_and_refresh54A364':True,
        'original_default56_20_4_byte_outputs_unchanged':True,
        'stock_refresh_enables0_for_owned_context_and_disables4_for_negative_context':True,
        'host_never_calls_updater_signal_or_enable0_for_activation':True,
        'native_computed_cell_center_events_reach_loaded_player_twice':True,
        'native_Containing_Page_geometry_exhausts_virtual_raw_then_SQL_inventory_not_completed':True,
        'containing_Page_outer_frame_explicit_input_fixture_actual_controller_open':True,
        'explicit_parent_API_r2_insertion_mode0_r3_anchor0_adds_fifth_child':True,
        'two_argument_parent_call_failure_preserved_uninitialized_remaining_registers':True,
        'paint_probe_returns_but_zero_canvas_byte_changes_and_no_font_calls':True,
        'no_actual_render_display_real_touch_or_accepted_install_claim':True,
        'font_handles_keep_fixture_bookkeeping0_native_pointer_queries_prefixes_guards_verified':True,
        'original388804_pointer_query_and388B22_BXLR_not_native_pin_counts':True,
        'nonfont_outer_guards_and_released_font_temporary_checks_retained':True,
        'hidden_backup_contains8_inferred_XOR76_sfnt_candidates_including_CJK_DFHeiW5_A':True,
        'candidate_native_decoder_or_external_loading_not_executed':True}
    actions=[
        'Connect eight external sfnt candidates found in hidden backup .System/ExtData (inferred XOR76; DFHeiW5-A contains caption glyphs) to the exact native resource reader/decoder and font loader. Native transform/boot loading remain unproved; current embedded-only fonts lack Chinese. Recover nonempty icons and clipping/canvas paint, actual rendering/display and MainMenu controller/root. Full containing Page geometry exhausted virtual raw/SQL inventories and remains unproved; its outer frame is still an input fixture.',
        'Recover actual settings19B/readyF06EF7 boot and UI-thread registration/selection timing; current containing Page still resets15 and test reselects after ctor. State updater now drives native enable/disable without host enable0, but physical input/default click wait/posted queue/kernel event delivery remain open.',
        'Establish accepted modified VPM loading and sourceID9 ownership, repeated play/stop/cleanup, safe unregister/reload/unload including pinned font handles/contexts. Current54982-byte EMULATION-ONLY package must not be installed.',
        'Integrate player controls with direct Bluetooth endpoint and continuous/kernel pipeline, failure recovery and navigation/speaker coexistence. Stereo/fidelity tuning deprioritized.',
        'User sleeping: offline only, no calls/sounds/USB/Bluetooth/device writes or physical questions. Explicit return: prepare live audio/agent and handle pairing first. Microphone canceled, Android Auto later, Maps deferred, goal active/no-achieve.']
    now=datetime.now(timezone.utc)
    state['updated_utc']=now.isoformat();state['next_actions']=actions;app['remaining_work']=actions[:4]
    state['last_goal_turn']={'classification':'progress','previous_goal_turn_classification':'progress',
        'validated_utc':now.isoformat(),'previous_state_snapshot':previous['state'],
        'previous_current_audit_snapshot':previous['audit'],
        'previous_turn_revalidation':'Fresh prior16-scope Grid audit saved with exact canonical state;22 earlier selected suites and all80 prior findings frozen.',
        'reasons':[
            'Four complete groups: original embedded-font initialization and native glyph queries; native two-size Grid geometry; recovered compiled updater driving original state refresh and events; visibility/context/outside controls restoring activation.',
            'Original4DF248/4DE236 create13 font records with test parameter0, load embedded3/4/5, native glyph lookup matches actual sfnt cmap. Chinese caption glyphs absent; external fonts/actual boot-resource inventory remain open, no fake metrics or glyphs.',
            'Original377AB8/547020 compute Widget frames from two outer bounds, avoiding previous null font context. New C updater registered through stock catalog is invoked by original factory/refresh, leaves default output objects byte-identical, enables0 or disables4 via native setter; no host updater/signal/enable0 call.',
            'Nested numeric events at original calculated Widget frame reach resident player twice; containing Page outer frame remains a test input, because its native geometry failed at virtual raw then SQL inventories. Real touch, UI loop/wake delivery and sound wait remain unproved. Earlier development paint returns with zero changed pixels/no font calls and is not rendering/display proof.',
            'Original voice RAM40 exports/private12/player2/code/full initialized regions/three exact once-words/canaries retained. Original388804 is a pointer query and388B22 BX LR:19 font allocations stay live with exact fixture bookkeeping0, checked native prefixes/queries/canaries; no native pin-count claim. All inherited non-font and any released-font temporary checks retained. SQL15 rows restored/backup unchanged.',
            'New local54982-byte player build remains EMULATION-ONLY; actual App, package acceptance, direct phone music, sourceID9 lifecycle and full goal incomplete. User sleeping, no device operations or sound.'],
        'build_manifest':proof['build_manifest'],'build_manifest_sha256':proof['build_manifest_sha256'],
        'integration_evidence':evidence,'integration_evidence_sha256':sha(evidence),
        'offline_integration_device_io':False,'device_io':False,'device_files_written':False,
        'native_firmware_or_research_package_written':False,'automatic_calls_or_sound':False,
        'attended_calls_or_sound':False,'automatic_calls_or_sound_while_away':False,
        'next_focus':actions[0],'goal_status':'active','full_goal_complete':False}
    for key in ['updated_utc','last_goal_turn','next_actions','current_priority','latest_user_instruction',
                'attended_testing','ordered_priorities','user_resting']:task[key]=state[key]
    task.update(stock_native_Grid_geometry_and_state_refresh_offline=True,user_away=True,
        current_connection_not_rechecked_this_offline_turn=True,current_device_connection_verified=False)
    public=read('reports/findings.json');public['deep_research']=state;public['updated']=now.isoformat()
    progress=public['research_progress'];progress['research_updated_utc']=now.isoformat()
    completed='原廠字型、格位佈局與狀態回呼：四組離線驗證載入三套內嵌字型、原廠計算按鈕座標及原廠狀態更新啟用播放器；數字事件與失敗控制通過。繁中文字型／實際繪圖／觸控與可接受的安裝仍待完成'
    assert completed not in progress['completed'];progress['completed'].append(completed)
    progress['next']='將備份中已找到的繁中字型候選接入原廠讀取／轉換及載入流程，再補畫布、圖示繪製和一般菜單頁面切換；繼續處理真實設定、安裝接受及播放停止流程。'
    progress['phases'][4]['next']='原廠字型初始化、真正格位座標與狀態回呼已離線走通；補繁中字型、非空圖示／繪圖環境、真觸控與實機載入。'
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    old='<div class="card"><h2>最新離線進展：原廠自動格位建立播放器按鈕</h2>'
    assert report.count(old)==1
    card='''<div class="card"><h2>最新離線進展：原廠字型、格位佈局與播放器狀態</h2>
<p><strong>四組完整離線驗證通過。</strong>已執行台灣 8.00 原廠字型初始化，建立十三個字型槽位並載入三套內嵌字型，解除前輪文字環境未初始化造成的中止。使用原廠設定外框與重新佈局函式，可計算兩種尺寸下播放器按鈕的位置和尺寸；按鈕座標由原廠指令寫入。第二種尺寸由測試明確呼叫原廠重新佈局函式，實際頁面的尺寸變更通知尚未執行。</p>
<p>播放器原型新增了原廠菜單會呼叫的狀態回呼。<strong>原廠狀態更新流程可自行把播放器從停用改為啟用。</strong>提供不符合播放器的測試識別值時，回呼會要求停用；還原後又能啟用。原廠預設樣式／標題輸出物件保持原樣。按照原廠算出的格位中心提供數字事件，能沿頁面、格位及按鈕事件函式呼叫載入的播放器，送出 WAV 登錄和開始播放請求。</p>
<p><strong>畫面與實機 App 仍未完成。</strong>這次明確跳過外部字型載入，三套內嵌字型沒有「播放器」三個中文字。前一次繪圖試驗雖然返回，畫布卻沒有任何 byte 改變，也沒有字型繪製呼叫，不能算畫面已畫出。接著必須找到繁中文字型來源、圖示材料與畫布／裁切環境，再接一般主選單的頁面切換和螢幕提交。</p>
<p>另外，已在備份的隱藏系統目錄找到八套外部字型候選。推定的 byte 轉換可還原完整字型表，其中 DFHeiW5-A 的字元表含有「播放器」與「竺原」。這是檔案分析線索；原廠轉換與外部字型載入尚未執行，也還沒有中文畫面證據。</p>
<p>外層頁面與格位外框、數字輸入、按鍵音選項及核心喚醒仍是明列的測試條件；沒有真觸控或事件迴圈證據。完整外層頁面的原廠佈局試驗先後碰到虛擬配置區與資料庫查詢資源上限，失敗證據已保留；頁面外框仍由測試提供，不能算一般菜單初始化完成。字型配置保持常駐；原廠函式是指標查詢，沒有證明原生記憶體鎖定，安全清理／卸載待完成。原語音記憶體與 40 個介面、程式區、完整初始化資料區及配置邊界核對通過，十五格資料庫記憶體副本已還原，備份未變。新版封裝只供離線研究；<strong>原機 App 和手機直接藍牙音樂尚未完成。</strong>使用者休息期間沒有操作車機或播放聲音。</p></div>'''
    report=report.replace(old,card+'<div class="card"><h2>前輪紀錄：原廠自動格位建立播放器按鈕</h2>')
    pattern=r'(<ul class="completed-progress">)(.*?)(</ul>)'
    report,count=re.subn(pattern,lambda m:m[1]+m[2]+'<li>'+html.escape(completed)+'</li>'+m[3],report,count=1,flags=re.S)
    assert count==1
    local=now.astimezone(ZoneInfo('Asia/Taipei'))
    iso=local.isoformat(timespec='seconds');display=local.strftime('%Y/%m/%d %H:%M:%S')
    for ident in ['report-updated-time','research-updated-time']:
        report,count=re.subn(r'<time id="'+ident+r'" datetime="[^"]+">[^<]+</time>',
            '<time id="'+ident+'" datetime="'+iso+'">'+display+'</time>',report,count=1)
        assert count==1
    write('evidence/deep-research-state.json',state);write('evidence/task-state.json',task)
    write('reports/findings.json',public);(ROOT/'reports/nuvi2565RT.html').write_text(report)
    print(json.dumps({'finding':'native_player_text','groups':4,'dependencies':item['source_artifact_count'],
        'estimated_progress':progress['estimate_percent'],'completed_items':len(progress['completed']),
        'updated_Taiwan':iso,'device_io':False}))


if __name__=='__main__':main()
