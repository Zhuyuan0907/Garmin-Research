#!/usr/bin/env python3
"""Publish original Page/input research with offline/physical boundaries."""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import html
import json
import re
from check_native_music_stream_checkpoint import ROOT, read, sha, artifacts


def write(path,value):
    (ROOT/path).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')


def main():
    previous=read('staging/native-player-page/previous-checkpoint.json')
    before,prior=read(previous['state']),read(previous['audit'])
    assert prior['all_passed'] and prior['state_sha256']==sha(previous['state'])
    state,task=read('evidence/deep-research-state.json'),read('evidence/task-state.json')
    for name,value in before['native_app_music']['static_findings'].items():
        assert state['native_app_music']['static_findings'][name]==value,name
    evidence='evidence/firmware-analysis/native-player-page-emulation.json'
    proof=read(evidence)
    assert proof['all_passed'] and proof['case_count']==3 and not proof['device_io']
    for path,expected in proof['source_sha256'].items():assert sha(path)==expected,path
    assert sha(proof['build_manifest'])==proof['build_manifest_sha256']
    artifacts(read(proof['build_manifest']))
    assert state['user_resting'] and not state['attended_testing']['user_present']
    app=state['native_app_music']
    item={k:v for k,v in proof.items()if k not in ['source_sha256','cases','load','snapshot']}
    item.update(evidence=evidence,evidence_sha256=sha(evidence),
        source_artifact_count=len(proof['source_sha256']),case_names=[r['name']for r in proof['cases']],
        original_Page_constructor_complete_offline=True,original_parent_visibility_and_event_chain_offline=True,
        host_supplied_geometry_and_numeric_events=True,automatic_grid_population_verified=False,
        native_layout_and_real_touch_verified=False,previous_checkpoint=previous)
    app['static_findings']['native_player_page']=item
    app['stock_Page_parent_and_numeric_input_offline']=True
    app['development_observations']['Page_input']={
        'stock_Page_ctor_5A2994_bytes_7C4_vtable_C0E5F0_children4':True,
        'observed_original_SQL_setter_clears_test_slot15_under_sparse_fixture':True,
        'exact_cause_or_real_boot_behavior_not_inferred':True,
        'test_reapplies_selection_after_Page_then_attaches_Widget_using_original_API':True,
        'Page_visibility_propagation_required_before_original_parent_dispatch':True,
        'numeric_actions0_1_only_change_state_action2_reaches_loaded_player':True,
        'prior_flag112_capture_interpretation_unverified_and_not_used':True,
        'flag112_remains0_no_flag_or_callback_fabrication':True,
        'nondefault_sound_selector36_requested_via_original_setter':True,
        'kernel_wake2FCF44_ack0_boundary_not_actual_notification_delivery':True,
        'initial_lookup_and_missing_kernel_wake_failures_preserved':True,
        'actual_input_classification_automatic_grid_layout_render_and_accepted_install_open':True}
    actions=[
        'Complete original automatic grid builder546878, Page controller switch/root installation, real geometry/layout and nonempty graphics/font rendering. Current Page ctor/native child attachment/visibility/numeric event dispatch works offline with explicit geometry/events and sound selector36; no physical icon/App claim.',
        'Recover why original Page construction clears selected slot15 under sparse catalog/DB fixture; preserve actual user icon settings and define UI-thread registration/selection timing. Recover original input classification, optional click-sound wait and posted-closure queue; kernel wake currently remains an explicit boundary.',
        'Establish actual accepted modified VPM loading and player sourceID9 ownership, repeated play/stop/cleanup, safe unregister/reload/unload. Keep objects/holders/signals/module pinned; current EMULATION-ONLY package must not be installed.',
        'Integrate normal player controls with direct Bluetooth endpoint and continuous/kernel pipeline, cancellation/failure recovery and navigation/speaker coexistence; stereo/fidelity tuning deprioritized.',
        'User sleeping: offline only, no calls/sounds/USB/Bluetooth/device writes or physical questions. Explicit return: prepare live audio/agent and handle pairing first. Microphone canceled, Android Auto later, Maps deferred, goal active/no-achieve.']
    now=datetime.now(timezone.utc)
    state['updated_utc']=now.isoformat();state['next_actions']=actions;app['remaining_work']=actions[:4]
    state['last_goal_turn']={'classification':'progress','previous_goal_turn_classification':'progress',
        'validated_utc':now.isoformat(),'previous_state_snapshot':previous['state'],
        'previous_current_audit_snapshot':previous['audit'],
        'previous_turn_revalidation':'Fresh prior16-scope Widget audit saved with exact canonical state;20 earlier selected suites and all prior findings frozen.',
        'reasons':[
            'Three complete groups: exact original PageCustomMainMenu constructor and native slot-clear observation; loaded Widget parent/visibility/numeric input dispatch; hidden/disabled/outside bounds and restored activation controls.',
            'Original Page and Widget event chain reaches loaded player twice via action2, with explicit geometry/numeric event fixtures and nondefault sound selector36 via original API. No direct host signal or compiled callback call; real input classification/layout/render open.',
            'Page ctor clears slot15 through original SQL setter in this sparse catalog fixture; initial lookup failure preserved, selection reapplied explicitly. Missing live kernel wake fault preserved; OS wake2FCF44 acknowledgement fixture declared without fabricating callbacks or capture flags.',
            'Original voice RAM/40 exports, loaded RX and MAIN/code/conditional full-region guards/allocation canaries retained. All15 in-memory SQL rows restored and statements finalized; actual backup unchanged. Objects/module remain pinned.',
            'User remains asleep; no device actions/sounds/questions. App/accepted loading/direct phone music and full goal remain incomplete.'],
        'build_manifest':proof['build_manifest'],'build_manifest_sha256':proof['build_manifest_sha256'],
        'integration_evidence':evidence,'integration_evidence_sha256':sha(evidence),
        'offline_integration_device_io':False,'device_io':False,'device_files_written':False,
        'native_firmware_or_research_package_written':False,'automatic_calls_or_sound':False,
        'attended_calls_or_sound':False,'automatic_calls_or_sound_while_away':False,
        'next_focus':actions[0],'goal_status':'active','full_goal_complete':False}
    for key in ['updated_utc','last_goal_turn','next_actions','current_priority','latest_user_instruction',
                'attended_testing','ordered_priorities','user_resting']:task[key]=state[key]
    task.update(stock_Page_parent_and_numeric_input_offline=True,user_away=True,
        current_connection_not_rechecked_this_offline_turn=True,current_device_connection_verified=False)
    public=read('reports/findings.json');public['deep_research']=state;public['updated']=now.isoformat()
    progress=public['research_progress'];progress['research_updated_utc']=now.isoformat()
    completed='原廠自訂主選單頁與播放器事件：三組離線驗證完整頁面建構、原廠掛接／顯示傳遞及合成事件到載入播放器；隱藏、停用與越界控制通過。座標／事件及核心喚醒仍由測試提供，自動格位、繪製與實機載入待完成'
    assert completed not in progress['completed'];progress['completed'].append(completed)
    progress['next']='接原廠自動格位建立、真正佈局／圖示繪製與頁面切換；釐清頁面初始化清除測試格位的原因，再驗證可接受的元件載入。'
    progress['phases'][4]['next']='已離線走通原廠頁面建構與播放器輸入回呼；接自動格位、真實佈局／圖示繪製、頁面切換與實機可接受的載入方式。'
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    old='<div class="card"><h2>最新離線進展：原廠按鈕建構與播放器訊號</h2>'
    assert report.count(old)==1
    card='''<div class="card"><h2>最新離線進展：原廠菜單頁接上播放器事件</h2>
<p><strong>三組完整驗證通過。</strong>精確台灣 8.00 的原廠自訂主選單頁完整建構，建立四個原廠子物件；再由原廠 API 掛入播放器按鈕、傳遞顯示狀態，頁面和按鈕事件函式可呼叫已載入的播放器，送出 WAV 登錄及開始播放請求。隱藏、停用與座標越界不會啟動播放器，恢復顯示與啟用後能再次派送。</p>
<p><strong>座標與事件仍由測試提供，沒有實機觸控或畫面完成的證據。</strong>這輪使用原廠 API 設定非預設的按鍵音選項，以跳過按鍵音等待；作業系統喚醒只記錄並回覆測試結果，沒有真正核心或畫面事件迴圈。原廠按鈕旗標沒有被捏造，亦未由測試直接呼叫播放器或軟體訊號。正常觸控如何分類成事件、原廠自動格位建立、真正佈局及圖示／文字繪製、頁面切換與螢幕提交仍待完成。</p>
<p>頁面建構在這組精簡功能清單測試中，會經原廠 SQL 函式清除播放器所在的第十五格；原因及實際開機時的行為尚未確認。測試在建構後重新選取該格位，並使用原廠掛接 API 加入按鈕，沒有宣稱一般菜單已自動保留 App。後續必須處理登錄時機與既有使用者格位資料。</p>
<p>原語音記憶體與 40 個介面、程式區、完整 RAM 初始化區及配置邊界均核對；十五格資料庫只在記憶體副本操作，最後還原，備份雜湊不變。物件、持有者與元件仍保留，安全停止／卸載待驗證。封裝仍僅供離線研究，沒有安裝到車機或發出聲音；<strong>原機 App 和手機直接藍牙音樂尚未完成。</strong></p></div>'''
    report=report.replace(old,card+'<div class="card"><h2>前輪紀錄：原廠按鈕建構與播放器訊號</h2>')
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
    print(json.dumps({'finding':'native_player_page','groups':3,'dependencies':item['source_artifact_count'],
        'estimated_progress':progress['estimate_percent'],'completed_items':len(progress['completed']),
        'updated_Taiwan':iso,'device_io':False}))


if __name__=='__main__':main()
