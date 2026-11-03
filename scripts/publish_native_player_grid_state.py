#!/usr/bin/env python3
"""Publish automatic Grid/player proof with settings and physical boundaries."""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import html
import json
import re
from check_native_music_stream_checkpoint import ROOT, read, sha, artifacts


def write(path,value):
    (ROOT/path).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')


def main():
    previous=read('staging/native-player-grid/previous-checkpoint.json')
    before,prior=read(previous['state']),read(previous['audit'])
    assert prior['all_passed'] and prior['state_sha256']==sha(previous['state'])
    state,task=read('evidence/deep-research-state.json'),read('evidence/task-state.json')
    for name,value in before['native_app_music']['static_findings'].items():
        assert state['native_app_music']['static_findings'][name]==value,name
    evidence='evidence/firmware-analysis/native-player-grid-emulation.json'
    proof=read(evidence)
    assert proof['all_passed'] and proof['case_count']==4 and not proof['device_io']
    for path,expected in proof['source_sha256'].items():assert sha(path)==expected,path
    assert sha(proof['build_manifest'])==proof['build_manifest_sha256']
    artifacts(read(proof['build_manifest']))
    assert state['user_resting'] and not state['attended_testing']['user_present']
    app=state['native_app_music']
    item={k:v for k,v in proof.items()if k not in ['source_sha256','cases','load','snapshot']}
    item.update(evidence=evidence,evidence_sha256=sha(evidence),
        source_artifact_count=len(proof['source_sha256']),case_names=[r['name']for r in proof['cases']],
        original_automatic_Grid_constructor_and_Widget_parenting_offline=True,
        original_nested_Page_Grid_Widget_numeric_input_offline=True,
        original_settings_uninitialized_failure_reset_cause_confirmed_offline=True,
        host_supplied_geometry_and_numeric_events=True,native_layout_render_and_real_touch_verified=False,
        previous_checkpoint=previous)
    app['static_findings']['native_player_grid']=item
    app['stock_automatic_Grid_population_offline']=True
    app['development_observations']['automatic_Grid']={
        'stock_Grid_ctor546C94_vtableC0DD9C_15rows72stride_19children':True,
        'native_builder546878_calls_original_getter_factory_and_parent_API':True,
        'player_cell12_caption_context_callback_retained_DB_unchanged':True,
        'setting19B_read_fails_minus1_when_readyF06EF7_is0_then3162F2_resets15':True,
        'positive_setting0_and1_controls_return4_preserve_icons_without_reset':True,
        'positive_controls_lower_persistent_record_inventory_and_ready_byte_are_fixtures':True,
        'actual_device_setting19B_or_settings_boot_initializer_not_recovered':True,
        'containing_Page_still_resets_three_times_under_uninitialized_settings_then_explicit_reselection':True,
        'Page_Grid_Widget_original_events_translate_restore_coordinates':True,
        'geometry_attempt_missingF071E8_plus8_context_read218_at4DDDBC_preserved_as_failed':True,
        'no_fake_null_context_font_metrics_or_successful_render_supplied':True,
        'separate4MiB_CPP_heap_fixture_avoids_SQL_overlap_not_actual_RAM_claim':True,
        'physical_touch_default_click_wait_native_layout_render_root_accepted_load_open':True}
    actions=[
        'Recover original GUI text/resource context initializer: original geometry attempt faults at4DDDBC because F071E8+8 is null. Complete native layout/font/bitmap/render/display and actual main-menu controller/root switch. Automatic Grid546878 now creates and parents player Widget offline, with test frames/numeric events.',
        'Recover actual persistent setting19B/readyF06EF7 boot initialization and GUI-thread registration/selection timing. Native read failure causes reset15; successful0/1 synthetic-record controls preserve icons, but actual device value unknown. Preserve user rows; recover physical input classification/click wait/posted queue and real kernel event delivery.',
        'Establish accepted modified VPM loading and sourceID9 ownership, repeated play/stop/cleanup and safe unregister/reload/unload. Keep objects/holders/signals/module pinned; do not install current EMULATION-ONLY package.',
        'Integrate player controls with direct Bluetooth endpoint and continuous/kernel pipeline, cancellation/failure recovery and navigation/speaker coexistence. Stereo/fidelity tuning deprioritized.',
        'User sleeping: offline only, no calls/sounds/USB/Bluetooth/device writes or physical questions. Explicit return: prepare live audio/agent and handle pairing first. Microphone canceled, Android Auto later, Maps deferred, goal active/no-achieve.']
    now=datetime.now(timezone.utc)
    state['updated_utc']=now.isoformat();state['next_actions']=actions;app['remaining_work']=actions[:4]
    state['last_goal_turn']={'classification':'progress','previous_goal_turn_classification':'progress',
        'validated_utc':now.isoformat(),'previous_state_snapshot':previous['state'],
        'previous_current_audit_snapshot':previous['audit'],
        'previous_turn_revalidation':'Fresh prior16-scope Page audit saved with exact canonical state;21 earlier selected suites and all79 prior findings frozen.',
        'reasons':[
            'Four complete groups: native setting failure/reset15 and positive0/1 record controls; original Grid automatic player Widget creation/parenting; nested Page/Grid/Widget numeric dispatch; hidden/disabled/outside Grid and restored activation controls.',
            'Grid constructor546C94 calls builder546878, stock SQL getter/factory/parent API and retains15 rows/19 children/player caption/context/click signal. No host factory call or direct Widget attachment. Grid remains explicitly attached to containing Page by stock API.',
            'Native setting read2CAD0A returns-1 with readyF06EF7=0;31632E then calls reset15. Successful0/1 controls return4 and preserve DB via declared lower persistent-record inventory; actual settings boot/value unknown. Page still requires explicit native reselection afterwards.',
            'Original geometry failed at4DDDBC reading218 due missing contextF071E8+8; failure/source preserved, no fake rendering pass. Nested input uses explicit frames/numeric events/enable/sound36 and kernel wake acknowledgement fixture; actual layout/touch/render/root open.',
            'Original voice RAM40 exports/code/full initialized regions and canaries retained; exact three native once-words allowed; all15 host DB rows restored/finalized/backup unchanged. Separate synthetic C++ heap is not device RAM. Objects/module remain pinned.',
            'User sleeping, no device actions/sounds/questions. App/accepted load/direct phone music and full goal remain incomplete.'],
        'build_manifest':proof['build_manifest'],'build_manifest_sha256':proof['build_manifest_sha256'],
        'integration_evidence':evidence,'integration_evidence_sha256':sha(evidence),
        'offline_integration_device_io':False,'device_io':False,'device_files_written':False,
        'native_firmware_or_research_package_written':False,'automatic_calls_or_sound':False,
        'attended_calls_or_sound':False,'automatic_calls_or_sound_while_away':False,
        'next_focus':actions[0],'goal_status':'active','full_goal_complete':False}
    for key in ['updated_utc','last_goal_turn','next_actions','current_priority','latest_user_instruction',
                'attended_testing','ordered_priorities','user_resting']:task[key]=state[key]
    task.update(stock_automatic_Grid_population_offline=True,user_away=True,
        current_connection_not_rechecked_this_offline_turn=True,current_device_connection_verified=False)
    public=read('reports/findings.json');public['deep_research']=state;public['updated']=now.isoformat()
    progress=public['research_progress'];progress['research_updated_utc']=now.isoformat()
    completed='原廠自動格位接上播放器：四組離線驗證確認十五格自動建立、原按鈕與回呼掛接、巢狀頁面事件及控制；追到設定未初始化造成重設十五格的原因。真實設定／佈局／繪製與實機載入仍待完成'
    assert completed not in progress['completed'];progress['completed'].append(completed)
    progress['next']='補原廠文字／資源環境初始化以完成佈局和繪製；研究真實設定儲存區、一般菜單頁面切換與可接受的元件載入。'
    progress['phases'][4]['next']='已離線走通自動格位建立及巢狀頁面事件；補文字／資源初始化、真實佈局和畫面、設定儲存區與實機載入。'
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    old='<div class="card"><h2>最新離線進展：原廠菜單頁接上播放器事件</h2>'
    assert report.count(old)==1
    card='''<div class="card"><h2>最新離線進展：原廠自動格位建立播放器按鈕</h2>
<p><strong>四組完整離線驗證通過。</strong>這輪讓台灣 8.00 原廠自動格位流程建立十五個格位，並自動建立、掛入「Pi 播放器」按鈕，保留標題、識別碼、回呼與所選資料。原廠頁面、格位、按鈕的事件函式可逐層轉換並還原座標，呼叫已載入的播放器，送出 WAV 登錄與開始播放請求。隱藏、停用與格位範圍外的事件不會啟動播放器。</p>
<p>前一輪清空格位的原因已追到：<strong>設定儲存區尚未初始化時，原廠讀取失敗，便重設十五格。</strong>在明列的設定記錄測試中，成功讀取值 0 或 1 都會保留圖示資料；實機的設定值與開機初始化尚未讀出。整合測試仍在頁面建構後用原廠函式重新選取播放器格位，尚未證明一般開機會自動保留新增 App。</p>
<p><strong>真正佈局與畫面仍未完成。</strong>原廠座標設定流程走到文字處理時，缺少已初始化的環境而中止；失敗記錄已保留。事件整合使用測試提供的座標與數字事件，啟用和按鍵音選項透過原廠 API 設定，核心喚醒仍是測試邊界。沒有真觸控、圖示／文字繪製、一般菜單頁面切換或螢幕提交的證據。</p>
<p>新增的模擬 C++ 記憶體區與 SQL 測試區分開，不代表車機有相同的可用記憶體。原語音記憶體、40 個介面、程式區、完整初始化資料區及配置邊界均核對；十五格資料庫只操作記憶體副本，最後還原，備份未變。物件和元件仍保留，停止／卸載及可接受的安裝封裝待研究；<strong>原機 App 和手機直接藍牙音樂尚未完成。</strong>休息期間沒有操作車機或播放聲音。</p></div>'''
    report=report.replace(old,card+'<div class="card"><h2>前輪紀錄：原廠菜單頁接上播放器事件</h2>')
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
    print(json.dumps({'finding':'native_player_grid','groups':4,'dependencies':item['source_artifact_count'],
        'estimated_progress':progress['estimate_percent'],'completed_items':len(progress['completed']),
        'updated_Taiwan':iso,'device_io':False}))


if __name__=='__main__':main()
