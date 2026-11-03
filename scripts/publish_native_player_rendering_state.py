#!/usr/bin/env python3
"""Publish original software-canvas caption proof without a display claim."""
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
import base64,html,json,re
from check_native_music_stream_checkpoint import ROOT,read,sha,artifacts


def write(path,value):
    (ROOT/path).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')


def main():
    previous=read('staging/native-player-rendering/previous-checkpoint.json')
    before,prior=read(previous['state']),read(previous['audit'])
    assert prior['all_passed'] and prior['state_sha256']==sha(previous['state'])
    state,task=read('evidence/deep-research-state.json'),read('evidence/task-state.json')
    assert state['user_resting'] and not state['attended_testing']['user_present']
    for name,value in before['native_app_music']['static_findings'].items():
        assert state['native_app_music']['static_findings'][name]==value,name
    path='evidence/firmware-analysis/native-player-rendering-emulation.json';proof=read(path)
    assert proof['all_passed'] and proof['case_count']==5 and not proof['device_io']
    for source,expected in proof['source_sha256'].items():assert sha(source)==expected,source
    artifacts(read(proof['build_manifest']))
    full,clipped=proof['cases'][1]['paint'],proof['cases'][2]['paint']
    item={k:proof[k]for k in ['MAIN_sha256','build_manifest','build_manifest_sha256','case_count','all_passed',
        'native_software_canvas_pixels_verified','original_native_glyph_rasterization_and_cached_Label_blit_executed',
        'glyph_metrics_indices_or_caption_pixels_mocked','host_wrote_pixel_buffer',
        'actual_display_framebuffer_submission_verified','actual_UI_thread_root_touch_verified',
        'device_io','sounds_emitted','device_install_candidate','actual_package_acceptance_verified',
        'native_App_running_on_device','phone_direct_music_verified','limits']}
    item.update(evidence=path,evidence_sha256=sha(path),source_artifact_count=len(proof['source_sha256']),
        previous_checkpoint=previous,case_names=[r['name']for r in proof['cases']],
        native_caption='Pi 播放器',full_caption_changed_pixels=full['changed_pixel_count'],
        full_caption_changed_bytes=full['changed_bytes'],full_caption_pixel_bounds=full['changed_bounds'],
        clipped_caption_changed_pixels=clipped['changed_pixel_count'],
        original_caption_fallback_font_indices=sorted(set(r['font_index']for r in proof['cases'][0]['actual_native_CJK_query_results'])),
        original_raster_flags8_path='0x26659e -> 0x13cf46',
        caption_preview='staging/native-player-rendering/loaded-caption-RGB565-preview.png',
        native_nonempty_icon_rendering_verified=False)
    app=state['native_app_music'];app['static_findings']['native_player_rendering']=item
    app['current_player_variant']=proof['build_manifest']
    app['native_caption_software_canvas_rendering_offline']=True
    app['development_observations']['caption_rendering']=dict(
        original_Label_caption_and_geometry_plus_native_CJK_fallback_verified=True,
        original_raster_flags8_13CF46_path_verified_14EC9C_branch_not_claimed=True,
        original_white_background_and_cached_Label_blit_change213_pixels=True,
        clip_preserves_exact_original_caption_pixel_subset_and_colors=True,
        outside_clip_no_writes_and_restore_repaint_byte_identical=True,
        native_player_numeric_events_retained_after_paint=True,
        prior_zero_difference_black_background_probe_superseded_not_native_draw_absence=True,
        icons_remain_blank_original_resource_placeholders=True,
        actual_framebuffer_display_UI_thread_root_touch_and_install_unverified=True)
    actions=[
        'Recover nonempty native icon/material resources and normal MainMenu controller/root. Original native caption rasterization and software-canvas clipping now work; actual framebuffer submission/display, real resize/dirty notification and Page geometry remain open.',
        'Recover actual settings19B, boot resource inventory, UI-thread and catalog registration/selection timing; posted queue, real touch classification and kernel delivery remain fixtures.',
        'Establish modified VPM acceptance and sourceID9 repeated playback/stop/cleanup, safe detach/unregister/reload/unload plus native font/cache/stream release. Preserved54982-byte package remains EMULATION-ONLY and must not be installed.',
        'Connect player controls to direct phone Bluetooth and continuous native/kernel audio with recovery/navigation coexistence; stereo/fidelity tuning stays deprioritized.',
        'User still sleeping: offline only, no USB/Bluetooth/device writes, calls/sounds or physical questions. Explicit return: live audio/agent and pairing first. Microphone canceled, Android Auto later, Maps deferred, goal active/no-achieve.']
    now=datetime.now(timezone.utc);state.update(updated_utc=now.isoformat(),next_actions=actions)
    app['remaining_work']=actions[:4]
    state['last_goal_turn']=dict(classification='progress',previous_goal_turn_classification='progress',
        validated_utc=now.isoformat(),previous_state_snapshot=previous['state'],previous_current_audit_snapshot=previous['audit'],
        previous_turn_revalidation='Fresh16-scope external-font audit saved; prior24 selected suites/all82 findings frozen.',
        reasons=[
            'Five complete original loader/font/Label/paint/clip/events groups and final original-region/voice/code/canary/DB checks passed.',
            'Original CJK fallback queries match backup cmap; actual font raster path uses flags8 ->13CF46, not assumed14EC9C. Label bitmap prepared by native code and drawn with original ARM blitter.',
            'Original white background exposes213 changed caption pixels/426 bytes. Native clipping retains exact glyph subset/colors; outside clip writes nothing; full repaint byte-identical.',
            'Numeric Page/Grid/Widget player events still reach resident compiled callback after paint. Original voice wholeRAM40/private12/player2 and exact once-words retained; SQL15 restored/finalized and raw backups unchanged.',
            'Actual screen/framebuffer, UI thread/root/boot/touch, nonempty icons, accepted modified package, native App/direct phone audio and safe resource/source lifecycle remain open. User asleep, no device operations or sound.'],
        build_manifest=proof['build_manifest'],build_manifest_sha256=proof['build_manifest_sha256'],
        integration_evidence=path,integration_evidence_sha256=sha(path),offline_integration_device_io=False,
        device_io=False,device_files_written=False,native_firmware_or_research_package_written=False,
        automatic_calls_or_sound=False,attended_calls_or_sound=False,automatic_calls_or_sound_while_away=False,
        next_focus=actions[0],goal_status='active',full_goal_complete=False)
    for key in ['updated_utc','last_goal_turn','next_actions','current_priority','latest_user_instruction',
        'attended_testing','ordered_priorities','user_resting']:task[key]=state[key]
    task.update(native_caption_software_canvas_rendering_offline=True,user_away=True,
        current_player_variant=proof['build_manifest'],
        current_connection_not_rechecked_this_offline_turn=True,current_device_connection_verified=False)
    public=read('reports/findings.json');public.update(deep_research=state,updated=now.isoformat())
    progress=public['research_progress'];progress['research_updated_utc']=now.isoformat()
    completed='原廠播放器文字繪製：五組完整離線驗證以原廠中文字形、點陣與畫布函式畫出「Pi 播放器」，白色測試背景上有 213 個像素變化；裁切只保留相同子集、重画一致且按鈕事件仍可播放。尚未提交至車機螢幕或安裝 App'.replace('重画','重畫')
    assert completed not in progress['completed'];progress['completed'].append(completed)
    progress['next']='原廠播放器文字已畫入模擬畫布；接著補非空圖示、一般主選單控制及真實畫面提交，再確認實機能接受自製元件。'
    progress['phases'][4]['next']='繁中文字形、標籤繪圖、裁切與按鈕事件已離線走通；補圖示、一般菜單／螢幕提交、真觸控及可接受的實機載入。'
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    old='<div class="card"><h2>最新離線進展：原廠流程載入繁中字型</h2>';assert report.count(old)==1
    preview=base64.b64encode((ROOT/item['caption_preview']).read_bytes()).decode()
    card='''<div class="card"><h2>最新離線進展：播放器文字已畫入模擬畫布</h2>
<p><strong>五組完整離線驗證通過。</strong>原廠載入器讀入播放器元件後，原廠菜單自動建立文字元件、計算佈局並查詢繁中字形。這次也追到實際使用的字形點陣路徑，再由原廠快取圖像與畫布函式繪製；沒有由模擬器生成標籤文字像素。</p>
<p>原廠函式畫白色測試背景後，「Pi 播放器」造成 <strong>213 個像素、426 bytes 的變化</strong>。原廠裁切僅保留指定範圍內的相同文字像素與色階；範圍完全在文字外時沒有寫入，恢復裁切後重畫逐 byte 相同。本輪黑底對照沒有 byte 變化，但原廠有進行繪製，只是黑色字形與背景重疊。</p>
<figure><img style="max-width:100%;width:400px;height:auto" src="data:image/png;base64,'''+preview+'''" alt="原廠指令繪製的 Pi 播放器標籤，模擬畫布局部放大"><figcaption>模擬畫布的文字局部放大；不是車機截圖。原始 480×272 像素資料另已保存。</figcaption></figure>
<p>繪圖後，原廠頁面／格位／按鈕事件仍能送出播放請求；原語音記憶體與 40 個介面、程式區、配置边界、完整資料區及資料庫還原等最後檢查通過。備份字型與資料庫保持原樣。</p>
<p><strong>目前完成的是離線文字畫布。</strong>白色背景、裁切要求、頁面外框與數字事件是明示的測試輸入；底層檔案、資料庫、記憶體、核心及音訊仍有模擬邊界。圖示資源仍為空白占位，一般主選單控制、畫布提交到真實螢幕、UI 執行緒、真觸控及修改封裝的實機接受尚未驗證。沒有在原機安裝播放器 App，也沒有讓手機直接連原機播放音樂。</p>
<p>下一步補圖示、一般菜單與螢幕提交，再處理實機載入、播放停止及資源清理；研究封裝仍只供離線使用。使用者休息期間沒有操作車機或播放聲音。</p></div>'''.replace('边界','邊界')
    report=report.replace(old,card+'<div class="card"><h2>前輪紀錄：原廠流程載入繁中字型</h2>')
    report,count=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',
        lambda m:m[1]+m[2]+'<li>'+html.escape(completed)+'</li>'+m[3],report,count=1,flags=re.S);assert count==1
    local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds');display=local.strftime('%Y/%m/%d %H:%M:%S')
    for ident in ['report-updated-time','research-updated-time']:
        report,count=re.subn(r'<time id="'+ident+r'" datetime="[^"]+">[^<]+</time>',
            '<time id="'+ident+'" datetime="'+iso+'">'+display+'</time>',report,count=1);assert count==1
    write('evidence/deep-research-state.json',state);write('evidence/task-state.json',task);write('reports/findings.json',public)
    (ROOT/'reports/nuvi2565RT.html').write_text(report)
    print(json.dumps(dict(finding='native_player_rendering',groups=5,dependencies=item['source_artifact_count'],
        estimate_percent=progress['estimate_percent'],completed_items=len(progress['completed']),updated_Taiwan=iso,device_io=False)))


if __name__=='__main__':main()
