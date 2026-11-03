#!/usr/bin/env python3
"""Publish native raw external-font loading with explicit display limits."""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import html
import json
import re
from check_native_music_stream_checkpoint import ROOT, read, sha, artifacts


def write(path, value):
    (ROOT/path).write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n')


def main():
    previous = read('staging/native-player-external-fonts/previous-checkpoint.json')
    before, prior = read(previous['state']), read(previous['audit'])
    assert prior['all_passed'] and prior['state_sha256'] == sha(previous['state'])
    state, task = read('evidence/deep-research-state.json'), read('evidence/task-state.json')
    for name, value in before['native_app_music']['static_findings'].items():
        assert state['native_app_music']['static_findings'][name] == value, name
    path = 'evidence/firmware-analysis/native-player-external-fonts-emulation.json'
    proof = read(path)
    assert proof['all_passed'] and proof['case_count'] == 5 and not proof['device_io']
    for source, expected in proof['source_sha256'].items():
        assert sha(source) == expected, source
    assert sha(proof['build_manifest']) == proof['build_manifest_sha256']
    artifacts(read(proof['build_manifest']))
    assert state['user_resting'] and not state['attended_testing']['user_present']
    fonts = proof['cases'][1]
    item = {k: proof[k] for k in ['MAIN_sha256', 'build_manifest', 'build_manifest_sha256', 'case_count',
        'all_passed', 'device_io', 'device_files_modified', 'sounds_emitted', 'device_install_candidate',
        'actual_package_acceptance_verified', 'native_App_running_on_device', 'phone_direct_music_verified',
        'raw_backup_CJK_fonts_loaded_offline', 'native_XOR76_reader_executed', 'host_decoded_font_bytes_supplied',
        'actual_boot_resource_setup_executed', 'real_rendering_or_display_verified', 'limits']}
    item.update(evidence=path, evidence_sha256=sha(path), source_artifact_count=len(proof['source_sha256']),
        case_names=[r['name'] for r in proof['cases']], previous_checkpoint=previous,
        active_font_indices=fonts['active_font_indices'], active_external_font_indices=fonts['active_external_font_indices'],
        active_embedded_font_indices=fonts['active_embedded_font_indices'],
        missing_backup_descriptor_indices=fonts['missing_backup_descriptor_indices'],
        native_CJK_glyph_indices=next(r['native_glyph_indices'] for r in fonts['native_glyph_queries'] if r['font_index'] == 2),
        raw_read_control_font_count=proof['cases'][0]['raw_source_control_count'],
        native_font_allocation_count=len(proof['snapshot']['original_font_persistent_handles']),
        resident_external_font_stream_count=sum(not e['closed'] for e in proof['resident_font_stream_inventory'].values()),
        generic_font_file_operations=len(proof['generic_font_file_requests']),
        callback_startup_zero_mapping_count=len(proof['callback_verified_startup_zero_mappings']),
        unrelated_shared_file_manager_calls_delegate_to_inherited_backend=True,
        CJK_paint_or_display_newly_verified=False)
    app = state['native_app_music']
    app['static_findings']['native_player_external_fonts'] = item
    app['native_CJK_font_loading_from_raw_backup_offline'] = True
    app['development_observations']['external_font_loading'] = dict(
        original_descriptor_filename_plus50_and_ExtData_prefix_recovered=True,
        original_read_wrapper14098C_XOR76_executed=True,
        raw_font_bytes_from_backup_no_host_decoding_or_glyph_success=True,
        eight_external_three_embedded_fonts_active_two_exact_backup_files_absent=True,
        native_CJK_glyph_indices_match_independent_cmap=True,
        eight_path_header_offset_controls_signed_seek_partial_element_EOF_zero_missing_passed=True,
        generic_file_manager_fixture_scoped_to_font_fopen_caller_and_owned_handles=True,
        unrelated_file_manager_cleanup_delegated_to_inherited_backend=True,
        callback_direct_writes_map_only_exact_verified_startup_zero_BSS=True,
        same_original_native_Widget_geometry_state_updater_and_nested_events_passed=True,
        external_font_streams_and_contexts_stay_resident_release_unknown=True,
        actual_boot_FAT_resource_setup_font_rendering_display_touch_install_unverified=True)
    actions = [
        'Complete native caption/icon rendering and canvas clipping/draw submission with the now-loaded raw-backup CJK fonts; stock glyph lookup is proven, pixels/display are not. Recover normal MainMenu controller/root and actual resize/dirty notification; containing Page frame remains a test input after earlier native geometry resource-limit failures.',
        'Recover actual settings19B/ready boot, real UI thread and catalog/selection timing; default click sound wait, posted callback queue, touch classification and kernel event delivery remain open.',
        'Establish actual modified VPM acceptance plus sourceID9 repeated play/stop/cleanup, safe detach/unregister/reload/unload and native release of resident font contexts/eight external streams. Same54982-byte EMULATION-ONLY package must not be installed.',
        'Integrate player controls with direct phone Bluetooth endpoint, continuous native/kernel audio and recovery/navigation coexistence; stereo/fidelity tuning remains deprioritized.',
        'User sleeping: offline only, no USB/Bluetooth/device writes, calls/sounds or physical questions. Explicit return: live audio/agent and pairing first. Microphone canceled, Android Auto later, Maps deferred, goal active/no-achieve.']
    now = datetime.now(timezone.utc)
    state.update(updated_utc=now.isoformat(), next_actions=actions)
    app['remaining_work'] = actions[:4]
    state['last_goal_turn'] = dict(classification='progress', previous_goal_turn_classification='progress',
        validated_utc=now.isoformat(), previous_state_snapshot=previous['state'],
        previous_current_audit_snapshot=previous['audit'],
        previous_turn_revalidation='Fresh16-scope native-text audit;23 earlier selected suites and all81 prior findings frozen.',
        reasons=[
            'Five complete groups:8raw file/path/XOR/header/offset/EOF controls; original external font initializer and actual CJK glyph lookup; native two-size Widget geometry; native state refresh/events; context/visibility/outside controls. All final guards passed.',
            'Original14098C transforms exact raw ExtData backup bytes with native XOR76, not host-decoded fonts. Explicit initializer parameter1 loads8external and3embedded fonts; two named resources absent from this exact backup remain inactive. Chinese glyph indices match independent cmap.',
            'Scoped lower generic file-manager boundaries retain unrelated inherited backend/cleanup. Only verified startup-zero BSS pages mapped for direct file-callback writes. Native prefixes/pointer queries/bookkeeping0/canaries checked, no native pin-count claim.',
            'Same native geometry/updater/nested numeric player requests retained with outer Page/frame/input/kernel/audio fixtures. Original voice wholeRAM40/private12/player2/code/full regions/exact three once-words and SQL15 restored/finalized; backup font files/database unchanged.',
            'Actual font painting/screen, general MainMenu/root, boot FAT/resource initialization, physical touch, accepted installation, native App/direct music and safe lifecycle remain open. Font contexts/eight streams remain resident; user away, no device operations/sound.'],
        build_manifest=proof['build_manifest'], build_manifest_sha256=proof['build_manifest_sha256'],
        integration_evidence=path, integration_evidence_sha256=sha(path),
        offline_integration_device_io=False, device_io=False, device_files_written=False,
        native_firmware_or_research_package_written=False, automatic_calls_or_sound=False,
        attended_calls_or_sound=False, automatic_calls_or_sound_while_away=False,
        next_focus=actions[0], goal_status='active', full_goal_complete=False)
    for key in ['updated_utc', 'last_goal_turn', 'next_actions', 'current_priority', 'latest_user_instruction',
        'attended_testing', 'ordered_priorities', 'user_resting']:
        task[key] = state[key]
    task.update(native_CJK_font_loading_from_raw_backup_offline=True, user_away=True,
        current_connection_not_rechecked_this_offline_turn=True, current_device_connection_verified=False)
    public = read('reports/findings.json')
    public.update(deep_research=state, updated=now.isoformat())
    progress = public['research_progress']
    progress['research_updated_utc'] = now.isoformat()
    completed = '原廠外部繁中字型載入：五組離線驗證讓原廠路徑轉換、XOR 讀取與解析器載入八套備份字型，播放器／竺原字元查詢相符；加入檔尾控制並保留原廠菜單事件與最後邊界檢查。文字繪圖／畫面與實機 App 仍待完成'
    assert completed not in progress['completed']
    progress['completed'].append(completed)
    progress['next'] = '繁中字型已由原廠讀取／解析指令載入；接著處理文字、圖示與畫布繪製，以及一般菜單頁面切換和實機載入流程。'
    progress['phases'][4]['next'] = '繁中字型、按鈕佈局與狀態回呼已離線走通；補實際繪圖／畫面、一般菜單切換、真觸控與可接受的實機載入。'
    report = (ROOT/'reports/nuvi2565RT.html').read_text()
    old = '<div class="card"><h2>最新離線進展：原廠字型、格位佈局與播放器狀態</h2>'
    assert report.count(old) == 1
    card = '''<div class="card"><h2>最新離線進展：原廠流程載入繁中字型</h2>
<p><strong>五組完整離線驗證通過。</strong>已讓台灣 8.00 的原廠路徑轉換、字型讀取、byte 轉換及解析指令讀取備份中的原始字型資料。原廠函式使用 XOR 0x76，這次由原廠指令執行，沒有由模擬器提供已轉換字型或虛構字元查詢成功。</p>
<p>共載入八套外部字型與三套內嵌字型；原廠表格另外指定的兩個檔案未出現在這份 USB 備份，因此保持未載入。<strong>原廠繁中字型查詢已能找到「播放器」與「竺原」。</strong>實際字元編號與獨立讀取的字型表相符。八個檔案的路徑、開啟、標頭、偏移讀取與關閉測試，以及檔尾、短讀、零長度和缺檔控制均通過。</p>
<p>繁中字型也已接回同一個播放器模擬流程，原廠按鈕佈局、啟用／停用回呼及頁面事件仍能送出播放請求。原語音記憶體與 40 個介面、程式區、完整資料區、配置邊界及資料庫還原等最後檢查通過；備份字型與資料庫未變。</p>
<p><strong>字元能載入，畫面仍未完成。</strong>目前提供的是備份檔案的底層唯讀 I/O，實機檔案系統、開機資源準備及一般菜單頁面切換尚未執行。這輪還沒有驗證外部字型的文字繪圖、畫布內容或螢幕輸出；前輪只有內嵌字型的繪圖試驗沒有改變任何畫布 byte，不能把載入字型當成画面完成。頁面外框、數字事件、按鍵音與核心喚醒仍是測試條件。字型物件和八個原廠外部字型串流保持常駐，安全釋放待完成。</p>
<p>下一步是接原廠文字／圖示繪圖、畫布裁切與一般主選單控制流程，再處理實機接受修改封裝及播放停止／清理。封裝仍只供離線研究；<strong>原機 App 和手機直接藍牙音樂尚未完成。</strong>使用者休息期間沒有操作車機或播放聲音。</p></div>'''.replace('画面','畫面')
    report = report.replace(old, card+'<div class="card"><h2>前輪紀錄：原廠字型、格位佈局與播放器狀態</h2>')
    report, count = re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',
        lambda m: m[1]+m[2]+'<li>'+html.escape(completed)+'</li>'+m[3], report, count=1, flags=re.S)
    assert count == 1
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    iso, display = local.isoformat(timespec='seconds'), local.strftime('%Y/%m/%d %H:%M:%S')
    for ident in ['report-updated-time', 'research-updated-time']:
        report, count = re.subn(r'<time id="'+ident+r'" datetime="[^"]+">[^<]+</time>',
            '<time id="'+ident+'" datetime="'+iso+'">'+display+'</time>', report, count=1)
        assert count == 1
    write('evidence/deep-research-state.json', state)
    write('evidence/task-state.json', task)
    write('reports/findings.json', public)
    (ROOT/'reports/nuvi2565RT.html').write_text(report)
    print(json.dumps(dict(finding='native_player_external_fonts', groups=5,
        dependencies=item['source_artifact_count'], estimated_progress=progress['estimate_percent'],
        completed_items=len(progress['completed']), updated_Taiwan=iso, device_io=False)))


if __name__ == '__main__':
    main()
