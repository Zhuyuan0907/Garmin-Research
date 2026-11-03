#!/usr/bin/env python3
"""Publish the built Android experiment without claiming phone or Garmin success."""
import argparse
import copy
from datetime import datetime, timezone
import gzip
import json
import os
import re
import urllib.request
from zoneinfo import ZoneInfo

from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, replace, service, sha
from publish_native_music_contracts_findings_v1 import FILES, require

FIELD = 'latest_android_hfp_prototype_checkpoint'
BUILD = ROOT / 'staging/android-hfp-prototype-apk-v3'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-proof-sha', required=True)
    args = parser.parse_args()
    raw = (BUILD / 'proof.json').read_bytes()
    require(sha(raw) == args.build_proof_sha, 'Reviewed exact Android build proof')
    proof = json.loads(raw)
    frontend_path = 'staging/native-music-frontend-membership-readonly-20261007-v1/frontend-membership.json'
    frontend_raw = (ROOT / frontend_path).read_bytes()
    require(sha(frontend_raw) == 'd13e41f3efe3c12a6e8185f66bc4aec3fcabb6e0d45acbfdc8ea35be2b9b2f1d', 'Reviewed frontend membership')
    frontend = json.loads(frontend_raw)
    require(frontend['no_new_menu_registration_or_UI_controller_adapter_call_in_entry_body']
            and frontend['separate_GUI_music_plan_is_unimplemented']
            and not frontend['native_menu_App_direct_A2DP_speaker_ownership_or_install_verified'], 'Frontend gap scope')
    for row in frontend['candidate_metadata'].values():
        require(row['entry_source_pin_matches'] and not row['adapter_implementation_in_source_hash_manifest']
                and not any(row['adapter_named_functions_declared'].values()), 'Adapter missing from candidate metadata')
    interop_path = 'evidence/android-aosp-hfp-interop.json'
    interop_raw = (ROOT / interop_path).read_bytes()
    require(sha(interop_raw) == 'fc7551ec765f2a7823b3de1ef701b85ada1c2c3ec49f6285c8e2aee9b3a95664', 'Reviewed static AOSP interop')
    receipt = json.loads((BUILD / 'actual-build-tool-receipt.json').read_text())
    require(receipt['exit_code'] == 0 and proof['all_build_checks_passed']
            and proof['API31_self_managed_call_visibility_opt_in_in_source']
            and proof['local_custom_scheme_numeric_call_handle_in_source']
            and not proof['actual_HFP_caller_ID_or_Pixel_call_visibility_verified']
            and proof['typechecked_against_real_official_Android_stub_jar'] and proof['DEX_generated']
            and proof['APK_signature_verified_for_min_API28'] and proof['APK_signature_v3_verified']
            and proof['host_gate_cases']['host_cases'] == 18
            and proof['host_load_lease_cases']['all_passed'] and proof['host_load_lease_cases']['host_cases'] >= 6
            and not proof['Android_runtime_or_phone_install_or_call_or_route_or_sound_verified'], 'Compile/sign/host scope only')
    for path, pin in proof['source_pins'].items():
        require(sha((ROOT / path).read_bytes()) == pin, 'Current built source: ' + path)
    apk = (ROOT / proof['apk']['path']).read_bytes()
    require(sha(apk) == proof['apk']['sha256'] and apk == (ROOT / 'reports/garmin-hfp-prototype.apk').read_bytes(), 'Exact signed APK copied')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    before = {name: (ROOT / name).read_bytes() for name in FILES}
    state, task, public = [json.loads(before[name]) for name in FILES[:3]]
    web = json.loads(before[FILES[4]])
    url = web['url'].rstrip('/') + '/garmin-hfp-prototype.apk'
    with opener.open(url, timeout=10) as response:
        require(response.status == 200 and response.read() == apk
                and response.headers['Content-Type'] == 'application/vnd.android.package-archive'
                and 'attachment;' in response.headers['Content-Disposition'], 'Live APK HTTP bytes/header')
    require(state == public['deep_research'], 'Prior canonical snapshot equal')
    require(all(d['current_goal_priority'] == 'bluetooth_music' and d['goal_status'] == 'active'
                and not d['goal_complete'] for d in (state, task, public, web)), 'Music active')
    require(state['navigation_repair']['status'] == 'stopped_by_user' and task['user_away']
            and not state['audio']['audible_tests_allowed'] and not web['current_physical_test_requested'], 'No physical request or navigation work')
    old_audio = copy.deepcopy(state['audio'])
    old_nav = copy.deepcopy(state['navigation_repair'])
    old_native = copy.deepcopy(state['native_app_music'])
    estimates = [public['research_progress']['estimate_percent'], [p['estimate_percent'] for p in public['research_progress']['phases']]]
    current_service = service()
    require(http(web['url'])[0] == before[FILES[3]], 'Prior exact report HTTP')
    now = datetime.now(timezone.utc)
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    stamp = local.isoformat(timespec='seconds')
    checkpoint = {'updated_utc': now.isoformat(), 'artifact': proof['apk'], 'download_url': url,
        'build_proof': {'path': str((BUILD / 'proof.json').relative_to(ROOT)), 'sha256': args.build_proof_sha},
        'scope': 'Android public platform API source, real API35 typecheck, DEX/signature and host behavior tests',
        'host_production_gate_cases': 18, 'host_player_load_lease_cases': proof['host_load_lease_cases']['host_cases'], 'HTTP_route_cases': 13,
        'entry': 'user-chosen local document, explicitly selected paired Garmin, local self-managed incoming call',
        'controls': 'explicit Play only after answered call and verified selected route; start player muted and confirm exact SCO address before unmute; ten-second cap and Stop cleanup',
        'runtime_device_route_or_sound_verified': False, 'APK_installed': False,
        'no_RECORD_AUDIO_CALL_PHONE_INTERNET_permissions': True, 'no_full_SDK_installed': True,
        'local_document_provider_and_setDataSource_can_block_main_thread': False,
        'provider_and_player_operations_on_background_thread_in_source': True,
        'blocked_provider_can_stall_worker': True, 'blocked_provider_force_cancel_verified': False,
        'process_player_job_limit': 1,
        'route_callback_gap_guarantees_zero_leakage': False,
        'native_Garmin_A2DP_menu_App_or_install_ready': False, 'Pi_elimination_verified': False,
        'native_work_preserved': True, 'full_goal_complete': False, 'device_IO': False}
    checkpoint.update(local_call_handle='garminmusic:0000', local_call_handle_is_carrier_dial=False,
        API31_self_managed_visibility_opt_in_requested_in_source=True,
        Pixel_call_visibility_or_final_HFP_caller_number_verified=False,
        static_AOSP_interop_evidence={'path': interop_path, 'sha256': sha(interop_raw)})
    native_field = 'latest_native_music_frontend_checkpoint'
    native_checkpoint = {'updated_utc': now.isoformat(), 'path': frontend_path, 'sha256': sha(frontend_raw),
        'entry_source_matches_both_candidate_manifests': True,
        'entry_adds_menu_registration_or_adapter_activation': False,
        'adapter_header_declared_but_implementation_and_functions_missing': True,
        'public_object_retention_alone_integrates_App': False,
        'GUI_and_music_separate_plan_implemented': False,
        'native_same_image_menu_App_or_phone_sound_verified': False,
        'native_compile_execution_or_device_IO': False, 'full_goal_complete': False}
    next_actions = [
        'Android第三版實驗APK已編譯／簽章核對，音檔背景載入保留，更新本機來電識別及API31通話介面可見性申請；使用者通知可操作時，先驗證自管來電與接聽回呼，再確認Garmin實際端點，最後短播本機音檔。尚未證明手機直接出聲或省去Pi，不自動發來電。',
        '原機A2DP／菜單App目標維持：完整性工具已拒絕缺四個函式及介面物件的兩候選；控制函式保留、來源所有權／停止重啟及新版端點啟用接線仍未完成；Android APK只是平行路徑，不是原機安裝包。',
        '導航／麥克風停止，Android Auto／Google Maps延後。使用者會通知可實測時間；目前不要求接線或配對。',
    ]
    state.update(updated_utc=now.isoformat(), next_actions=copy.deepcopy(next_actions))
    state[FIELD] = copy.deepcopy(checkpoint)
    state['native_app_music'][FIELD] = copy.deepcopy(checkpoint)
    state[native_field] = copy.deepcopy(native_checkpoint)
    state['native_app_music'][native_field] = copy.deepcopy(native_checkpoint)
    state['native_app_music']['remaining_work'] = [
        '單一原機候選仍是被動TTS載入入口與後台API；菜單前端及來源管理adapter未整合。須在合法UI owner／初始化完成後做單次延後啟用，不重跑語音bootstrap。',
        '以明確linker root保留36-byte公開介面物件，另確認kick與必要helper保留；新版型別／同映像狀態地址須完整接線，不能cast舊表或挪用另一版位址。',
        '來源發布、原始清理返回、永久身分／所有權及重新啟動仍未完成；真正A2DP端點／手機封包／喇叭／导航共存均待驗證。',
        'Android第三版APK已編譯：本機數字識別與API31可見性申請，不撥電信電話；等使用者通知可實測時先連線，再測來電／接聽、exact SCO及短音檔。',
    ]
    work = state['offline_24h_work_order']
    work[FIELD] = copy.deepcopy(checkpoint)
    work[native_field] = copy.deepcopy(native_checkpoint)
    work['current_offline_line_status']['android_direct_HFP'] = 'Signed v3 APK: local numeric custom-scheme caller identity and API31 visibility opt-in requested; phone call/endpoint/sound unverified'
    turn = {'classification': 'Android_HFP_local_identity_and_native_frontend_membership_progress', 'previous_goal_turn_classification': 'progress',
        'validated_utc': now.isoformat(), 'goal_status': 'active', 'full_goal_complete': False, 'required_work_remaining': True,
        'device_files_written': False, 'reason': 'Actual v3 compile/sign/control results accompany AOSP-derived local caller identity and visibility configuration; native source membership proves frontend/adapter still missing from passive candidates. Hardware playback remains unverified.'}
    state['last_goal_turn'] = copy.deepcopy(turn)
    for key in ('updated_utc', 'next_actions', 'offline_24h_work_order', FIELD, native_field, 'last_goal_turn'):
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state), offline_24h_work_order=copy.deepcopy(work), last_goal_turn=copy.deepcopy(turn))
    public[FIELD] = copy.deepcopy(checkpoint)
    public[native_field] = copy.deepcopy(native_checkpoint)
    public['research_progress'].update(research_updated_utc=now.isoformat(), next=next_actions[0])
    report = before[FILES[3]].decode()
    card = ('<section class="card" id="bluetooth-music-current-checkpoint-v1"><h2>藍牙音樂：Android 第三版—本機來電相容性</h2>'
        f'<p>更新：<time datetime="{stamp}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>（台灣時間）</p>'
        '<p>已產生手機端的本機音檔試驗APK：以自管通話經Garmin的HFP通話音訊播放。它不是GarminOS菜單App，也不是原機A2DP；原生研究目標維持。</p>'
        '<p><a href="/garmin-hfp-prototype.apk" download="garmin-hfp-prototype.apk">下載 Android 第三版實驗 APK</a> '
        f'（{len(apk):,} bytes，Android 9／API28以上；Pixel版本尚未確認）</p><ul>'
        '<li><strong>本次修改：</strong>自管測試來電統一用garminmusic:0000，讓來電與通話清單的Java輸入避免斜線／字母格式差異；API31以上明確申請把本機通話提供給支援自管通話的系統介面。'
        '<a href="https://developer.android.com/reference/android/telecom/PhoneAccount#EXTRA_ADD_SELF_MANAGED_CALLS_TO_INCALLSERVICE">公開PhoneAccount設定</a>不保證Pixel实际可見性或Garmin接受。</li>'
        '<li><strong>已完成：</strong>對Google官方API35 stub做完整Java型別檢查、生成DEX、APK簽章驗證；實際使用的播放控制通過18項主機案例。'
        f'新增背景載入lease通過{proof["host_load_lease_cases"]["host_cases"]}項主機控制；下載服務原13項路由檢查保留，並確認第三版實際APK讀回一致。這些檢查不證明手機或車機出聲。</li>'
        '<li><strong>操作流程：</strong>選本機音檔及已配對Garmin → 按建立本機來電 → 接聽 → 等指定端點確認 → 按播放，最多10秒。'
        '通話聲道由公開<a href="https://developer.android.com/reference/android/telecom/ConnectionService">ConnectionService API</a>管理；不撥電信電話，沒有麥克風錄音功能或網路權限。</li>'
        '<li><strong>停止條件：</strong>未接聽、路由不符／消失、逾時、掛斷、媒體錯誤或Stop均停止並釋放播放器；新session不接受舊回呼。'
        '播放先靜音，再核對實際SCO裝置。provider及MediaPlayer操作改在背景；Stop先作廢lease，過期結果不准播放。單一process只容許一個未回收player job。Android回呼／排程仍需實測。</li>'
        '<li><strong>仍未驗證：</strong>Pixel是否允許自管來電、Garmin能否接聽、端點名稱與SCO位址是否可取得、選定音檔是否真正從Garmin出聲。'
        '沒有安裝APK、配對、發來電或播音；通話音質限制仍在。provider若不返回可卡住背景worker，不能強制中止；後續播放會拒絕busy。此時不宣稱立即回收或硬體截止，Android實際行為尚未驗證。</li>'
        '<li><strong>原機進度：</strong>兩版控制器建置宣告缺四個函式與公開介面物件，端點載入回傳不等於音樂啟用成功；來源所有權、發布後停止及重啟仍待接線。'
        '沒有Garmin原生可安裝整合包。</li></ul>'
        '<p>原生App工程估計維持40%，不把Android替代原型算成Garmin原機完成。導航／麥克風已停止；目前不要求接線，等使用者通知可操作時間。</p></section>')
    report, count = re.subn(r'<section class="card" id="bluetooth-music-current-checkpoint-v1">.*?</section>', lambda _: card, report, count=1, flags=re.S)
    require(count == 1, 'Current card')
    native_card = ('<section class="card" id="native-music-frontend-checkpoint-v1"><h2>原機App：菜單前端與播放候選仍分開</h2>'
        f'<p>更新：<time datetime="{stamp}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>（台灣時間）</p>'
        '<p>已核對當前兩候選的入口C檔與建置宣告雜湊。新增入口只做BSS初始化、呼叫原廠TTS入口並保留原回傳；公開resident API提供後台方法指標，入口本身不呼叫來源啟動／菜單註冊。</p>'
        '<p>候選宣告有adapter header，卻無adapter C／四個具名管理函式；歷史連結參數也沒有該adapter物件。先前GUI与播放的整合計畫仍標示未實作，因此既有畫面模擬不能證明這份候選有菜單App。</p>'
        '<p>已保存的兩份builder AST有明確KEEP保留resident API，沒有公開控制表的explicit KEEP；nm的-u不是linker root。此為來源設定核對，未新讀或執行ELF／物件，實際GC圖仍未驗證。</p>'
        '<p>下一個原機缺口是合法UI owner延後啟用、同映像型別／狀態接線與來源生命週期；僅保留公開表不會完成App。仍無可安裝原機音樂包。</p></section>')
    native_anchor = '<section class="card" id="native-music-control-retention-checkpoint-v1">'
    require(report.count(native_anchor) == 1, 'Native retention anchor')
    report = report.replace(native_anchor, native_card + native_anchor, 1)
    report, count = re.subn(r'<p id="offline-frontier-latest-v1">.*?</p>',
        lambda _: '<p id="offline-frontier-latest-v1">最新：Android第三版已更新本機來電識別與API31可見性申請，編譯／簽章及30項主機控制通過。原機被動候選尚未整合菜單／來源橋接，手機直接出聲仍未驗證。</p>', report, count=1, flags=re.S)
    require(count == 1, 'Current frontier')
    report, count = re.subn(r'<p><strong>下一步：</strong>保留原機A2DP／菜單App研究，Android第二版背景載入APK待使用者通知.*?</p>',
        lambda _: '<p><strong>下一步：</strong>保留原機A2DP／菜單App研究，Android第三版本機來電APK待使用者通知可操作時依序驗證來電、端點及十秒音檔播放；現在不需接線或配對。</p>', report, count=1, flags=re.S)
    require(count == 1, 'Current next action')
    for name in ('report-updated-time', 'research-updated-time'):
        report, count = re.subn(r'<time id="' + name + r'" datetime="[^"]+">[^<]+</time>',
            lambda _: f'<time id="{name}" datetime="{stamp}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>', report, count=1)
        require(count == 1, 'Timestamp')
    expected_native = copy.deepcopy(old_native)
    expected_native[FIELD] = copy.deepcopy(checkpoint)
    expected_native[native_field] = copy.deepcopy(native_checkpoint)
    expected_native['remaining_work'] = copy.deepcopy(state['native_app_music']['remaining_work'])
    require(state['native_app_music'] == expected_native and state['audio'] == old_audio and state['navigation_repair'] == old_nav, 'History preserved')
    require(estimates == [public['research_progress']['estimate_percent'], [p['estimate_percent'] for p in public['research_progress']['phases']]], 'No native progress inflation')
    out = ROOT / 'staging' / ('android-hfp-prototype-v3-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(mode=0o700)
    for path, data in before.items():
        (out / (path.replace('/', '__') + '.gz')).write_bytes(gzip.compress(data, mtime=0))
    for path, value in zip(FILES[:4], (state, task, public, report)):
        replace(path, value)
    served, response = http(web['url'])
    require(served == report.encode() and service() == current_service, 'Fresh report and stable deployed server')
    web.update(updated_utc=now.isoformat(), HTTP_status=response['status'], local_report_sha256=sha(served),
        served_report_sha256=sha(served), report_bytes=len(served), service=current_service, service_not_restarted=True,
        offline_24h_work_order=copy.deepcopy(work), last_goal_turn=copy.deepcopy(turn))
    web[FIELD] = copy.deepcopy(checkpoint)
    web[native_field] = copy.deepcopy(native_checkpoint)
    web['progress_display_verified'].update(report_updated_time=stamp, research_updated_time=stamp, Android_experiment_download_visible=True)
    replace(FILES[4], web)
    fresh = [json.loads((ROOT / p).read_bytes()) for p in (FILES[0], FILES[1], FILES[2], FILES[4])]
    require(fresh[0] == fresh[2]['deep_research'] and all(d[FIELD] == checkpoint and d['goal_status'] == 'active'
                and not d['goal_complete'] for d in fresh), 'Canonical readback, goal incomplete')
    require(all(d[native_field] == native_checkpoint for d in fresh), 'Native frontend scope canonical equality')
    create(out / 'fresh-readback.json', {'all_passed': True, 'updated_at_Taiwan': stamp, 'APK_HTTP_verified': True,
        'APK_sha256': sha(apk), 'report_url': web['url'], 'service': current_service, 'device_IO': False, 'full_goal_complete': False})
    print(json.dumps({'all_passed': True, 'snapshot': str(out.relative_to(ROOT)), 'updated_at_Taiwan': stamp,
        'download_url': url, 'APK_bytes': len(apk), 'runtime_sound_verified': False, 'device_IO': False}))


if __name__ == '__main__':
    main()
