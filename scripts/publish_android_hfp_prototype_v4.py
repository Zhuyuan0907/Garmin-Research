#!/usr/bin/env python3
"""Publish the host-built Android experiment and its actual, limited evidence."""
import copy
import gzip
import hashlib
import json
import os
import re
import stat
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
FILES = ['evidence/deep-research-state.json', 'evidence/task-state.json',
         'reports/findings.json', 'reports/nuvi2565RT.html', 'evidence/report-web-latest.json']
FIELD = 'latest_android_hfp_prototype_checkpoint'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()


def replace(path, data):
    target = ROOT / path
    fd, temporary = tempfile.mkstemp(prefix=target.name + '.v4.', dir=target.parent)
    try:
        os.fchmod(fd, stat.S_IMODE(target.stat().st_mode))
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    build_path = 'staging/android-hfp-prototype-apk-v4/proof.json'
    proof_raw = (ROOT / build_path).read_bytes()
    require(sha(proof_raw) == 'aa652e42479dbc57083e761149a800cae103f8b77eab7ebfa6a24ceef2cf5a7f', 'Reviewed build proof')
    proof = json.loads(proof_raw)
    receipt = json.loads((ROOT / 'staging/android-hfp-prototype-apk-v4/actual-build-tool-receipt.json').read_text())
    require(receipt['exit_code'] == 0 and proof['all_build_checks_passed'] and proof['DEX_generated']
            and proof['APK_signature_verified_for_min_API28'] and proof['typechecked_against_real_official_Android_stub_jar']
            and proof['host_gate_cases']['host_cases'] == 18 and proof['host_load_lease_cases']['host_cases'] == 12
            and not proof['Android_runtime_or_phone_install_or_call_or_route_or_sound_verified'], 'Actual host build scope')
    for name, pin in proof['source_pins'].items():
        require(sha((ROOT / name).read_bytes()) == pin, 'Compiled source remains current: ' + name)
    route_path = 'evidence/android-sco-route-identity-review.json'
    route_raw = (ROOT / route_path).read_bytes()
    require(sha(route_raw) == '3d1239547d11927706e1ccc33e4b3161b8065d05ae5e244f09ce0c6b5f9fc7dc', 'Sealed limited route review')
    route = json.loads(route_raw)
    require(len(route['sources']) == 3 and not route['scope']['full_call_graph'], 'Bounded primary source scope')
    for source in route['sources']:
        raw = (ROOT / source['snapshot_path']).read_bytes()
        require(len(raw) == source['decoded_bytes'] and sha(raw) == source['decoded_snapshot_sha256'], 'Primary source snapshot')
    change_path = 'staging/android-hfp-provider-query-fix-v4/source-change-review.json'
    change_raw = (ROOT / change_path).read_bytes()
    require(sha(change_raw) == '15f35c00416dc989423d7f5e37245cdf47d39df5d2e392f0dffe750f6dff7044', 'Reviewed Android source changes')
    changes = json.loads(change_raw)
    for row in changes['changes']:
        require(sha((ROOT / row['path']).read_bytes()) == row['after_sha256'], 'Changed source remains current')
    before = {path: (ROOT / path).read_bytes() for path in FILES}
    state, task, public = [json.loads(before[path]) for path in FILES[:3]]
    web = json.loads(before[FILES[4]])
    require(state == public['deep_research'], 'Prior canonical equality')
    require(all(d['current_goal_priority'] == 'bluetooth_music' and d['goal_status'] == 'active'
                and not d['goal_complete'] for d in (state, task, public, web)), 'Music remains active')
    require(state['navigation_repair']['status'] == 'stopped_by_user' and task['user_away']
            and not state['audio']['audible_tests_allowed'] and not web['current_physical_test_requested'], 'No physical or navigation work')
    old_android = copy.deepcopy(state[FIELD])
    old_native = copy.deepcopy(state['native_app_music'])
    old_audio = copy.deepcopy(state['audio'])
    old_nav = copy.deepcopy(state['navigation_repair'])
    old_progress = copy.deepcopy(public['research_progress'])
    apk = (ROOT / proof['apk']['path']).read_bytes()
    require(len(apk) == proof['apk']['bytes'] and sha(apk) == proof['apk']['sha256'], 'Actual signed APK')
    require(sha((ROOT / 'reports/garmin-hfp-prototype.apk').read_bytes()) == old_android['artifact']['sha256'], 'Previous downloaded APK')
    pid = int(web['service']['MainPID'])
    process = Path('/proc') / str(pid)
    require(b'garmin-report-web/server.py' in (process / 'cmdline').read_bytes(), 'Live report service PID')
    start_ticks = (process / 'stat').read_bytes().split()[21]
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(web['url'], timeout=10) as response:
        require(response.status == 200 and response.read() == before[FILES[3]], 'Prior served report')
    now = datetime.now(timezone.utc)
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    stamp, display = local.isoformat(timespec='seconds'), local.strftime('%Y/%m/%d %H:%M:%S')
    url = web['url'].rstrip('/') + '/garmin-hfp-prototype.apk'
    checkpoint = copy.deepcopy(old_android)
    checkpoint.update(updated_utc=now.isoformat(), artifact=proof['apk'], download_url=url,
        build_proof={'path': build_path, 'sha256': sha(proof_raw)}, versionCode=4,
        versionName='0.4-background-document-check',
        document_provider_query_open_and_setDataSource_on_worker_in_source=True,
        entire_UI_thread_nonblocking_guarantee=False,
        ordinary_system_Binder_calls_remain_on_main=True,
        canceled_metadata_result_checked_before_file_open_in_source=True,
        cursor_cleanup_failure_keeps_process_busy_in_source=True,
        SCO_diagnostics_only_record_aggregate_counts=True,
        actual_Android_provider_or_UI_responsiveness_verified=False,
        route_identity_review={'path': route_path, 'sha256': sha(route_raw), 'full_call_graph_verified': False},
        source_change_review={'path': change_path, 'sha256': sha(change_raw)})
    checkpoint.pop('local_document_provider_and_setDataSource_can_block_main_thread', None)
    correction = {'scope': 'v2/v3 moved player file open and MediaPlayer work off main, but document-picker COLUMN_FLAGS query remained on main',
                  'fixed_in': 'v4 source', 'prior_v3_tests_did_not_cover_Android_provider_or_UI_callbacks': True}
    checkpoint['prior_query_scope_correction'] = correction
    next_actions = [
        '原機A2DP／菜單App目標維持：前端與來源管理尚未整合，本地解除綁定不等於端點撤銷或可卸載；常駐所有權、回呼排空與停止重啟仍未完成。',
        'Android第四版實驗APK已編譯／簽章核對，文件query也移到既有單一背景工作並保留取消檢查；SCO新增不含位址的計數診斷。等使用者通知可操作時先維持連線，依序驗來電、接聽、指定路由及十秒音檔，不自動發來電。',
        '導航／麥克風停止，Android Auto／Google Maps延後；目前不要求接線或配對。手機直接出聲、省去Pi、原機A2DP和喇叭驗收仍未完成。',
    ]
    turn = {'classification': 'progress', 'work': 'Android provider-query source fix, compiled v4 APK and nonidentifying route diagnostics',
        'previous_goal_turn_assessment': 'progress', 'previous_goal_turn_reason': 'Source-contract evidence changed endpoint retirement and module-lifetime next action',
        'validated_utc': now.isoformat(), 'goal_status': 'active', 'full_goal_complete': False,
        'required_work_remaining': True, 'device_files_written': False, 'native_runtime_progress': False,
        'reason': 'Actual Android source edits and new compile/DEX/sign/control output; no phone, Garmin native, speaker or runtime responsiveness success claimed.'}
    state.update(updated_utc=now.isoformat(), next_actions=copy.deepcopy(next_actions), last_goal_turn=copy.deepcopy(turn))
    state[FIELD] = copy.deepcopy(checkpoint)
    history = state.setdefault('android_hfp_prototype_checkpoints', {})
    require('v4' not in history, 'Do not republish v4 history')
    history['v3'], history['v4'] = old_android, copy.deepcopy(checkpoint)
    state['android_v3_provider_query_scope_correction'] = correction
    state['native_app_music'][FIELD] = copy.deepcopy(checkpoint)
    state['native_app_music']['remaining_work'] = [text.replace('第三版APK', '第四版APK')
        .replace('Android第三版實驗APK', 'Android第四版實驗APK')
        .replace('第三版Android實驗APK', '第四版Android實驗APK') for text in state['native_app_music']['remaining_work']]
    work = state['offline_24h_work_order']
    work[FIELD] = copy.deepcopy(checkpoint)
    work['current_offline_line_status']['android_direct_HFP'] = 'Signed v4 APK: document metadata query on existing player worker; privacy-preserving SCO counts; exact route and speaker on phone/Garmin unverified'
    for key in ('updated_utc', 'next_actions', 'offline_24h_work_order', FIELD, 'last_goal_turn', 'android_hfp_prototype_checkpoints', 'android_v3_provider_query_scope_correction'):
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state), offline_24h_work_order=copy.deepcopy(work), last_goal_turn=copy.deepcopy(turn))
    public[FIELD] = copy.deepcopy(checkpoint)
    public['research_progress'].update(research_updated_utc=now.isoformat(), next=next_actions[0])
    card = ('<section class="card" id="bluetooth-music-current-checkpoint-v1"><h2>藍牙音樂：Android第四版—文件查詢移到背景</h2>'
        f'<p>更新：<time datetime="{stamp}">{display}</time>（台灣時間）</p>'
        '<p>手機端本機音檔試驗APK已重新編譯並簽章。它使用HFP通話音訊；原機A2DP及GarminOS菜單App仍未完成。</p>'
        f'<p><a href="/garmin-hfp-prototype.apk" download="garmin-hfp-prototype.apk">下載 Android第四版實驗 APK</a>（{len(apk):,} bytes，versionCode 4，Android 9／API28以上）</p><ul>'
        '<li><strong>修正：</strong>第二／三版把音檔開啟與播放器移到背景，但選檔返回時仍在畫面執行緒查COLUMN_FLAGS，可能卡住介面。第四版將文件辨識、query、cursor存取／close搬到既有單一player job；<a href="https://developer.android.com/guide/components/processes-and-threads">Android執行緒指引</a>說明長查詢會阻塞UI。晚到或已取消的結果在開檔前再次檢查。</li>'
        '<li><strong>已核對：</strong>十份Java檔以官方API35 stub編譯，DEX／manifest／API28簽章核對通過；既有18項gate與12項lease主機控制再次通過。這些案例未執行Android provider，不證明Pixel介面反應或Garmin出聲。</li>'
        '<li><strong>路由診斷：</strong>只記SCO輸出數、空位址數與選定裝置匹配數。<a href="https://developer.android.com/reference/android/media/AudioDeviceInfo#getAddress()">getAddress官方契約</a>沒有全平台SCO MAC保證；未知或不匹配仍拒絕播放，沒有降低辨識條件。固定Android15三份來源只是有限核對，未查完整匿名化／權限管線。</li>'
        '<li><strong>保留限制：</strong>最多一個未回收載入工作。query／cursor／descriptor／MediaPlayer阻塞可卡住該worker；Stop只先作廢ticket，不等待它。cursor等資源清理失敗後保留busy，不宣稱強制取消、立即回收或整個UI絕不阻塞。普通系統Binder呼叫仍在主執行緒。</li>'
        '<li><strong>之後實測：</strong>選本機音檔及已配對Garmin → 建立本機來電 → 接聽 → 指定端點確認 → 明確按播放，包含靜音驗證最多10秒。本次没有安裝App、配對、發來電或播音；通話音質限制仍在。</li></ul>'
        '<p>原機前端／來源管理、發布後停止／重啟與元件常駐仍有缺口；沒有原機可安裝音樂包。原生App工程估計維持40%，不把Android平行路徑算成原機完成。</p></section>')
    report, count = re.subn(r'<section class="card" id="bluetooth-music-current-checkpoint-v1">.*?</section>', lambda _: card, before[FILES[3]].decode(), count=1, flags=re.S)
    require(count == 1, 'Current Android card')
    report, count = re.subn(r'<p id="offline-frontier-latest-v1">.*?</p>', lambda _: '<p id="offline-frontier-latest-v1">最新：Android第四版已移除選檔時的UI provider查詢，30項既有主機控制及編譯／簽章通過；新增SCO計數診斷。手機／Garmin出聲未測，原機A2DP與菜單App未完成。</p>', report, count=1, flags=re.S)
    require(count == 1, 'Current frontier')
    report, count = re.subn(r'<p><strong>下一步：</strong>保留原機A2DP／菜單App研究，Android第三版本機來電APK待使用者通知.*?</p>', lambda _: '<p><strong>下一步：</strong>原機繼續追來源管理與元件常駐缺口；Android第四版待使用者通知可操作時先維持藍牙連線，再依序測來電、接聽、指定SCO與十秒音檔。現在不需接線或配對。</p>', report, count=1, flags=re.S)
    require(count == 1, 'Current next action')
    for element in ('report-updated-time', 'research-updated-time'):
        report, count = re.subn(r'<time id="' + element + r'" datetime="[^"]+">[^<]+</time>', lambda _: f'<time id="{element}" datetime="{stamp}">{display}</time>', report, count=1)
        require(count == 1, 'Timestamp')
    expected_native = copy.deepcopy(old_native)
    expected_native[FIELD] = copy.deepcopy(checkpoint)
    expected_native['remaining_work'] = copy.deepcopy(state['native_app_music']['remaining_work'])
    require(state['native_app_music'] == expected_native and state['audio'] == old_audio and state['navigation_repair'] == old_nav, 'Native and audio history preserved')
    for key in ('estimate_percent', 'weighted_estimate_percent', 'phases'):
        require(public['research_progress'][key] == old_progress[key], 'No native progress inflation')
    out = ROOT / 'staging' / ('android-hfp-prototype-v4-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(mode=0o700)
    (out / 'canonical-before.json.gz').write_bytes(gzip.compress(encoded({name: data.decode() for name, data in before.items()}), mtime=0))
    replace('reports/garmin-hfp-prototype.apk', apk)
    for name, value in zip(FILES[:4], (state, task, public, report)):
        replace(name, value.encode() if isinstance(value, str) else encoded(value))
    with opener.open(url, timeout=10) as response:
        require(response.status == 200 and response.read() == apk
                and response.headers['Content-Type'] == 'application/vnd.android.package-archive'
                and 'attachment;' in response.headers['Content-Disposition'], 'Actual new APK HTTP bytes and headers')
    with opener.open(web['url'], timeout=10) as response:
        served = response.read()
        require(response.status == 200 and served == report.encode(), 'Actual report HTTP readback')
    require(process.exists() and (process / 'stat').read_bytes().split()[21] == start_ticks, 'Report server not restarted')
    web.update(updated_utc=now.isoformat(), HTTP_status=200, local_report_sha256=sha(served), served_report_sha256=sha(served),
               report_bytes=len(served), service_not_restarted=True, offline_24h_work_order=copy.deepcopy(work), last_goal_turn=copy.deepcopy(turn))
    web[FIELD] = copy.deepcopy(checkpoint)
    web['progress_display_verified'].update(report_updated_time=stamp, research_updated_time=stamp, Android_v4_query_scope_correction_visible=True)
    replace(FILES[4], encoded(web))
    fresh = [json.loads((ROOT / name).read_bytes()) for name in (FILES[0], FILES[1], FILES[2], FILES[4])]
    require(fresh[0] == fresh[2]['deep_research'] and all(d[FIELD] == checkpoint and not d['goal_complete'] for d in fresh), 'Canonical readback')
    (out / 'fresh-readback.json').write_bytes(encoded({'all_passed': True, 'updated_at_Taiwan': stamp, 'APK_HTTP_verified': True,
        'APK_sha256': sha(apk), 'report_url': web['url'], 'report_PID': pid, 'service_not_restarted': True,
        'source_change_review_sha256': sha(change_raw), 'route_identity_review_sha256': sha(route_raw),
        'Android_or_Garmin_runtime_verified': False, 'device_IO': False, 'full_goal_complete': False}))
    print(json.dumps({'all_publication_checks_passed': True, 'snapshot': str(out.relative_to(ROOT)),
        'updated_at_Taiwan': stamp, 'download_url': url, 'APK_bytes': len(apk), 'runtime_audio_verified': False,
        'device_IO': False, 'full_goal_complete': False}, ensure_ascii=False))


if __name__ == '__main__':
    main()
