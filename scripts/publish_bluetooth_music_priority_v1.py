#!/usr/bin/env python3
"""Apply the user's music-only priority change to the existing LAN report."""
import copy
import gzip
import html
import json
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, replace, service, sha

FILES = ['evidence/deep-research-state.json', 'evidence/task-state.json',
         'reports/findings.json', 'reports/nuvi2565RT.html', 'evidence/report-web-latest.json']
INSTRUCTION = '算了導航不需要修復了，請你協助幫忙直接研究藍牙音樂的部分'
PRIORITIES = [
    '現場藍牙配對與維持連線：使用者主動開始實測時立即優先。',
    '藍牙音樂：核對既有 Pixel → Pi → Garmin 路徑的音質、音量與持續播放限制。',
    'Garmin 原機直接接收手機音樂與播放器 App：先整理唯讀證據及未完成環節。',
    'Android Auto 與原機離線 Google Maps 延後；導航修復依使用者指示停止。',
]
NEXT = [
    '用離線 PCM／FFmpeg 測量窄頻重取樣與立體聲混合，維持固定音量，準備可獨立使用的轉換檢查。',
    '核對已保存的 HFP 協商及音量事件，區分已證明的通話音質上限與尚未證實的音量起伏原因。',
    '唯讀整理直接 A2DP、媒體生命週期、原生音訊來源與 App 選單的證據缺口；不執行受中斷的原生 guest。',
    '使用者返回會主動通知；目前不詢問在場、不發模擬來電、不播放音訊、不要求 USB 或配對。',
]


def require(value, message):
    if not value:
        raise ValueError(message)


def main():
    before = {p: (ROOT / p).read_bytes() for p in FILES}
    state, task, public = [json.loads(before[p]) for p in FILES[:3]]
    web = json.loads(before[FILES[4]])
    require(state == public['deep_research'], 'Current canonical state matches report')
    require(state['navigation_repair'] == task['navigation_repair'] == public['navigation_repair'],
            'Current navigation snapshots match')
    require(all(d['goal_status'] == 'active' and not d['goal_complete'] for d in [state, task, public, web]),
            'Research remains active and incomplete')
    require(task['user_away'] and not state['attended_testing']['user_present']
            and not state['audio']['audible_tests_allowed'] and not web['current_physical_test_requested'],
            'Away, silent scope')
    live = service()
    require(http(web['url'])[0] == before[FILES[3]], 'Previous HTTP exactly matches report')
    old_audio = copy.deepcopy(state['audio'])
    old_device = copy.deepcopy(state['navigation_repair']['latest_country_v2_comparison_checkpoint'])
    now = datetime.now(timezone.utc)
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    decision = {
        'updated_utc': now.isoformat(), 'user_instruction': INSTRUCTION,
        'navigation_work_status': 'stopped_by_user',
        'navigation_goal_claimed_achieved': False,
        'old_goal_text_map_priority_overridden_by_latest_user_instruction': True,
        'current_research_priority': 'bluetooth_music',
        'device_IO': False, 'device_audio_played': False,
        'current_device_map_configuration_changed': False,
        'historical_audio_success_seconds': 60,
        'long_duration_device_playback_verified': False,
        'native_direct_A2DP_or_App_verified': False,
        'native_interrupted_guest_retried': False,
        'full_goal_complete': False,
        'parallel_lines': {
            'continuous_music_binding': 'native_music_readonly_feature_acceptance_review',
            'native_address_candidate_check': 'captured_HFP_protocol_and_quality_audit',
            'taiwan_address_ingestion_plan': 'host_only_FFmpeg_conversion_and_offline_CLI',
        },
        'local_navigation_test_packet': {
            'status': 'stopped_incomplete', 'new_archive_created': False,
            'new_public_download_published': False, 'installed': False,
            'working_v2_half_load_only_verified': True,
            'coherent8K_half_load_only_executed': False,
        },
    }
    state.update(updated_utc=now.isoformat(), current_goal_priority='bluetooth_music',
                 current_priority='導航修復停止；優先研究藍牙音樂及 Garmin 原機播放器。',
                 latest_user_instruction=INSTRUCTION, ordered_priorities=copy.deepcopy(PRIORITIES),
                 next_actions=copy.deepcopy(NEXT), research_goal_status='active_offline_bluetooth_music',
                 native_app_research_status='active_readonly_feasibility_review',
                 music_priority_decision=copy.deepcopy(decision))
    state['native_app_music']['research_priority'] = (
        'Active first priority: Bluetooth music and native player; interrupted native guest branch remains file review only.')
    state['native_app_music']['latest_music_priority_decision'] = copy.deepcopy(decision)
    nav = state['navigation_repair']
    nav.update(updated_utc=now.isoformat(), status='stopped_by_user',
               navigation_repair_status='stopped_by_user', execution_status='stopped_by_user',
               current_goal_priority='bluetooth_music', research_goal_status='active_offline_bluetooth_music',
               native_app_research_status='active_readonly_feasibility_review',
               latest_user_stop=copy.deepcopy(decision),
               next='使用者取消導航修復；保留目前已驗證地圖與研究檔案，沒有繼續安裝、打包或實機要求。',
               remaining_next_actions=[])
    nav['native_country_address_update_progress'].update(
        status='stopped_by_user', estimate_is_last_historical_planning_value=True,
        next='導航工作已停止；75%為停止前的工程估計，不是完成或地址覆蓋率。')
    work = state['offline_24h_work_order']
    work.update(current_priority='bluetooth_music', priorities=copy.deepcopy(NEXT[:3]),
                latest_user_priority_decision=copy.deepcopy(decision),
                native_device_audio_tests_allowed=False, user_away=True,
                later_work=['Android Auto', 'Native offline Google Maps'])
    work['current_offline_line_status'].update(
        navigation='stopped_by_user; existing device maps and partial local packets retained',
        pi_music='host-only conversion measurement and offline preparation in progress',
        hfp_music='captured protocol and volume evidence review in progress',
        native_audio='file-only feature acceptance review; interrupted guest is not retried',
        user_presence_question_pending=False, device_audio_allowed=False)
    turn = {'classification': 'user_priority_override', 'validated_utc': now.isoformat(),
            'goal_status': 'active', 'full_goal_complete': False, 'required_work_remaining': True,
            'device_files_written': False, 'reason': INSTRUCTION}
    state['last_goal_turn'] = copy.deepcopy(turn)
    for key in ['updated_utc', 'current_priority', 'current_goal_priority', 'latest_user_instruction',
                'ordered_priorities', 'next_actions', 'research_goal_status', 'native_app_research_status',
                'music_priority_decision', 'navigation_repair', 'native_app_music',
                'offline_24h_work_order', 'last_goal_turn']:
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state),
                  navigation_repair=copy.deepcopy(nav), offline_24h_work_order=copy.deepcopy(work),
                  music_priority_decision=copy.deepcopy(decision), last_goal_turn=copy.deepcopy(turn),
                  current_goal_priority=state['current_goal_priority'],
                  research_goal_status=state['research_goal_status'],
                  native_app_research_status=state['native_app_research_status'],
                  native_country_address_update_progress=copy.deepcopy(nav['native_country_address_update_progress']))
    progress = public['research_progress']
    progress.update(research_updated_utc=now.isoformat(), ordered_priorities=copy.deepcopy(PRIORITIES),
                    next=NEXT[0], original_research_status='active', current_goal_priority='bluetooth_music',
                    estimate_retained_from_previous_research_scope=True,
                    method='沿用原完整研究計畫的歷史里程碑估計；本次改優先順序不提高百分比，導航修復已停止。')
    for phase in progress.get('phases', []):
        if '音樂' in phase.get('name', '') or 'App' in phase.get('name', ''):
            phase['next'] = NEXT[2]
    report = before[FILES[3]].decode()
    paragraph = ('<p id="offline-frontier-latest-v1">最新指示：導航修復已停止，現在優先研究藍牙音樂。'
                 '既有 Pixel → Pi → Garmin 路徑曾實測持續播放60秒，但使用8 kHz單聲道通話音訊；'
                 '音量起伏原因仍未確認。三條離線工作正在檢查轉換流程、HFP協商與原機播放器缺口。'
                 '手機直接連Garmin播放音樂、自製App及長時間穩定度尚未達成。</p>')
    report, n = re.subn(r'<p id="offline-frontier-latest-v1">.*?</p>', lambda _: paragraph,
                        report, count=1, flags=re.S)
    require(n == 1, 'One current report frontier')
    report, n = re.subn(r'<ol class="research-priorities">.*?</ol>',
                        lambda _: '<ol class="research-priorities">'
                        + ''.join('<li>' + html.escape(p) + '</li>' for p in PRIORITIES) + '</ol>',
                        report, count=1, flags=re.S)
    require(n == 1, 'One visible priority list')
    outdoor = ('<h2>外出期間：藍牙音樂離線研究</h2>'
               '<p>使用者返回會主動通知；目前不要求接車機或配對。</p><ol>'
               + ''.join('<li>' + html.escape(p) + '</li>' for p in NEXT[:3])
               + '</ol><p>導航研究已停止，現有地圖與部分測試包保留。離線結果不代表實機喇叭、'
               '原機App或手機直接藍牙連線已成功。</p></section>')
    report, n = re.subn(r'<h2>外出期間：離線研究與本機驗證</h2>.*?</section>',
                        lambda _: outdoor, report, count=1, flags=re.S)
    require(n == 1, 'One outdoor research scope')
    report = report.replace('<h2>v2道路與民權路回歸通過；擴大更新仍進行中</h2>',
                            '<h2>導航研究紀錄：依使用者指示停止</h2>'
                            '<p>以下為停止前的研究結果；目前沒有繼續導航修復或更新包工作。</p>', 1)
    report = report.replace('<p>全台更新工程估計 <strong>75%</strong>。這是工作進度估計，不是地址覆蓋率。</p>',
                            '<p>停止前的全台更新工程估計 <strong>75%</strong>；非完成或地址覆蓋率。</p>', 1)
    for ident in ['navigation-address-updated-time', 'report-updated-time', 'research-updated-time']:
        report, n = re.subn(r'<time id="' + ident + r'" datetime="[^"]+">[^<]+</time>',
                            lambda _: f'<time id="{ident}" datetime="{local.isoformat(timespec="seconds")}">'
                            f'{local.strftime("%Y/%m/%d %H:%M:%S")}</time>', report, count=1)
        require(n == 1, 'One timestamp ' + ident)
    require(old_audio == state['audio'] and old_device == nav['latest_country_v2_comparison_checkpoint'],
            'Historical audible evidence and installed-device map evidence unchanged')
    out = ROOT / 'staging' / ('bluetooth-music-priority-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(mode=0o700)
    for path, data in before.items():
        with (out / (path.replace('/', '__') + '.gz')).open('xb') as stream:
            stream.write(gzip.compress(data, mtime=0)); stream.flush(); os.fsync(stream.fileno())
    for path, value in zip(FILES[:4], [state, task, public, report]):
        replace(path, value)
    served, response = http(web['url'])
    require(served == report.encode() and live == service(), 'Exact current HTTP, original live service')
    web.update(updated_utc=now.isoformat(), HTTP_status=response['status'], local_report_sha256=sha(served),
               served_report_sha256=sha(served), report_bytes=len(served), service_not_restarted=True,
               current_goal_priority='bluetooth_music', navigation_execution_status='stopped_by_user',
               native_app_research_status=state['native_app_research_status'],
               music_priority_decision=copy.deepcopy(decision), offline_24h_work_order=copy.deepcopy(work),
               last_goal_turn=copy.deepcopy(turn))
    web['progress_display_verified'].update(report_updated_time=local.isoformat(timespec='seconds'),
                                          research_updated_time=local.isoformat(timespec='seconds'),
                                          navigation_progress_is_stopped_historical_value=True)
    replace(FILES[4], web)
    fresh = [json.loads((ROOT / p).read_bytes()) for p in [FILES[0], FILES[1], FILES[2], FILES[4]]]
    require(fresh[0] == fresh[2]['deep_research'] and fresh[0]['navigation_repair']
            == fresh[1]['navigation_repair'] == fresh[2]['navigation_repair'], 'Fresh canonical equality')
    require(all(d['current_goal_priority'] == 'bluetooth_music' and d['goal_status'] == 'active'
                and not d['goal_complete'] for d in fresh), 'Music priority and incomplete active goal')
    create(out / 'fresh-readback.json', {
        'all_passed': True, 'decision': decision, 'service': live,
        'report_sha256': sha(served), 'report_url': web['url'],
        'updated_at_Taiwan': local.isoformat(timespec='seconds'),
        'canonical_sha256': {p: sha((ROOT / p).read_bytes()) for p in FILES},
        'historical_native_App_estimate': 40, 'historical_overall_estimate': 37,
        'device_IO': False, 'goal_status': 'active', 'goal_complete': False,
    })
    print(json.dumps({'all_passed': True, 'checkpoint': str(out.relative_to(ROOT)),
                      'report_url': web['url'], 'updated_at_Taiwan': local.isoformat(timespec='seconds'),
                      'current_goal_priority': 'bluetooth_music', 'device_IO': False}, ensure_ascii=False))


if __name__ == '__main__':
    main()
