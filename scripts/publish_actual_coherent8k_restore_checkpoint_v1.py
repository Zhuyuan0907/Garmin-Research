"""Publish one actual disabled map and exact complete streamed restoration."""
import copy
import gzip
import json
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, replace, service, sha

FILES=['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json',
       'reports/nuvi2565RT.html','evidence/report-web-latest.json']
ACTUAL='staging/navigation-AP-coherent8k-actual-stock-verification-v2/'
PREFLIGHT='staging/navigation-AP-coherent-control-rollback-binding-preflight-v1/'
REVIEW='staging/navigation-AP-header-control-materializer-independent-review-v1/'
PINS={
    ACTUAL+'proof.json':'e44ded4324705fc9482b60898edda790e6155a646a5d9e5d7b4a139e5f41aa8e',
    ACTUAL+'sealed-files.json':'0c6589d72116afc30cb575cc99b6cd366cedde48ae2875f70cbc5bf447ad6410',
    'staging/navigation-AP-coherent8k-actual-materialization-rollback-v1/failure-closure.json':
        'f2a1fd1d787ebd723443074c650333864aacb72088e208b7f15ec4cb45d4746e',
    PREFLIGHT+'proof.json':'a6418ca226e22f4bcbfae273abec4daf8ab8725c3d83ce5dc8e09e5f9d155198',
    PREFLIGHT+'sealed-files.json':'b68b33e3e6d8af2126c1da1e2667a40ea73a081c3e906d5accd73fcc9f9abc30',
    REVIEW+'proof.json':'9fa96cf0f4596b90a1c25c753347261fe74390a8721684268db71c948236b5c3',
    REVIEW+'sealed-files.json':'f8c6dc5e29df1d3ece2722426e14d4c4a786086ce01199218753c4f26d3e7008',
}


def require(ok,message):
    if not ok:raise ValueError(message)


def main():
    docs={}
    for path,pin in PINS.items():
        raw=(ROOT/path).read_bytes()
        require(len(raw)<=32768 and sha(raw)==pin,'Pinned small prerequisite '+path)
        docs[path]=json.loads(raw)
    actual=docs[ACTUAL+'proof.json'];failure=docs[next(p for p in PINS if p.endswith('failure-closure.json'))]
    require(actual['all_assigned_checks_passed'] and actual['all_handles_closed'] and
            actual['candidate_full_sha256']=='9af1e68e1308bf28deeb7f7d4c7cfab88efd0063c38f4f2df77fcde352990dd3' and
            actual['computed_inverse_original_v3_sha256']=='1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360',
            'Actual coherent candidate and inverse full hashes')
    require(actual['exact_stock_bytes']==96739328 and actual['exact_stock_blocks']==23618 and
            actual['exact_stock_reconstruction_sha256']=='864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2',
            'Actual complete original stock reconstruction')
    require(actual['actual_candidate_read_bytes']==249424497 and not actual['whole_pipeline_one_attempt'] and
            failure['actual_terminal']=='ea061f EXIT1' and not actual['installable'],
            'Preserved host glue failure and explicit validation scope')
    before={p:(ROOT/p).read_bytes() for p in FILES}
    state,task,public=[json.loads(before[p]) for p in FILES[:3]]
    web=json.loads(before[FILES[4]])
    require(state==public['deep_research'] and
            state['navigation_repair']==task['navigation_repair']==public['navigation_repair'], 'Canonical equality')
    require(all(x['goal_status']=='active' and not x['goal_complete'] for x in [state,task,public,web]),'Active incomplete goal')
    require(not state['attended_testing']['user_present'] and state['attended_testing']['no_pending_question'] and
            not state['audio']['audible_tests_allowed'] and not web['current_physical_test_requested'], 'Silent away scope')
    svc=service();require(http(web['url'])[0]==before[FILES[3]],'Initial exact HTTP report')
    old_app=copy.deepcopy(state['native_app_music']);old_audio=copy.deepcopy(state['audio'])
    nav=state['navigation_repair'];old_device=copy.deepcopy(nav['latest_country_v2_comparison_checkpoint'])
    now=datetime.now(timezone.utc);local=now.astimezone(ZoneInfo('Asia/Taipei'))
    checkpoint=dict(updated_utc=now.isoformat(),prerequisite_pins=PINS,
        actual_materialization_initial_terminal='b7e3a6 session87026; ea061f EXIT1 after saved output verified',
        materialization_completed_before_first_stock_recorder_error=True,
        actual_complete_stock_verification_terminal='835864 EXIT0',actual_verification_session=47661,
        actual_candidate_path=actual['candidate_path'],actual_candidate_bytes=153346048,
        actual_candidate_sha256=actual['candidate_full_sha256'],actual_saved_output_readback_verified=True,
        fresh_second_candidate_full_SHA_verified=True,fresh_inverse_old_v3_SHA_verified=True,
        actual_complete_stock_reconstruction_bytes=96739328,actual_complete_stock_reconstruction_blocks=23618,
        actual_complete_stock_reconstruction_sha256=actual['exact_stock_reconstruction_sha256'],
        old_strict_helper_and_parser_guards_unchanged=True,actual_verification_candidate_read_bytes=249424497,
        actual_verification_read_cap=260000000,current_process_peak_KiB=actual['current_memory']['VmHWM'],
        new_full_candidate_IMG_files=1,second_full_backup_created=False,streamed_stock_IMG_saved=False,
        first_failed_host_recorder_attempt_preserved=True,cumulative_failed_read_counter_missing=True,
        cumulative_all_attempt_IMG_reads_conservative_upper_bound=816116593,whole_pipeline_one_attempt=False,
        all_source_handles_closed=True,all_188870_added_records_content_unchanged_inherited_from_body_identity=True,
        all_188870_added_records_UI_verified=False,installer_integration='active_host_preparation',
        expanded4K_restore_binding='active_separate_supported_profile_preparation',
        actual_restore_independent_review='active_small_data_source_review',
        device_IO=False,device_candidate_installed=False,installable=False,
        checksum_policy_verified=False,road_loss_rootcause_proven=False,Garmin_UI_renderer_verified=False,
        full_Taiwan_update_complete=False,native_App_complete=False,direct_phone_A2DP_complete=False,full_goal_complete=False)
    nav['actual_coherent8K_restore_checkpoint_v1']=copy.deepcopy(checkpoint)
    nav['next']=('把已完整讀回與原廠還原驗證的新8K對照檔接進嚴格測試安裝包；'
                 '另準備4K較大封裝的獨立實際FAT／還原綁定。原廠還原SHA通過不等於Garmin道路顯示恢復，'
                 '完整全台更新、新街道／子號與實機驗收仍未完成；目前車機v2＋Search v2保持。')
    phases=nav['native_country_address_update_progress']['phases']
    phases.extend([
        '已在Pi真正產生一個153346048-byte的新8K只改結尾欄位對照檔，完整存檔讀回SHA9af1…90dd3與先前虛擬預期一致；內容保留，沒有寫入Garmin。候選仍以.img.disabled保存，未提供安裝下載。',
        '第一次還原驗證停在root自製紀錄介面缺extend，原程式／失敗／工具紀錄保留；補正的獨立驗證使用同一個候選、不重跑產檔。實際完整candidate與inverse old-v3 SHA通過，再由未修改的原嚴格helper輸出23618個原廠block，96739328 bytes與原始stock完整SHA864d…053c2一致。原廠還原影像未另存，完整USB備份仍只有一份。',
        '本次驗證實際candidate讀249424497 bytes低於260M限制，current-mm峰32288KiB；所有source handles關閉。資料可完整還原已有實證，Garmin接受、道路顯示／搜尋、未知checksum政策與根因仍未證。繼續測試安裝工具整合與獨立4K封裝還原綁定，使用者在外不要求車機。',
    ])
    nav['updated_utc']=now.isoformat();nav['native_country_address_update_progress']['updated_utc']=now.isoformat()
    work=state['offline_24h_work_order'];work['latest_completed_actual_coherent8K_restore_checkpoint']=copy.deepcopy(checkpoint)
    work['current_offline_line_status']['navigation']=nav['next']
    turn=dict(classification='progress',validated_utc=now.isoformat(),goal_status='active',full_goal_complete=False,
        required_work_remaining=True,device_files_written=False,
        reason='One actual disabled map materialized and read back; complete fresh strict stock reconstruction verified after preserving host recorder failure.')
    state.update(updated_utc=now.isoformat(),last_goal_turn=copy.deepcopy(turn))
    for key in ['updated_utc','navigation_repair','offline_24h_work_order','last_goal_turn']:task[key]=copy.deepcopy(state[key])
    public.update(updated=now.isoformat(),deep_research=copy.deepcopy(state),navigation_repair=copy.deepcopy(nav),
        offline_24h_work_order=copy.deepcopy(work),last_goal_turn=copy.deepcopy(turn),
        native_country_address_update_progress=copy.deepcopy(nav['native_country_address_update_progress']))
    public['research_progress']['research_updated_utc']=now.isoformat()
    report=before[FILES[3]].decode()
    paragraph=('<p id="offline-frontier-latest-v1">最新：已真正產生一個保留全部新版門牌內容的8K封裝對照檔，完整存檔讀回核對通過。'
        '使用同一個新檔完整重建原廠Address Point，96739328 bytes與原備份完整雜湊一致，未另存還原影像。'
        '這證明本機還原路徑可用，尚未證明Garmin道路顯示恢復。接著整合測試安裝包，並準備另一個4K封裝的嚴格還原綁定。'
        '車機維持已實測正常的門牌v2＋Search v2；全台更新、原機App與手機直接藍牙音樂仍未完成。</p>')
    report,count=re.subn(r'<p id="offline-frontier-latest-v1">.*?</p>',lambda _:paragraph,report,count=1,flags=re.S)
    require(count==1,'One current frontier paragraph')
    report,count=re.subn(r'<h3>已完成</h3><ul>.*?</ul>',lambda _:'<h3>已完成</h3><ul>'+''.join('<li>'+x+'</li>' for x in phases)+'</ul>',report,count=1,flags=re.S)
    require(count==1,'One navigation phase detail list')
    for ident in ['navigation-address-updated-time','report-updated-time','research-updated-time']:
        report,count=re.subn(r'<time id="'+ident+r'" datetime="[^"]+">[^<]+</time>',
            lambda _:f'<time id="{ident}" datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>',report,count=1)
        require(count==1,'One current timestamp '+ident)
    require(nav['latest_country_v2_comparison_checkpoint']==old_device and state['native_app_music']==old_app and state['audio']==old_audio,
            'Device/App/audio evidence unchanged')
    require(nav['native_country_address_update_progress']['estimate_percent']==75,'Milestone estimate not full address coverage')
    out=ROOT/'staging'/('actual-coherent8K-restore-publication-'+now.strftime('%Y%m%dT%H%M%S%fZ'));out.mkdir(mode=0o700)
    for path,data in before.items():
        with (out/(path.replace('/','__')+'.gz')).open('xb') as f:f.write(gzip.compress(data,mtime=0));f.flush();os.fsync(f.fileno())
    for path,value in zip(FILES[:4],[state,task,public,report]):replace(path,value)
    served,response=http(web['url']);require(served==report.encode() and service()==svc,'Fresh exact HTTP and original live report service')
    web.update(updated_utc=now.isoformat(),HTTP_status=response['status'],local_report_sha256=sha(served),
        served_report_sha256=sha(served),report_bytes=len(served),service_not_restarted=True,
        actual_coherent8K_restore_checkpoint_v1=copy.deepcopy(checkpoint),
        offline_24h_work_order=copy.deepcopy(work),last_goal_turn=copy.deepcopy(turn))
    web['progress_display_verified'].update(report_updated_time=local.isoformat(timespec='seconds'),
        research_updated_time=local.isoformat(timespec='seconds'),navigation_repair_estimate_percent=75)
    replace(FILES[4],web)
    fresh=[json.loads((ROOT/p).read_bytes()) for p in [FILES[0],FILES[1],FILES[2],FILES[4]]]
    require(fresh[0]==fresh[2]['deep_research'] and fresh[0]['navigation_repair']==fresh[1]['navigation_repair']==fresh[2]['navigation_repair'],
            'Fresh canonical equality')
    require(all(x['goal_status']=='active' and not x['goal_complete'] for x in fresh) and
            fresh[1]['user_away'] and not fresh[3]['current_physical_test_requested'],'Active goal and away scope retained')
    create(out/'fresh-readback.json',dict(all_passed=True,prerequisite_pins=PINS,service=svc,report_sha256=sha(served),
        actual_stock_SHA=actual['exact_stock_reconstruction_sha256'],new_candidate_files=1,second_full_backup=False,
        navigation_estimate=75,native_App_estimate=40,overall_estimate=37,user_away=True,device_IO=False,goal_status='active',full_goal_complete=False))
    print(json.dumps(dict(all_passed=True,checkpoint=str(out.relative_to(ROOT)),report_url=web['url'],
        updated_at_Taiwan=local.isoformat(timespec='seconds'),actual_stock_SHA=actual['exact_stock_reconstruction_sha256'],device_IO=False)))


if __name__=='__main__':main()
