"""Latest full offline map/fallback/inverse checkpoint, preserving real limits."""
import copy
import gzip
import json
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, read, replace, service, sha

FILES=['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json','reports/nuvi2565RT.html','evidence/report-web-latest.json']
PINS={
 'staging/navigation-new-street-v2-4k-offline-prototype-v2/proof.json':'a03ba7d4a5a01138c5109610224be3aeec07f767632cf0aec70b3d793573b576',
 'staging/navigation-new-street-v2-exact-inverse-v1/proof.json':'3c63dbdd985c27202a8410142bc9ea26f80ca82e23d1811d38be61523bf2834f',
 'staging/navigation-native-jai-frontend-abi-v1/final-proof.json':'b7fb31e06db567244859f379bf7a67acbd2d7d29ef515bf8ddb48244181efdf7',
 'staging/navigation-native-ap-sector-reader-matrix-v1/proof.json':'a40e9e41f4246551955e875fd963a8c17e139c7c3726ee702a70962bf231fcf8',
 'staging/native-os20-source-media-v1/contract-v1.json':'b853750f9560713720bdfe6b473a954c1d3d6aee347f2b7617543f8d1c4dcc2a',
}


def main():
 values=[]
 for name,expected in PINS.items():
  raw=(ROOT/name).read_bytes();assert len(raw)<20000 and sha(raw)==expected;values.append(json.loads(raw))
 full,inverse,front,reader,source=values
 assert full['all_assigned_checks_passed'] and inverse['all_assigned_checks_passed'] and front['all_assigned_checks_passed']
 assert not full['installable'] and inverse['reconstructed_v2_sha256']=='925a515b668f3878ef0acea3e1c79188c15216f1af7f039c0e426942907ebefb'
 assert front['actual_full_prototype_SQL_and_native_first_scalar_new48312_verified'] and front['full_UI_not_verified']
 assert reader['all_assigned_checks_passed'] and not reader['AP_physical_renderer_failure_reproduced']
 assert source['copied_packet_Source_FIFO_subscope_passed'] and source['actual_guest_EXIT']==1
 assert not source['original_Source_to_mixer_integration_passed'] and not source['speaker_acceptance']
 now=datetime.now(timezone.utc);local=now.astimezone(ZoneInfo('Asia/Taipei'))
 before={n:(ROOT/n).read_bytes()for n in FILES}
 state,task,public=[json.loads(before[n])for n in FILES[:3]];web=json.loads(before[FILES[4]])
 assert state==public['deep_research'] and state['navigation_repair']==task['navigation_repair']==public['navigation_repair']
 assert state['goal_status']=='active' and not state['attended_testing']['user_present'] and state['attended_testing']['no_pending_question']
 assert not state['audio']['audible_tests_allowed']
 svc=service();served,_=http(web['url']);assert served==before[FILES[3]]
 nav=state['navigation_repair'];current_v2=copy.deepcopy(nav['latest_country_v2_comparison_checkpoint'])
 checkpoint=dict(updated_utc=now.isoformat(),prerequisite_pins=PINS,
  actual_full_original4K_new_street_IMG_created=True,output=full['output'],output_bytes=full['output_bytes'],output_sha256=full['output_sha256'],
  original4K_header_capacity_checksum_CHS_prefix_retained=True,full_source_and_output_components_verified=True,
  actual_inverse_v2_stream_bytes=inverse['reconstructed_v2_bytes'],actual_inverse_v2_sha256=inverse['reconstructed_v2_sha256'],second_full_backup_created=False,
  true_native_missing_prefix_status3_and_two_fallback_callers_executed=True,native_fallback_new_street_record48312_scalar_verified_with_SQL_fixture=True,
  native_SQL_engine_or_materializer_or_UI_verified=False,source_alias_official_street_verified=False,
  generic_filesystem_reader_15_windows_6_guards_passed=True,v3_display_failure_reproduced=False,original_AP_renderer_or_boarddriver_verified=False,
  device_IO=False,installable=False,current_device_v2_unchanged=True,full_Taiwan_update_complete=False,full_goal_complete=False)
 nav['new_street_full_original4K_offline_checkpoint_v1']=copy.deepcopy(checkpoint)
 phases=nav['native_country_address_update_progress']['phases']
 phases.append('一條新街完整離線原型：132,173,824-byte原4K封裝，六個元件完整讀回通過；可從實際新檔精確重建128,356,352-byte v2，完整SHA相同，沒有第二份完整備份。原機新街/UI尚未驗收。')
 phases.append('真正查詢fallback：原prefix缺項回status3，兩個caller改走FTS；12案/3,056指令中，完整離線DB的SQL fixture回敦富六街record48312，原caller讀取scalar，停在materializer前。')
 nav['native_country_address_update_progress']['updated_utc']=now.isoformat();nav['updated_utc']=now.isoformat()
 app=state['native_app_music']
 app['original_OS20_Source_copied_packet_partial_offline']=dict(contract=list(PINS)[4],proof_sha256=list(PINS.values())[4],
  actual_guest_terminal='8604d1 EXIT1; session5912',FILE_verification='bf88bd EXIT0',
  copied_packet_Source_FIFO_subscope_passed=True,actual_READY_reference_PCM_bytes=256,
  native_CURRENT_POST_WAIT=True,original_registration_and_queue_start_full_return=True,
  original_Source_to_mixer_passed=False,mixer_allocator_diagnostic_observed=True,physical_heap_availability='unknown',
  native_owner_certified=False,native_STOP_DONE=False,physical_install_App_phone_speaker_verified=False)
 app['remaining_work'][0]='True OS20 Source now receives one copied mono16k packet and publishes256 correct PCM bytes; original registration/queue-start returned. Mixer creation stops at flag2 software page allocator exhaustion. Next recover pool initialization/ownership without fake diagnostic success, then actual factory/reader/mixer integration.'
 work=state['offline_24h_work_order'];work['latest_completed_map_checkpoint']=copy.deepcopy(checkpoint)
 work['latest_audio_partial_checkpoint']=copy.deepcopy(app['original_OS20_Source_copied_packet_partial_offline'])
 state['updated_utc']=now.isoformat()
 for key in ['updated_utc','navigation_repair','native_app_music','offline_24h_work_order']:task[key]=copy.deepcopy(state[key])
 public.update(updated=now.isoformat(),deep_research=copy.deepcopy(state),navigation_repair=copy.deepcopy(nav),
  native_country_address_update_progress=copy.deepcopy(nav['native_country_address_update_progress']),offline_24h_work_order=copy.deepcopy(work))
 public['research_progress']['research_updated_utc']=now.isoformat()
 assert nav['latest_country_v2_comparison_checkpoint']==current_v2 and nav['native_country_address_update_progress']['estimate_percent']==75
 report=before[FILES[3]].decode()
 paragraph=('<div id="new-street-full-offline-result-v1"><h3>一條新街道：完整離線原型與還原已通過</h3><p>'
 '以實機正常的v2補入敦富六街368號，132 MB原4K圖資完整封裝與讀回校驗通過；從新檔反向重建v2的完整SHA一致，未另存完整備份。'
 '原程式的兩條前綴缺項fallback已執行，配合完整離線DB的SQL fixture取得新街道編號48312；目前停在畫面資料建立前，原SQLite引擎／UI與安裝接受仍待驗證。</p>'
 '<p>道路消失：三種封裝的原底層讀檔對照15個窗口與6項防護通過，尚未重現v3的顯示問題；繼續追真正Map載入與繪圖流程。</p>'
 '<p>音樂：真正Source工作程序已接收一包複製音訊並解出256 bytes正確PCM；原混音器建立遇到模擬頁配置器耗盡，正在追初始化與配置來源。原機可用heap未量測，App／直接藍牙／喇叭播放尚未完成。</p></div>')
 marker='<section class="card" id="offline-research-24h">'
 assert report.count(marker)==1 and 'id="new-street-full-offline-result-v1"'not in report
 report=report.replace(marker,marker+paragraph,1)
 report,count=re.subn(r'<h3>已完成</h3><ul>.*?</ul>',lambda _:'<h3>已完成</h3><ul>'+''.join('<li>'+p+'</li>'for p in phases)+'</ul>',report,count=1,flags=re.S);assert count==1
 for ident in ['navigation-address-updated-time','report-updated-time','research-updated-time']:
  report,count=re.subn(r'<time id="'+ident+r'" datetime="[^"]+">[^<]+</time>',
   lambda _:f'<time id="{ident}" datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>',report,count=1);assert count==1
 out=ROOT/'staging'/('new-street-full-offline-publication-'+now.strftime('%Y%m%dT%H%M%S%fZ'));out.mkdir()
 for name,data in before.items():
  with(out/(name.replace('/','__')+'.gz')).open('xb')as f:f.write(gzip.compress(data,mtime=0));f.flush();os.fsync(f.fileno())
 for name,value in zip(FILES[:4],[state,task,public,report]):replace(name,value)
 served,response=http(web['url']);assert served==report.encode()and service()==svc
 web.update(updated_utc=now.isoformat(),HTTP_status=response['status'],local_report_sha256=sha(served),served_report_sha256=sha(served),
  report_bytes=len(served),service_not_restarted=True,new_street_full_original4K_offline_checkpoint_v1=checkpoint,offline_24h_work_order=copy.deepcopy(work))
 replace(FILES[4],web)
 assert read(FILES[0])==read(FILES[2])['deep_research']
 assert read(FILES[0])['navigation_repair']==read(FILES[1])['navigation_repair']==read(FILES[2])['navigation_repair']
 assert read(FILES[0])['native_app_music']==read(FILES[1])['native_app_music']
 create(out/'fresh-readback.json',dict(all_passed=True,prerequisite_pins=PINS,service=svc,report_sha256=sha(served),
  native_country_engineering_estimate_percent=75,actual_goal_status='active',device_IO=False,full_goal_complete=False))
 print(json.dumps(dict(all_passed=True,checkpoint=str(out.relative_to(ROOT)),report_url=web['url'],device_IO=False)))


if __name__=='__main__':main()
