#!/usr/bin/env python3
"""Publish v2 evidence while retaining v1 history and pending physical checks."""
import copy,gzip,hashlib,html,json,os,re,subprocess,urllib.request
from datetime import datetime,timezone
from pathlib import Path
from zoneinfo import ZoneInfo
ROOT=Path(__file__).resolve().parents[1]
B=ROOT/'staging/navigation-repair-checkpoint-v2'
AUDIT=ROOT/'evidence/navigation-repair-checkpoint-v2.json'
STATE=ROOT/'evidence/navigation-repair-state-v2.json'
CAN=['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json','reports/nuvi2565RT.html']

def read(p):return json.loads(p.read_text())
def sha(b):return hashlib.sha256(b).hexdigest()
def encode(v):return v.encode() if isinstance(v,str) else (json.dumps(v,ensure_ascii=False,indent=2)+'\n').encode()
def create(p,v):
 with p.open('xb') as f:f.write(encode(v));f.flush();os.fsync(f.fileno())
def replace(p,v):
 t=p.with_name('.nav-v2-'+p.name)
 with t.open('xb') as f:f.write(encode(v));f.flush();os.fsync(f.fileno())
 os.replace(t,p)
def http(url):
 with urllib.request.urlopen(urllib.request.Request(url,headers={'Cache-Control':'no-cache'}),timeout=15) as r:
  assert r.status==200;return r.read(),dict(status=r.status,cache_control=r.headers.get('Cache-Control'))
def service(name):
 p=subprocess.run(['systemctl','show',name,'--property=MainPID,ActiveState,SubState,UnitFileState'],text=True,capture_output=True,check=True)
 d=dict(l.split('=',1) for l in p.stdout.splitlines() if '=' in l)
 assert d['ActiveState']=='active' and d['SubState']=='running' and d['UnitFileState']=='enabled'
 os.kill(int(d['MainPID']),0);return d

def main():
 assert not B.exists() and not AUDIT.exists() and not STATE.exists()
 package=read(ROOT/'staging/navigation-repair-v2/package-result.json');assert package['all_passed']
 build=read(ROOT/'staging/navigation-repair-v2/build-manifest.json');assert build['state']=='compiled_candidate_not_device_verified' and build['exit_code']==0
 old=read(ROOT/'evidence/navigation-repair-checkpoint-v1.json');assert old['all_passed']
 latest=read(ROOT/'evidence/report-web-latest.json')
 before={n:(ROOT/n).read_bytes() for n in CAN};state,task,public=[json.loads(before[n]) for n in CAN[:3]]
 assert public['deep_research']==state
 app_before=copy.deepcopy(state['native_app_music']['static_findings']);progress=public['research_progress']
 details_before=copy.deepcopy(progress['completed']);assert len(app_before)==318
 assert progress['estimate_percent']==progress['weighted_estimate_percent']==37 and progress['phases'][4]['estimate_percent']==40
 body,pre_http=http(latest['url']);assert body==before[CAN[3]]
 report_service=service('garmin-report-web.service');download_service=service('garmin-navigation-download.service')
 assert report_service['MainPID']=='357833'
 web_result=read(ROOT/'staging/navigation-repair-v2/download-web-verification.json');assert web_result['all_passed']
 package['download_url']=web_result['url']
 now=datetime.now(timezone.utc);local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds')
 next_text='核對USB實機、安裝第二版候選並讀回；新版OSM單独與原廠CN＋Address Point分別測地址→台中市→民權路、路段位置、耗時與GPS路由。導航實機確認後依原先指示繼續音樂／App研究。'
 details=[
 '原韌體有限指令探針確認：常用漢字及Extension A/B走原生implicit排序，補SRT中文頁本身不會改變該路徑。',
 '在v1實際MDR索引定位8組地名排序反例；修正主機產生的中文implicit字序及已驗範圍的非BMP處理。',
 '確認原韌體讀取16/10/6位元權重，原編譯工具寫16/8/8；已同時修正字元與expansion記錄封裝並加入溢位拒絕。',
 '48個字串三層權重、23組三種比較強度均吻合原韌體函式；18175既有BMP、2610expansion數值保留，非中文控制及maxPrimary不變。',
 '第二版36圖磚已重編；全部LBL/MDR/SRT身份、記錄封裝與索引指標核對通過，臺中市分組可達民權路與民和路對照。',
 '第二版實際NET/RGN/LBL核對道路名稱、臺中市歸屬及5個來源座標；包內地圖、安裝/還原和校驗資料完成ZIP讀回。',
 '原廠地址manager存在依可用圖資分流及JAI地圖ID核對；尚未證明車機UI選到新版OSM，也未證明兩小時搜尋的根因。',
 '鍵盤code_page950會被原程式解析；輸入字元到地圖查詢的轉碼流程仍未連接，沒有更改鍵盤檔。']
 nav=copy.deepcopy(read(ROOT/'evidence/navigation-repair-state-v1.json'))
 nav.update(updated_utc=now.isoformat(),navigation_repair_status='offline_v2_candidate_packaged_waiting_for_device',repair_estimate_percent=65,
  estimate_is_planning_not_verified_success=True,goal_status='active',goal_complete=False,
  required_work_remaining=True,candidate_version=2,package=package,download_url=package['download_url'],
  previous_candidate_status='superseded_after_native_sort_incompatibilities_identified',previous_candidate_state='evidence/navigation-repair-state-v1.json',
  previous_candidate_installable=False,GarminOS_recompiled=False,firmware_modified=False,
  completed_offline_details=details,device_installed=False,device_search_verified=False,device_routing_verified=False,
  physical_ab_test_success=False,stock_maps_modified=False,next=next_text,
  findings=dict(native_sort='Verified scoped host/native ordering alignment after Han and packed-weight corrections; actual device query still unverified.',
   layers='Original CN and Address Point are complementary versioned products; retained with original basemap/JCV/SID/SQLite/POI.',
   query='Actual map availability dispatch exists; checkbox source and OSM address caller remain unverified.',
   symptom='Only Taichung 民權路 is user-confirmed; 民和路 is a control. Two-hour search symptom cause not established.'),
  native_instruction_probe_is_physical_device_test=False,
  known_limits=['未安裝實機；中文輸入、地址/門牌查詢、耗時與路線結果仍待確認。',
   '原指令驗證使用合成記憶體與有限函式，不能等同車機UI或完整GarminOS模擬。',
   '已驗原生漢字範圍：3400–4DBF、4E00–9FBB、20000–2A6D6；其他nonBMP/emoji未宣稱支援。',
   '高雄/旗津原始界線缺兩段方式，未補造幾何；OSM地址完整性亦需實機核對。',
   '原廠CN＋Address Point維持互補；與OSM疊加是否影响搜尋須A/B，不先認定衝突。'],
  progress_components=[dict(name='離線修正、編圖與封装',weight=65,completed_points=65),dict(name='實機安裝與讀回',weight=10,completed_points=0),dict(name='地址與路線驗收',weight=25,completed_points=0)])
 sources={
  'build':'staging/navigation-repair-v2/build-manifest.json','build_script':'scripts/build_navigation_repair_v2.py',
  'build_receipt':'staging/navigation-repair-v2/build-terminal-receipt.json','package':'staging/navigation-repair-v2/package-result.json',
  'package_script':'scripts/package_navigation_repair_v2.py','sort':'staging/navigation-repair-v2/sort-verification.json',
  'sort_verifier':'staging/navigation-search-encoding-v2/verify_navigation_sort_v2.py',
  'MDR':'staging/navigation-mdr-query-v2/candidate-mdr-query-proof-v3.json',
  'roads':'staging/navigation-road-regression-v2/road-city-regression-proof-v2.json',
  'native_alignment':'staging/navigation-firmware-sort-v1/packed-shadow-alignment-proof-v2.json',
  'native_seal':'staging/navigation-firmware-sort-v1/sealed-manifest-v1.json',
  'independent_packing':'staging/navigation-native-srt-layout-v1/srt-layout-evidence.json',
  'address_dispatch':'staging/navigation-firmware-address-v1/address-dispatch-evidence.json',
  'keyboard':'staging/navigation-keyboard-query-v1/keyboard-metadata-dispatch-proof-v2.json',
  'download_readback':'staging/navigation-repair-v2/download-web-verification.json',
  'download_source':'scripts/serve_navigation_download_v2.py','download_unit':'staging/navigation-repair-v2/download-service.unit',
  'device_preflight':'evidence/navigation-bundle-20261005T231323766290+0800.json',
  'package_terminal':'staging/navigation-repair-v2/package-terminal-receipt.json',
  'download_deployment':'staging/navigation-repair-v2/download-deployment.json',
  'sort_terminal':'staging/navigation-search-encoding-v2/fullmap-verifier-terminal-receipt.json',
  'road_terminal':'staging/navigation-road-regression-v2/road-regression-terminal-receipt.json',
  'MDR_terminal':'staging/navigation-mdr-query-v2/candidate-mdr-query-v3-terminal-tool-receipt.json',
  'installer':'staging/navigation-map-layers-v2/install_navigation_bundle.py',
  'installer_adaptation':'staging/navigation-map-layers-v2/installer-test-results.json',
  'package_preparation':'staging/navigation-map-layers-v2/preparation-review-rev2.json',
  'package_preparation_seal':'staging/navigation-map-layers-v2/preparation-file-seal.json'}
 nav['sources'].update(sources)
 check_names=['package','sort','MDR','roads','native_alignment','independent_packing','keyboard','download_readback']
 for name in check_names:assert read(ROOT/sources[name])['all_passed'],sources[name]
 create(STATE,nav)
 state.update(updated_utc=now.isoformat(),goal_status='active',goal_complete=False,required_work_remaining=True,
  current_goal_priority='navigation_search_repair',research_goal_status='paused',native_app_research_status='deferred_until_navigation_verified',
  navigation_repair=nav,current_navigation_repair_checkpoint=str(AUDIT.relative_to(ROOT)),current_priority=next_text,next_actions=nav['remaining_physical_checks'])
 state['map_update']['repair_candidate']=dict(evidence=str(STATE.relative_to(ROOT)),package=sources['package'],candidate=True,version=2,installed=False,device_search_verified=False,device_routing_verified=False)
 state['last_goal_turn']=dict(classification='progress',validated_utc=now.isoformat(),goal_status='active',full_goal_complete=False,
  required_work_remaining=True,next_focus=next_text,reason='Identified original sorting/layout incompatibilities and rebuilt, validated and packaged v2 map candidate.',
  device_IO=False,guest_execution_scope='Finite original sorting/parser instructions only; no full OS guest or old App scopes',old_frozen_suites_rerun=False)
 for key in ['updated_utc','goal_status','goal_complete','required_work_remaining','current_goal_priority','research_goal_status','native_app_research_status','navigation_repair','current_navigation_repair_checkpoint','current_priority','next_actions','last_goal_turn']:task[key]=copy.deepcopy(state[key])
 task['research_completed']=False
 progress['completed'].extend(details);progress['phases'][0]['completed'].extend(details)
 progress.update(research_updated_utc=now.isoformat(),next=next_text,current_goal_priority='navigation_search_repair',original_research_status='paused')
 public.update(updated=now.isoformat(),deep_research=state,navigation_repair=nav,current_navigation_repair_checkpoint=str(AUDIT.relative_to(ROOT)),
  navigation_repair_progress=dict(estimate_percent=65,estimate_is_milestone_assessment=True,goal_complete=False,components=nav['progress_components']),
  goal_status='active',goal_complete=False,required_work_remaining=True,current_goal_priority='navigation_search_repair')
 assert state['native_app_music']['static_findings']==app_before and progress['completed'][:len(details_before)]==details_before
 e=html.escape
 card='<section class="card" id="navigation-repair-checkpoint-v2"><h2>導航修復第二版：待車機驗收</h2><p>工作里程碑估計 <strong>65%</strong>；尚未確認實機搜尋問題已解決。</p><progress id="navigation-repair-progress" max="100" value="65" style="width:100%;height:18px">65%</progress><p>離線修正與封裝65分；實機安裝10分、地址搜尋及GPS路由25分待完成。</p>'
 card+=f'<p>更新：<time datetime="{iso}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>（台灣時間）</p><p><a href="{e(package["download_url"])}" download>下載第二版完整候選包</a>（約{package["zip_bytes"]/1e6:.1f} MB）。第一版保留作研究歷史，已停止推薦安裝。</p>'
 card+='<h3>已處理的進度</h3><ul>'+''.join('<li>'+e(d)+'</li>' for d in details)+'</ul><h3>實機確認順序</h3><ol><li>USB隨身碟模式：核對身份、安裝新版並讀回，保留原廠資料。</li><li>一般模式：新版OSM單獨與原廠CN＋Address Point兩組重啟對照。</li><li>地址→台中市→民權路，記錄路名、位置、門牌與耗時；期望30秒內有結果，60秒仍未完成則記錄並取消。</li><li>民和路一/二段作對照，最後確認GPS定位後的路線計算及實際導引。</li></ol>'
 card+='<p>原廠道路主圖與Address Point是互補圖層；底圖DEM、JCV、SID、SQLite與POI保留。導航確認後依原先指示繼續音樂／App研究。</p><h3>限制</h3><ul>'+''.join('<li>'+e(d)+'</li>' for d in nav['known_limits'])+'</ul></section>'
 report=before[CAN[3]].decode()
 report,count=re.subn(r'<aside class="card" id="native-sort-compatibility-notice">.*?</aside>','',report,count=1,flags=re.S);assert count==1
 report,count=re.subn(r'<section class="card" id="navigation-repair-checkpoint-v1">.*?</section>',lambda _:card,report,count=1,flags=re.S);assert count==1
 for name in ['report-updated-time','research-updated-time']:
  report,count=re.subn(r'<time id="'+name+r'" datetime="[^"]+">[^<]+</time>',lambda _:f'<time id="{name}" datetime="{iso}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>',report,count=1);assert count==1
 report,count=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda _:'<p><strong>下一步：</strong>'+e(next_text)+'</p>',report,count=1,flags=re.S);assert count==1
 report,count=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda m:m[1]+m[2]+''.join('<li>'+e(d)+'</li>' for d in details)+m[3],report,count=1,flags=re.S);assert count==1
 assert 'id="research-progress" max="100" value="37"' in report
 assert not re.search(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b',report) and 'REDACTED_PRIVATE_ID' not in report
 B.mkdir();protected=dict(old['protected_sources']);focused={}
 def register(p):
  data=p.read_bytes();assert len(data)<=4*1024*1024
  name=str(p.relative_to(ROOT));d=sha(data);assert name not in protected or protected[name]==d,name
  protected[name]=focused[name]=d
 selected=[Path(__file__),STATE,ROOT/'evidence/navigation-repair-state-v1.json',ROOT/'staging/navigation-readiness-notice-v1/notice-readback.json']+[ROOT/n for n in sources.values()]
 for ledger_name in ['staging/navigation-firmware-sort-v1/sealed-manifest-v1.json','staging/navigation-mdr-query-v2/file-seal-v2.json']:
  ledger=ROOT/ledger_name
  if ledger.exists():selected.append(ledger)
 for p in selected:register(p)
 snapshots=[]
 assert all((ROOT/n).read_bytes()==d for n,d in before.items())
 for i,n in enumerate(CAN):
  p=B/('previous-'+str(i)+'.gz')
  with p.open('xb') as f:
   with gzip.GzipFile(filename='',mode='wb',fileobj=f,mtime=0) as z:z.write(before[n])
  assert gzip.decompress(p.read_bytes())==before[n];register(p)
  snapshots.append(dict(original=n,snapshot=str(p.relative_to(ROOT)),decoded_sha256=sha(before[n])))
 for n,v in zip(CAN,[state,task,public,report]):replace(ROOT/n,v)
 assert [read(ROOT/n) for n in CAN[:3]]==[state,task,public]
 served,post_http=http(latest['url']);assert served==report.encode()
 after={n:sha((ROOT/n).read_bytes()) for n in CAN}
 assert service('garmin-report-web.service')==report_service
 audit=dict(old,all_passed=True,updated_utc=now.isoformat(),previous_checkpoint='evidence/navigation-repair-checkpoint-v1.json',
  current_navigation_repair_checkpoint=str(AUDIT.relative_to(ROOT)),protected_sources=protected,current_focused_sources_sha256=focused,previous_canonical_snapshots=snapshots,canonical_after_sha256=after,
  current_state_sha256=after[CAN[0]],report_sha256=after[CAN[3]],local_report_sha256=after[CAN[3]],served_report_sha256=sha(served),
  canonical_readback_uncached=True,current_findings=318,current_public_details=len(progress['completed']),navigation_repair=nav,
  goal_status='active',full_goal_complete=False,required_work_remaining=True,physical_navigation_search_verified=False,physical_navigation_routing_verified=False,
  current_goal_priority='navigation_search_repair',research_goal_status='paused',native_app_research_status='deferred_until_navigation_verified',
  original_overall_percent=37,original_App_percent=40,navigation_repair_estimate_percent=65,
  device_IO_this_turn=False,old_registry_hashes_inherited_without_revalidation=True,full_backup_rehash_repeated=False,old_frozen_suites_rerun=False,
  report_service_not_restarted=True,download_service=download_service,
  ROOT_verified_navigation_large_files={package['map_path']:dict(bytes=package['map_bytes'],sha256=package['map_sha256']),package['zip']:dict(bytes=package['zip_bytes'],sha256=package['zip_sha256'])})
 create(AUDIT,audit)
 latest.update(updated_utc=now.isoformat(),current_navigation_repair_checkpoint=str(AUDIT.relative_to(ROOT)),
  local_report_sha256=after[CAN[3]],served_report_sha256=sha(served),report_bytes=len(served),navigation_download=web_result,
  navigation_v1_installation_held=True,navigation_v1_hold_reason='Superseded by corrected v2 candidate; physical verification pending',navigation_candidate_version=2,
  HTTP_status=post_http['status'],cache_control=post_http['cache_control'],served_latest_report=True,service=report_service,service_not_restarted=True)
 latest.setdefault('checkpoint_sha256',{})[str(AUDIT.relative_to(ROOT))]=sha(AUDIT.read_bytes())
 latest['progress_display_verified'].update(navigation_repair_estimate_percent=65,report_updated_time=iso,research_updated_time=iso,completed_items=len(progress['completed']))
 replace(ROOT/'evidence/report-web-latest.json',latest)
 create(B/'fresh-readback.json',dict(all_passed=True,checked_utc=datetime.now(timezone.utc).isoformat(),canonical_sha256=after,
  report_HTTP=post_http,served_report_sha256=sha(served),checkpoint_sha256=sha(AUDIT.read_bytes()),report_service=report_service,
  download_service=download_service,old_frozen_sources_freshly_rehashed=False,device_IO=False))
 print(json.dumps(dict(all_passed=True,checkpoint=str(AUDIT.relative_to(ROOT)),report_sha256=after[CAN[3]],public_details=len(progress['completed']),
  protected_sources=len(protected),navigation_estimate_percent=65,device_search_verified=False,goal_status='active')))
if __name__=='__main__':main()
