#!/usr/bin/env python3
"""Publish actual cleanup outcome; never rerun guests or delete another file."""
import json,hashlib,html,re,importlib.util,urllib.request
from pathlib import Path
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
ROOT=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('report_helper',ROOT/'scripts/publish_native_warm_probe_checkpoint_v1.py');P=importlib.util.module_from_spec(s);s.loader.exec_module(P)
read,sha,create,write=P.read,P.sha,P.create,P.write
G='staging/garminos-storage-cleanup-v1/';B='staging/garminos-storage-cleanup-checkpoint-v1/'
OLD='evidence/firmware-analysis/native-platform-readonly-probe-ROOT-checkpoint-audit.json';OUT='evidence/firmware-analysis/garminos-storage-cleanup-checkpoint-audit.json'
def main():
 assert not(ROOT/B).exists()and not(ROOT/OUT).exists()
 old=read(OLD);cleanup=read(G+'cleanup-result.json');receipt=read(G+'apply-terminal-tool-receipt.json')['actual_terminal_result'];post=read(G+'post-cleanup-live-verification.json')
 assert old['all_passed']and old['current_findings']==296 and old['current_public_details']==277 and len(old['protected_sources'])==4596
 assert cleanup['all_passed']and cleanup['protected4596_sources_rechecked']==4596 and cleanup['protected_source_content_preserved']and cleanup['duplicate_extracted_tree_removed']and cleanup['backup_image_unchanged']
 assert receipt['exit_code']==0 and 'session_id'not in receipt and post['all_passed']and post['original_backup_image_sha256']==cleanup['sole_backup_sha256']
 assert cleanup['freed_bytes']>1024**3 and not cleanup['device_IO']
 assert all(sha(p)==h for p,h in old['canonical_after_sha256'].items())
 protected=dict(old['protected_sources'])
 # The completed cleanup actor actually rehashed all4596 protected sources.
 # Reuse that explicit scope; do not claim a second full hash pass here.
 def register(p):
  h=sha(p);assert p not in protected or protected[p]==h,p;protected[p]=h
 for p in sorted((ROOT/G).rglob('*')):
  if p.is_file():register(str(p.relative_to(ROOT)))
 for p in (OLD,'scripts/plan_garmin_storage_cleanup_v1.py','scripts/apply_garmin_storage_cleanup_v1.py','scripts/publish_garmin_storage_cleanup_v1.py','scripts/stage_native_platform_probe_voice_v2.py','staging/native-platform-readonly-probe/ready-for-attended-test-v2.json','staging/native-platform-readonly-probe-checkpoint/publication-v1-terminal-tool-receipt.json'):register(p)
 state,task,public=[read(p)for p in P.CANONICAL[:3]];app=state['native_app_music'];progress=public['research_progress'];latest=read('evidence/report-web-latest.json');service=P.service_now()
 assert state['goal_status']=='active'and not state['goal_complete']and len(app['static_findings'])==296 and len(progress['completed'])==277
 with urllib.request.urlopen(urllib.request.Request(latest['url'],headers={'Cache-Control':'no-cache'}),timeout=10)as r:before=r.read();assert r.status==200 and 'no-store'in r.headers.get('Cache-Control','')
 assert hashlib.sha256(before).hexdigest()==sha(P.CANONICAL[3])
 (ROOT/B).mkdir();snapshots=[]
 for p,name in[(OLD,'previous-audit.json'),('evidence/report-web-latest.json','previous-web.json')]+list(zip(P.CANONICAL,['previous-state.json','previous-task.json','previous-public.json','previous-report.html'])):
  target=B+name
  with(ROOT/target).open('xb')as f:f.write((ROOT/p).read_bytes())
  register(target);snapshots.append(dict(original=p,snapshot=target,sha256=sha(target)))
 freed=cleanup['freed_bytes']/1024**3;available=post['free_bytes']/1024**3;previous=cleanup['before_free_bytes']/1024**3
 details=[f'依使用者要求清除GarminOS重複內容，实际釋放{freed:.2f}GiB，可用容量由{previous:.2f}GiB增至{available:.2f}GiB。已核對完整備份映像SHA及1402檔案，刪除約1.25GB解壓副本；原路徑現在唯讀掛載同一份sda.img，完整備份只保留這一份映像。',f"另外清除{cleanup['duplicate_copies_removed']}個相同內容副本，改為{cleanup['dedup_hardlinks']}個共享inode索引和{cleanup['readonly_image_symlinks']}個唯讀映像連結。內容不同的試驗成果與可編輯C程式保留。4596個舊保護來源重新核對保持相同；VS Code207檔核對及27.4MiB下載包完整HTTP雜湊仍相同。"]
 key='garminos_storage_exact_duplicate_cleanup';assert key not in app['static_findings'];app['static_findings'][key]=dict(evidence=G+'cleanup-result.json',evidence_sha256=sha(G+'cleanup-result.json'),scope='User-authorized duplicate content removal. Original complete disk image and all1402 file bytes verified; readonly image replaces extracted copy, immutable duplicates share content. Actual freed space measured;4596 protected sources rehashed, editable research and distinct results retained. No device operation.',evidence_type='ROOT actual filesystem cleanup evidence',device_io=False,physical_App_or_audio_verified=False)
 now=datetime.now(timezone.utc);state.update(updated_utc=now.isoformat(),latest_user_instruction='User explicitly requests GarminOS duplicate deletion, sole backup and disk space recovery. Completed exact-content cleanup; continue original native audio/App research.')
 state['native_app_music']['development_observations']['native_platform_readonly_probe']['current_installer']='scripts/stage_native_platform_probe_voice_v2.py'
 state['storage_cleanup']=dict(result=G+'cleanup-result.json',post_readback=G+'post-cleanup-live-verification.json',sole_complete_backup=cleanup['sole_complete_backup'],freed_bytes=cleanup['freed_bytes'],free_bytes=post['free_bytes'],original_paths_are_readonly_image_view=True,immutable_duplicate_content_single_copy=True)
 state['last_goal_turn'].update(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),previous_state_snapshot=B+'previous-state.json',previous_current_audit_snapshot=B+'previous-audit.json',focused_evidence=G+'cleanup-result.json',focused_evidence_sha256=sha(G+'cleanup-result.json'),reasons=['Requested207-file VS Code workspace delivered with verified LAN download.','Prepared readonly CPU/mode candidate and completed bounded micro/native reader evidence.','Explicitly authorized duplicate cleanup removed extracted backup and96 redundant immutable copies while preserving hashes; sole complete image retained.'],device_IO=False,goal_status='active',full_goal_complete=False)
 for key in('updated_utc','last_goal_turn','storage_cleanup','latest_user_instruction'):task[key]=state[key]
 public.update(updated=now.isoformat(),deep_research=state);progress['completed'].extend(details);progress['phases'][4]['completed'].extend(details);progress['research_updated_utc']=now.isoformat()
 assert len(app['static_findings'])==297 and len(progress['completed'])==279 and progress['estimate_percent']==37 and progress['phases'][4]['estimate_percent']==35
 card='<div class="card"><h2>最新進展：GarminOS空間整理與研究專案</h2><p>依要求清除重複資料，實際釋放<strong>'+f'{freed:.2f}GiB'+'</strong>，目前可用<strong>'+f'{available:.2f}GiB'+'</strong>。完整備份只保留sda.img；1402個檔案原路徑以唯讀映像提供，不再另存1.25GB解壓副本。其他相同研究檔共用一份資料，4596個舊來源雜湊核對通過。</p><p><a href="'+html.escape(latest['workspace_download_url'],quote=True)+'">下載VS Code研究專案（207檔，約27.4MiB）</a>，解壓後開啟GarminOS-research.code-workspace。提供原韌體、反組譯、研究C程式與工具；<strong>原廠完整原始碼未取得</strong>。</p><p>只讀CPU诊断44組微測試與2組原廠候選讀取器核對完成，候選未寫入實機。原語音2.10已確認；實機載入、正常模式音訊所有權、手機直接A2DP、App菜單、重連及安全卸載仍待研究。進度估計保持整體37%、App35%，本輪沒有車機操作。</p></div>'
 report,n=re.subn(r'<div class="card"><h2>最新進展：CPU診斷與VS Code研究專案</h2>.*?</div>',lambda _:card,before.decode(),count=1,flags=re.S);assert n==1
 report,n=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda x:x[1]+x[2]+''.join('<li>'+html.escape(d)+'</li>'for d in details)+x[3],report,count=1,flags=re.S);assert n==1
 local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds')
 for name in('report-updated-time','research-updated-time'):
  report,n=re.subn(r'<time id="'+name+r'" datetime="[^"]+">[^<]+</time>','<time id="'+name+'" datetime="'+iso+'">'+local.strftime('%Y/%m/%d %H:%M:%S')+'</time>',report,count=1);assert n==1
 for row in snapshots:assert sha(row['original'])==row['sha256']
 create(B+'publication-inputs.json',dict(all_passed=True,protected_sources=protected,details=details,old_sources_rechecked_by_cleanup_actor=4596,second_full_source_rehash_claimed=False));register(B+'publication-inputs.json')
 for p,d in zip(P.CANONICAL[:3],(state,task,public)):write(p,d)
 (ROOT/P.CANONICAL[3]).write_text(report);after={p:sha(p)for p in P.CANONICAL}
 with urllib.request.urlopen(urllib.request.Request(latest['url'],headers={'Cache-Control':'no-cache'}),timeout=10)as r:served=r.read();assert r.status==200 and 'no-store'in r.headers.get('Cache-Control','')
 assert served==report.encode()and P.service_now()==service
 audit=dict(old,all_passed=True,updated_utc=now.isoformat(),previous_checkpoint=B+'previous-audit.json',protected_sources=protected,canonical_after_sha256=after,current_state_sha256=after[P.CANONICAL[0]],report_sha256=after[P.CANONICAL[3]],local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],current_findings=297,current_public_details=279,storage_cleanup_result=G+'cleanup-result.json',storage_cleanup_freed_bytes=cleanup['freed_bytes'],sole_backup_image_preserved=True,scope_checks=dict(old['scope_checks'],cleanup4596_actual_source_rehash_preserved=True,original1402_backup_files_preserved_by_RO_image=True,requested_duplicate_storage_removed=True))
 create(OUT,audit);assert latest.pop('current_native_platform_readonly_probe_ROOT_checkpoint')==OLD;latest.setdefault('historical_offline_checkpoint_audits',{})['prior_native_platform_readonly_probe_ROOT_checkpoint']=dict(audit=B+'previous-audit.json',audit_sha256=sha(B+'previous-audit.json'),all_passed=True)
 latest.update(updated_utc=now.isoformat(),current_garminos_storage_cleanup_checkpoint=OUT,checkpoint_sha256={OUT:sha(OUT)},local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],report_bytes=len(served),served_latest_report=True,canonical_hash_readback_uncached=True,service_not_restarted=True)
 latest['progress_display_verified'].update(completed_items=279,report_updated_time=iso,research_updated_time=iso,actual_storage_cleanup_visible=True);write('evidence/report-web-latest.json',latest)
 print(json.dumps(dict(all_passed=True,findings=297,details=279,protected_sources=len(protected),report_sha256=after[P.CANONICAL[3]],updated_Taiwan=iso,freed_GiB=round(freed,2),available_GiB=round(available,2),goal_status='active',device_IO=False)),flush=True)
if __name__=='__main__':main()
