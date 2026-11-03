#!/usr/bin/env python3
"""Independent packed DATA decoder over sealed captures; never opens an IMG."""
import sys
sys.dont_write_bytecode=True
import ast,gzip,hashlib,json,struct
from pathlib import Path
from bounded_artifacts import BudgetReader,sha,ROOT
HERE=Path(__file__).resolve().parent;D='staging/navigation-single-lane-v2-4k-virtual-delta-v1'
SEAL_SHA='e70643bf37de5edd1dc4a4701da9df0f54e8ea03580040034f23b360ade0cde0'
def save(n,d):
 assert not(HERE/n).exists()
 (HERE/n).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
def uint(raw,at,n):return int.from_bytes(raw[at:at+n],'little')
class Captures:
 def __init__(self,raw,index,size):
  self.raw,self.index,self.size=raw,index,size;self.requests=[];cursor=0;previous_end=0
  for row in index:
   a,n,o=row['physical_offset'],row['bytes'],row['artifact_offset']
   assert n>0 and o==cursor and a>=previous_end and a+n<=size
   assert sha(raw[o:o+n])==row['SHA256'];cursor+=n;previous_end=a+n
  assert cursor==len(raw)==88047
 def get(self,at,n):
  assert n>0 and 0<=at<at+n<=self.size
  for r in self.index:
   if r['physical_offset']<=at and at+n<=r['physical_offset']+r['bytes']:
    off=r['artifact_offset']+at-r['physical_offset'];b=self.raw[off:off+n]
    self.requests.append(dict(offset=at,bytes=n,sha256=sha(b)));return b
  raise ValueError('Exact actual stream capture unavailable for requested bytes')
class Mapper:
 def __init__(self,capture):
  self.c=capture;self.header=capture.get(0,512);h=self.header
  assert h[0]==0 and h[16:23]==b'DSKIMG\0'
  assert h[65:72]==b'GARMIN\0' and h[510:512]==b'\x55\xaa' and (h[97],h[98])==(9,3)
  self.block=1<<(h[97]+h[98]);assert self.block==4096
  self.capacity=uint(h,99,2)*self.block
  assert self.capacity==uint(h,458,4)*512==134217728
  fat_at=h[64]*512;root=capture.get(fat_at,512)
  assert root[0]==1 and root[16]==3 and uint(root,17,2)==0
  self.end=uint(root,12,4);assert self.end==73728 and self.end%4096==0
  assert [b for b in struct.unpack_from('<240H',root,32)if b!=65535]==list(range(18))
  self.metadata=capture.get(0,self.end);fat=self.metadata[fat_at:self.end];parts={}
  for row in [fat[i:i+512]for i in range(0,len(fat),512)]:
   if row[0]!=1 or row[16]==3:continue
   name=row[1:9].decode('ascii').rstrip()+'.'+row[9:12].decode('ascii').rstrip()
   parts.setdefault(name,[]).append((uint(row,17,2),uint(row,12,4),list(struct.unpack_from('<240H',row,32))))
  self.components={};used=set()
  for name,ps in parts.items():
   ps.sort();assert [p[0]for p in ps]==list(range(len(ps)))
   assert ps[0][1]>0 and all(p[1]==0 for p in ps[1:])
   for p in ps:
    if 65535 in p[2]:assert all(b==65535 for b in p[2][p[2].index(65535):])
   blocks=[b for p in ps for b in p[2]if b!=65535];size=ps[0][1]
   assert len(blocks)==(size+4095)//4096
   assert len(set(blocks))==len(blocks) and not set(blocks)&used
   assert min(blocks)>=self.end//4096 and all((b+1)*4096<=capture.size for b in blocks)
   used.update(blocks);self.components[name]=dict(size=size,blocks=blocks,parts=len(ps))
  assert len(self.components)==6 and len(fat)//512==136
  assert list(self.components)==['00004171.MD2','00004171.MDR','00004171.SRT','I053061A.GMP','I053061A.SRT','MAPSOURC.MPS']
  assert used==set(range(18,capture.size//4096))
 def get(self,name,at,n):
  obj=self.components[name];assert 0<=at<at+n<=obj['size'];pieces=[]
  while n:
   i,inside=divmod(at,4096);amount=min(n,4096-inside)
   pieces.append(self.c.get(obj['blocks'][i]*4096+inside,amount));at+=amount;n-=amount
  return b''.join(pieces)
def tables(m):
 h=m.get('00004171.MDR',0,772);assert uint(h,0,2)==772 and h[2:12]==b'GARMIN MDR'
 dstart,n,entry,tag=struct.unpack_from('<4I',h,600);assert(n,entry,tag)==(120,20,1)
 assert dstart+n==m.components['00004171.MDR']['size'];d=m.get('00004171.MDR',dstart,n);ts={}
 for level in range(1,7):
  start,span,stride,a,b=struct.unpack_from('<5I',d,(level-1)*20)
  w=[(a>>18)&63,(a>>24)&63,(a>>12)&63,(a>>6)&63,a&63,b&63,(b>>11)&63,(b>>17)&63]
  ref=[(a>>30)&1,(a>>31)&1]
  assert w[4]+sum(ref)*w[3]+w[0]+w[5]+w[1]+2*w[2]==stride
  assert w[6:]==[0,0]
  ts[level]=dict(start=start,bytes=span,stride=stride,count=span*8//stride,widths=w,flags=ref,unused_bits=span*8%stride)
 order=[6,5,4,3,2,1]
 for a,b in zip(order,order[1:]):assert ts[a]['start']+ts[a]['bytes']==ts[b]['start']
 assert ts[1]['start']+ts[1]['bytes']==dstart
 return h,d,ts
def decode(value,t):
 w=t['widths'];rf=t['flags'];at=0;r={}
 for name,width,present,isref in [('mapordinal',w[4],True,False),('secondary_ref',w[3],rf[1],True),
  ('primary_ref',w[3],rf[0],True),('first_child',w[0],True,False),('child_count',w[5],True,False),
  ('raw_flags',w[1],True,False),('raw_lat',w[2],True,False),('raw_lon',w[2],True,False)]:
  v=(value>>at)&((1<<width)-1) if present else None
  r[name]=None if isref and (not present or v==(1<<width)-1)else v
  if present:at+=width
 assert at==t['stride'];r['next_level']=(r['raw_flags']or 0)&7
 return r
def main():
 assert not(HERE/'proof.json').exists()
 prior=sum(json.loads((HERE/n).read_text())['actual_artifact_bytes_read']for n in
  ['first-seal-read-receipt.json','inspection-read-receipts.json','source-inspection-read-receipts.json',
   'setup-source-read-receipts.json','baseline-metadata-inspection-receipts.json'])
 prior+=json.loads((HERE/'FAT-continuation-size-failure.json').read_text())['completed_source_reads_bytes']
 prior+=json.loads((HERE/'continuation-format-source-inspection-receipts.json').read_text())['actual_artifact_bytes_read']
 br=BudgetReader();br.actual_bytes=prior
 seal=json.loads(br.read(D+'/sealed-files.json',SEAL_SHA,8915,'0o644'))
 blobs={}
 for f in seal['files']:
  blobs[Path(f['path']).name]=br.read(f['path'],f['SHA256'],f['bytes'],f['mode'],f['stat_at_seal'])
 load=lambda n:json.loads(blobs[n]);producer=load('proof.json');delta=load('delta-manifest.json');inv=load('inverse-metadata.json');sr=load('stream-receipt.json')
 pins={r['path']:r for r in producer['normal_inputs']}
 def baseline(name):
  p=pins[name];return br.read(name,p['SHA256'],p['bytes'],expected_stat=p['stat_before'])
 rawroot=baseline('staging/navigation-minimal-lane-render-isolation-plan-v1/v2-root-raw-window.bin')
 rawhouses=baseline('staging/navigation-minimal-lane-render-isolation-plan-v1/v2-lane-raw-window.bin')
 oldmeta=json.loads(baseline('staging/navigation-minimal-lane-render-isolation-plan-v1/actual-raw-capture-metadata.json'))
 selected=json.loads(baseline('staging/navigation-minimal-lane-render-isolation-plan-v1/selected-control.json'))
 controls=json.loads(baseline('staging/navigation-single-lane-minquan-controls-extraction-v1/actual-minquan-controls.json'))
 v2seal=json.loads(baseline('staging/navigation-country-native-candidate-v2/sealed-files.json'))
 basepin=next(r for r in v2seal['files']if r['path'].endswith('/gmapprom1.img'))
 assert basepin['bytes']==128356352 and basepin['sha256']==inv['original_IMG_SHA256']==sr['source_inverse_IMG_SHA256']
 capture=Captures(blobs['actual-stream-windows.bin'],load('actual-stream-windows-index.json'),sr['virtual_IMG_bytes'])
 mapper=Mapper(capture);header,dirbytes,ts=tables(mapper)
 assert mapper.capacity>=capture.size==128360448 and capture.size-128356352==4096
 for name,c in mapper.components.items():
  planned=delta['layout']['allocations'][name]
  assert c['size']==delta['layout']['sizes'][name]
  assert c['blocks']==list(range(planned['first_block'],planned['last_block']+1))
 assert ts[3]['stride']==112 and ts[3]['widths'][0]==23
 assert ts[4]['stride']==128 and ts[5]['stride']==126 and ts[6]['stride']==68
 assert [ts[i]['count']for i in range(1,7)]==[22,343,47870,3781861,2667578,1984066]
 gh=mapper.get('I053061A.GMP',0,57);assert gh[2:12]==b'GARMIN GMP'
 lbl_at=uint(gh,33,4);lh=mapper.get('I053061A.GMP',lbl_at,661);assert lh[2:12]==b'GARMIN LBL'
 pool,poolbytes=struct.unpack_from('<II',lh,21);shift=lh[29]
 assert (pool,poolbytes,shift,lh[30],uint(lh,170,2))==(6566,3805432,3,10,950)
 label_cache={}
 def label(ref):
  if ref is None:return None
  if ref not in label_cache:
   at=ref*(1<<shift);assert at<poolbytes
   b=mapper.get('I053061A.GMP',pool+at,min(64,poolbytes-at));end=b.index(0)
   label_cache[ref]=dict(text=b[:end].decode('cp950'),bytes_hex=b[:end].hex(),window_SHA256=sha(b))
  return label_cache[ref]['text']
 def record(level,ID):
  t=ts[level];assert 1<=ID<=t['count'];at,off=divmod((ID-1)*t['stride'],8)
  b=mapper.get('00004171.MDR',t['start']+at,(off+t['stride']+7)//8)
  v=(int.from_bytes(b,'little')>>off)&((1<<t['stride'])-1);r=decode(v,t)
  r.update(level=level,ID=ID,value_hex=v.to_bytes((t['stride']+7)//8,'little').hex(),initial_shift=off,label=label(r['primary_ref']))
  assert r['mapordinal']==1;return r,v
 root,rootv=record(3,1153);assert(root['label'],root['first_child'],root['child_count'],root['raw_flags'])==('四川路二段',3781595,267,4)
 oldroot=oldmeta['parent_actual_bit_offsets']['v2']['root'];assert oldroot['payload']==inv['old_ROOT1153_hex']
 rootmask=((1<<35)-1)<<20
 oldrootv=int.from_bytes(bytes.fromhex(inv['old_ROOT1153_hex']),'little')
 assert (rootv&~rootmask)==(oldrootv&~rootmask)
 assert decode(oldrootv,ts[3])['first_child']==2134701 and decode(oldrootv,ts[3])['child_count']==267
 siblings=[];old_flag_counts={};lane=None
 for i in range(267):
  r,v=record(4,3781595+i);oldv=int.from_bytes(rawroot[i*16:i*16+16],'little')
  original=decode(oldv,ts[4]);old_flag_counts[original['raw_flags']]=old_flag_counts.get(original['raw_flags'],0)+1
  if i==5:
   mask=((1<<32)-1)<<39;assert (v&~mask)==(oldv&~mask)
   assert (r['first_child'],r['child_count'],r['label'],r['raw_flags'])==(2667574,5,'4巷',5);lane=r
   assert(original['first_child'],original['child_count'])==(169831,4)
  else:assert v==oldv
  siblings.append(dict(old_current_ID=2134701+i,new_ID=r['ID'],label=r['label'],raw_flags=r['raw_flags'],first=r['first_child'],count=r['child_count']))
 assert len([r for r in siblings if r['label']=='4巷'])==1
 houses=[];values=[]
 for i in range(5):
  r,v=record(5,lane['first_child']+i);houses.append(r);values.append(v)
 assert [r['label']for r in houses]==['+ 交叉路口 +','1號','2號','4號','7號']
 oldvalues=[(int.from_bytes(rawhouses,'little')>>(4+i*126))&((1<<126)-1)for i in range(4)]
 assert [values[i]for i in (0,1,3,4)]==oldvalues
 assert [decode(v,ts[5])['raw_flags']for v in oldvalues]==[6,8,0,0]
 newpayload=blobs['new2-source-bound126bits.bin'];assert values[2]==int.from_bytes(newpayload,'little') and len(newpayload)==16
 assert (houses[2]['primary_ref'],houses[2]['raw_flags'],houses[2]['raw_lat'],houses[2]['raw_lon'])==(19,0,1164928,5660270)
 assert selected['candidate']['payload']==newpayload.hex() and selected['candidate']['source_ids']==[12084620255]
 assert selected['candidate']['source_group_ids']==[3508619] and selected['candidate']['raw24']==[1164928,5660270]
 assert (houses[0]['first_child'],houses[0]['child_count'],houses[0]['next_level'])==(120119,1,6)
 nested,nestedv=record(6,120119);assert[nested['raw_lat'],nested['raw_lon']]==[houses[0]['raw_lat'],houses[0]['raw_lon']]
 # Independently check tight append source bits against real global shifted captures.
 assert mapper.get('00004171.MDR',ts[4]['start']+(3781595-1)*16,4272)==blobs['append-L4-267-significant.bin']
 appended5=int.from_bytes(blobs['append-L5-5-significant.bin'],'little')
 assert appended5>>630==0 and [(appended5>>(126*i))&((1<<126)-1)for i in range(5)]==values
 assert [r['initial_shift']for r in houses]==[6,4,2,0,6]
 minroot,mv=record(3,16707);assert minroot['value_hex']==controls['parent']['significant_rawbits_hex'] and minroot['label']=='民權路'
 minrecords=[]
 for c in controls['controls']:
  r,v=record(4,c['ID']);assert r['value_hex']==c['significant_rawbits_hex'] and r['label']==c['label']
  assert(r['primary_ref'],[r['raw_lat'],r['raw_lon']])==(c['primary_ref'],c['raw24'])
  assert label_cache[r['primary_ref']]['bytes_hex']==c['actual_label_bytes_hex']
  assert label_cache[r['primary_ref']]['window_SHA256']==c['actual_label_window_SHA256'];minrecords.append(r)
 # Full captured FAT/header inverse, without any underlying IMG reads.
 restored=bytearray(mapper.metadata);runs=blobs['inverse-metadata-runs.bin'];cursor=0;previous=0;run_count=0
 while cursor<len(runs):
  off,n=struct.unpack_from('<IH',runs,cursor);cursor+=6
  assert n>0 and previous<=off and off+n<=len(restored) and cursor+2*n<=len(runs)
  old,new=runs[cursor:cursor+n],runs[cursor+n:cursor+2*n];cursor+=2*n
  assert bytes(restored[off:off+n])==new;restored[off:off+n]=old;previous=off+n;run_count+=1
 assert run_count==inv['metadata_diff_run_count']==980 and cursor==len(runs)
 assert restored[:4096]==mapper.metadata[:4096]
 sourcecalls=producer['source_actual_reads']['first_read_calls']
 assert sha(mapper.metadata[:512])==sourcecalls[0]['SHA256'] and sha(mapper.metadata[512:4096])==sourcecalls[1]['SHA256']
 padding=gzip.decompress(blobs['inverse-original-padding.bin.gz']);assert len(padding)==11999
 for name,p in inv['original_component_padding']['components'].items():
  b=padding[p['offset']:p['offset']+p['bytes']];assert len(b)==p['bytes'] and sha(b)==p['SHA256']
 assert sum(p['bytes']for p in inv['original_component_padding']['components'].values())==len(padding)
 assert sum(n for at,n in inv['MDR_keep_new_offset_old_length'])==124255307
 masks=inv['MDR_byte_masks'];patch={m['new_offset']:(m['mask'],m['original_masked_value'])for m in masks}
 restored_header=bytearray(header);restored_dir=bytearray(dirbytes);restored_root=bytearray(bytes.fromhex(root['value_hex']))
 root_at=ts[3]['start']+(1153-1)*14;dir_at=uint(header,600,4)
 for at,(mask,val)in patch.items():
  assert val&~mask==0
  if at<772:target,off=restored_header,at
  elif dir_at<=at<dir_at+120:target,off=restored_dir,at-dir_at
  elif root_at<=at<root_at+14:target,off=restored_root,at-root_at
  else:
   assert at==ts[5]['start']+delta['COW_report']['original_tables'][4]['bytes']-1 and mask==192 and val==0
   continue
  target[off]=(target[off]&~mask)|val
 assert restored_root.hex()==inv['old_ROOT1153_hex']
 assert uint(restored_header,600,4)==124255187
 for i,t in enumerate(delta['COW_report']['original_tables']):
  assert struct.unpack_from('<3I',restored_dir,i*20)==(t['start'],t['bytes'],t['stride'])
  assert restored_dir[i*20+8:(i+1)*20]==dirbytes[i*20+8:(i+1)*20]
 # Static source dataflow witnesses; no producer module executes.
 support=blobs['stream_support_v1.py'].decode().splitlines();build=blobs['build_virtual_delta_v1.py'].decode().splitlines()
 ast.parse('\n'.join(support));ast.parse('\n'.join(build))
 witnesses=[]
 for name,lines,a,b,meaning in [('stream_support_v1.py',support,155,185,'Actual destination write raw feeds forwardhash/captures; MDR raw slice feeds inverse.consume'),
  ('stream_support_v1.py',support,109,122,'InverseMDR derives kept bytes from raw input, patches masks, updates inverse wholehash'),
  ('stream_support_v1.py',support,186,192,'Non-MDR bytes from emitted raw, original recorded padding only supplements tails'),
  ('build_virtual_delta_v1.py',build,269,278,'Real repack_stream(image,sink) precedes sink.receipt; separate source auditor.finish precedes comparison'),
  ('build_virtual_delta_v1.py',build,63,88,'OriginalMDRDigest is separately based on supplier original chunks and restored original cache')]:
  witnesses.append(dict(file=D+'/'+name,line=a,end_line=b,meaning=meaning,source_sha256=sha(blobs[name]),exact_source='\n'.join(lines[a-1:b])))
 assert 'self.inverse_mdr.consume(low-start,b,self.inverse_whole)'in'\n'.join(support)
 assert 'returned=base.repack_stream(image,sink' in '\n'.join(build)
 readback=load('actual-captured-readback-proof.json')
 for own,their in [(root,readback['root']),(lane,readback['lane']),(houses[2],readback['new2']),*zip(houses,readback['old_and_new_five_houses'])]:
  assert own['value_hex']==their['significant_bits_hex']
 receipt=br.verify_immutable();assert receipt['actual_artifact_bytes_read']<=1<<20
 save('independent-decoded-witnesses.json',dict(root=root,lane=lane,houses=houses,nested_intersection_child=nested,
  siblings=siblings,original_flag_counts=old_flag_counts,Minquan_parent=minroot,Minquan_controls=minrecords,
  partial_inverse=dict(metadata_bytes=len(restored),metadata_runs=run_count,restored_metadata_SHA256=sha(restored),
    restored_MDR_header_SHA256=sha(restored_header),restored_MDR_DIR_SHA256=sha(restored_dir),padding_bytes=len(padding)),
  code_dataflow_witnesses=witnesses,all_original_field_identity_checks_passed=True))
 save('independent-read-receipts.json',dict(**receipt,earlier_artifact_read_bytes=prior,
  new_review_artifact_read_bytes=receipt['actual_artifact_bytes_read']-prior,
  captured_byte_requests=len(capture.requests),captured_requested_bytes=sum(r['bytes']for r in capture.requests),
  no_underlying_IMG_file_opened=True,producer_reader_or_writer_modules_executed=False))
 save('proof.json',dict(schema='independent-small-virtual-lane-delta-review/v1',all_assigned_checks_passed=True,
  producer_seal_SHA256=SEAL_SHA,producer_proof_SHA256=sha(blobs['proof.json']),virtual_bytes=128360448,
  virtual_full_SHA256_from_producer_execution=sr['virtual_IMG_SHA256'],
  independent_full_forward_SHA256_recomputed=False,independent_full_inverse_SHA256_recomputed=False,
  inverse_whole925a_origin='Actual emitted transformed output bytes through CaptureHashSink.write -> InverseMDR.consume and inverse_whole.update, plus recorded sparse old metadata/masks and11999B original padding. Not OriginalMDRDigest source identity.',
  inverse_whole_SHA256_from_producer_execution=sr['source_inverse_IMG_SHA256'],
  separate_original_MDR_source_digest_origin=load('original-MDR-source-digest.json')['method'],
  independent_inverse_scope='Complete captured FAT metadata restoration, captured MDR header/DIR/root masks and packed original padding verified; omitted ~128MB emitted bytes not independently available in captures.',
  independently_decoded_actual_forward_capture_bytes=88047,finite_captures_are_not_full_output_file_readback=True,
  independent_4K_header_capacity_and_FAT_mapping_passed=True,capacity_bytes=mapper.capacity,
  original_header_first4096_match_recorded_source_hashes=True,all267_original_sibling_significant_bits_preserved_except_selected_first_count=True,
  selected_L3_first_count_only_change=True,selected_lane_L4_first_count_only_change=True,
  retained_old4_complete126bit_fields_order_flags_lowerpointer_preserved=True,old_flags=[6,8,0,0],
  new2_path=['四川路二段','4巷','2號'],new2_source_ID=12084620255,new2_group_ID=3508619,
  tight_L5_shift_controls=[6,4,2,0,6],Minquan_controls=['6號','150號','184號'],
  unique_CP950_refs_decoded=len(label_cache),partial_inverse_padding_gzip_lossless=True,
  artifact_bytes_read_total=receipt['actual_artifact_bytes_read'],artifact_limit_bytes=1<<20,
  initial_failed_extra_mode_assumption_preserved=True,producer_actual_modes_preserved_without_chmod=True,
  renderer_UI_native_lookup_route_and_device_verified=False,original_v3_road_loss_root_cause_proved=False,
  data_compaction_has_no_renderer_or_acceptance_implication=True,full_output_IMG_created_or_opened=False,
  IMG_PBF_MAIN_CPU_guest_device_audio_reads_or_execution=0,native_write_ready=False,install_ready=False,
  full_update_complete=False,all_handles_closed=True))
 print(json.dumps(dict(result='PASS independent DATA captures/mapping/inverse-origin review',artifact_bytes_total=receipt['actual_artifact_bytes_read'],
  actual_forward_capture_bytes=88047,siblings=267,old4_flags_preserved=[6,8,0,0],Minquan_controls=3,
  inverse_origin='emitted transformed bytes with sparse inverse metadata; separate sourceidentity not substituted',
  full_inverse_independently_recomputed=False,IMG_CPU_device_reads=0,all_handles_closed=True)))
if __name__=='__main__':main()
