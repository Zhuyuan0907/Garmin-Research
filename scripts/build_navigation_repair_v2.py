#!/usr/bin/env python3
"""Build an independent native-sort candidate from frozen Taiwan split inputs."""
import datetime as dt
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'staging/navigation-repair-v2'
PREV=ROOT/'staging/navigation-repair-v1'
SORT=ROOT/'staging/navigation-firmware-sort-v1'
ENC=ROOT/'staging/navigation-search-encoding-v1'
TOOL=ROOT/'sources/maps/mkgmap-r4924'
SPLIT=ROOT/'staging/maps/Taiwan_OSM_20261001_UTF8/tiles'

def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(4*1024*1024),b''):h.update(b)
 return h.hexdigest()

def main():
 if len(sys.argv)!=2:
  raise SystemExit('Usage: build_navigation_repair_v2.py PROTOTYPE_VALIDATION_JSON')
 proof_path=Path(sys.argv[1]).resolve()
 assert proof_path.is_relative_to(SORT) and proof_path.is_file()
 proof=json.loads(proof_path.read_text());assert proof['all_passed'] is True
 assert proof['SRT_native_16_10_6_layout'] is True and proof['tables_and_maxPrimary_and_maxExp_unchanged'] is True
 assert proof['SRT_all_weight_records']['all_records_preserved_numerically'] is True
 assert proof['policy_hooks']==[] and proof['device_search_or_real_query_caller_verified'] is False
 assert len(proof['unit_tests'])==48 and len(proof['comparator_tests'])==23
 assert all(r['all_three_levels_equal'] for r in proof['unit_tests'])
 assert all(r['matches_primary_secondary_tertiary'] for r in proof['comparator_tests'])
 assert not OUT.exists(),'One-shot candidate namespace already exists'
 OUT.mkdir();compiled=OUT/'compiled';compiled.mkdir()
 old=json.loads((PREV/'build-manifest.json').read_text())
 assert old['state']=='compiled_candidate_not_device_verified'
 assert old['tile_count']==36 and old['family_id']==7052
 style=PREV/'style';bounds=PREV/'taiwan-bounds'
 assert bounds.is_dir() and sha(style/'inc/address')==old['style_address_sha256']
 classes=SORT/'packed-shadow-classes-v2'
 class_files=sorted(classes.rglob('*.class'));assert len(class_files)==5
 source=SORT/'packed-shadow-src-v2/uk/me/parabola/imgfmt/app/srt/Sort.java'
 writer_source=SORT/'packed-shadow-src-v2/uk/me/parabola/imgfmt/app/srt/SRTFile.java'
 source_receipt=json.loads((SORT/'packed-shadow-source-receipt-v2.json').read_text())
 assert sha(source)==source_receipt['shadow_sources']['Sort.java']=='a83fff5cf342879465165a7bfe7cda648e64dd05c825679eadbf70499bcf1947'
 assert sha(writer_source)==source_receipt['shadow_sources']['SRTFile.java']=='c31bfacba73e5f47dc64035af19f95ec75c582b4d075053f4f7aa3713ae221ea'
 assert source_receipt['hard_guards_not_assert_only'] is True
 resources=OUT/'sort-resource';(resources/'sort').mkdir(parents=True)
 original=(ENC/'sort-id-resource/sort/cp65001.txt').read_text()
 assert original.count('id2 7052')==1
 original=original.replace('id2 7052','id2 7053',1).replace('Taiwan UTF8 implicit BMP materialized v1','Taiwan UTF8 native Han Search v2')
 (resources/'sort/cp65001.txt').write_text(original)
 args=OUT/'tiles.args'
 args.write_text(''.join(f'mapname: {70530000+i}\ninput-file: {SPLIT/(str(70510000+i)+".osm.pbf")}\n\n' for i in range(1,37)))
 assert all((SPLIT/(str(70510000+i)+'.osm.pbf')).is_file() for i in range(1,37))
 for name in ['copyright.txt','license.txt']:shutil.copyfile(PREV/name,OUT/name)
 state=dict(started_utc=dt.datetime.now(dt.timezone.utc).isoformat(),state='compiling',candidate=True,
  family_id=7053,map_id_start=70530001,tile_count=36,sort_id1=19,sort_id2=7053,code_page=65001,
  osm_data_timestamp=old['osm_data_timestamp'],original_split_inputs_reused=True,
  frozen_boundary_preprocessing_reused=True,boundary_selection=old['boundary_selection'],
  style_path=str(style.relative_to(ROOT)),style_address_sha256=old['style_address_sha256'],
  finite_prototype_validation=str(proof_path.relative_to(ROOT)),finite_prototype_validation_sha256=sha(proof_path),
  native_sort_source=str(source.relative_to(ROOT)),native_sort_source_sha256=sha(source),
  pinned_compiler_classes={str(p.relative_to(ROOT)):sha(p) for p in class_files},
  native_packed_writer_source=str(writer_source.relative_to(ROOT)),native_packed_writer_source_sha256=sha(writer_source),sort_resource_sha256=sha(resources/'sort/cp65001.txt'),
  changes=['Generate host Han primary,secondary,tertiary keys using verified stock native implicit ranges',
   'Recognize verified supplementary Han codepoints as one codepoint',
   'Keep maxPrimary and all defined weight values unchanged; pack table and expansion records as native 16/10/6',
   'Retain v1 administrative-boundary city assignment and 台/臺 normalization',
   'Use independent FID/map IDs and consistent LBL/MDR/SRT identity'],
  device_installed=False,device_search_verified=False,device_routing_verified=False,
  stock_maps_modified=False,GarminOS_recompiled=False,
  limitations=['Finite original-instruction compatibility checks do not establish UI caller reachability or navigation symptom cause.',
   'Original Kaohsiung/旗津 boundary omissions are retained and documented.'])
 manifest=OUT/'build-manifest.json'
 def save():manifest.write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n')
 cp=':'.join(map(str,[classes,resources,TOOL/'mkgmap.jar']))
 command=['nice','-n','10','java','-Xmx2800m','-cp',cp,'uk.me.parabola.mkgmap.main.Main','--max-jobs=2',
  '--route','--index','--housenumbers','--gmapsupp','--code-page=65001',
  '--name-tag-list=name:zh-Hant,name:zh,name,int_name','--drive-on=right',
  '--country-name=Taiwan','--country-abbr=TWN','--region-name=Taiwan','--region-abbr=TW',
  '--location-autofill=is_in','--bounds='+str(bounds),'--style-file='+str(style),
  '--family-id=7053','--product-id=1','--family-name=OSM TW 2026-10-01 Search v2',
  '--series-name=OSM Taiwan Search v2','--description=OSM TW 2026-10-01 Search v2',
  '--copyright-file='+str(OUT/'copyright.txt'),'--license-file='+str(OUT/'license.txt'),
  '--output-dir='+str(compiled),'-c',str(args)]
 state['command']=command;save()
 try:
  with (OUT/'mkgmap-build.log').open('x') as f:
   result=subprocess.run(command,cwd=OUT,stdout=f,stderr=subprocess.STDOUT)
  state['exit_code']=result.returncode
  if result.returncode:raise RuntimeError(f'mkgmap exit {result.returncode}')
  image=compiled/'gmapsupp.img'
  state.update(state='compiled_candidate_not_device_verified',image=str(image.relative_to(ROOT)),
   image_bytes=image.stat().st_size,image_sha256=sha(image),finished_utc=dt.datetime.now(dt.timezone.utc).isoformat())
  save();print(json.dumps({k:state[k] for k in ['state','image_bytes','image_sha256']},ensure_ascii=False),flush=True)
 except Exception as e:
  state.update(state='failed',error=str(e),finished_utc=dt.datetime.now(dt.timezone.utc).isoformat());save();raise
if __name__=='__main__':main()
