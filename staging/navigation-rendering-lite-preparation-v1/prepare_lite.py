#!/usr/bin/env python3
"""Prepare source-only single-tile visual comparison. Does not launch Java."""
from pathlib import Path
import hashlib,json,shutil,datetime,difflib
ROOT=Path('/root/garmin');OUT=ROOT/'staging/navigation-rendering-lite-preparation-v1';SRC=ROOT/'staging/navigation-repair-v1/style'
ORIGINAL='building=* & building!=no [0x13 resolution 24]'
ACTION="building=* & building!=no { set mkgmap:execute_finalize_rules=true; set mkgmap:lite-building-suppressed=yes }"
FOLLOWING=["tourism=* & area!=no & waterway!=* {add name='${tourism|subst:\"_=> \"}'} [0x21 resolution 24]","man_made=* & area!=no {add name='${man_made|subst:\"_=> \"}'} [0x24 resolution 24]","place=island & name=* & area_size() < 1000000 [0x53 resolution 19]","place=islet & name=* [0x53 resolution 20]"]
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
 src=(SRC/'polygons').read_text();assert src.count(ORIGINAL)==1
 assert src.count('<finalize>')==1 and "addr:housenumber=* {set mkgmap:execute_finalize_rules=true}" in src
 assert 'mkgmap:lite-building-suppressed' not in src
 assert not (OUT/'baseline-style').exists() and not (OUT/'lite-style').exists()
 for n in ['baseline-style','lite-style']:shutil.copytree(SRC,OUT/n)
 lite=src.replace(ORIGINAL,ACTION)
 for rule in FOLLOWING:
  assert lite.count(rule)==1
  expr,body=rule.split(' {',1) if ' {' in rule else rule.split(' [',1)
  tail=(' {' if ' {' in rule else ' [')+body
  lite=lite.replace(rule,'mkgmap:lite-building-suppressed!=yes & ('+expr+')'+tail)
 assert src.split('<finalize>',1)[1]==lite.split('<finalize>',1)[1]
 assert src.split(ORIGINAL)[0]==lite.split(ACTION)[0]
 (OUT/'lite-style/polygons').write_text(lite)
 (OUT/'style-change.diff').write_text(''.join(difflib.unified_diff(src.splitlines(True),lite.splitlines(True),fromfile='baseline-style/polygons',tofile='lite-style/polygons')))
 files=[]
 for p in sorted(SRC.rglob('*')):
  if not p.is_file():continue
  rel=p.relative_to(SRC);base=OUT/'baseline-style'/rel;candidate=OUT/'lite-style'/rel
  assert digest(base)==digest(p)
  if str(rel)!='polygons':assert digest(candidate)==digest(p)
  files.append({'path':str(rel),'source_sha256':digest(p),'baseline_sha256':digest(base),'lite_sha256':digest(candidate),'unchanged':digest(candidate)==digest(p)})
 assert sum(not x['unchanged'] for x in files)==1
 proof={
  'schema':'garmin-rendering-lite-source-preparation/v1','created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
  'source_only':True,'Java_launched':False,'style_runtime_tested':False,'real_tile_compiled':False,'device_IO':False,'candidate_installable':False,
  'source_tile':'staging/maps/Taiwan_OSM_20261001_UTF8/tiles/70510020.osm.pbf','output_mapname':70530020,
  'note':'Input split names retain70510020, compiled v2 mapname is70530020; no source70530020.osm.pbf exists.',
  'changes':['Only polygons source differs. At original0x13 match position, no polygon type is emitted; set execute_finalize_rules=true and private suppression marker.','Gate the four lower-priority polygon rules so features originally claimed by0x13 cannot silently become tourism/man_made/island/islet polygons.','All pre-building rules and exact entire finalize block retained, all lines/points/relations/options/includes identical.'],
  'address_processing_static_evidence':{
   'official_archive_receipt':'staging/navigation-rendering-lite-preparation-v1/exact-source-receipt.json',
   'exact_r4924_RuleSet':'reference/RuleSet.java:94-104 calls last rule finalizer when no type resolved and execute_finalize_rules=true.',
   'exact_r4924_ActionRule':'reference/ActionRule.java:65-103 applies tag actions; type-null does not invoke its own type-finalizer; sends null type to watcher.',
   'exact_r4924_WatchableTypeResult':'reference/WatchableTypeResult.java:34-38 ignores null type output and leaves found=false.',
   'exact_r4924_StyledConverter':'reference/StyledConverter.java:551-552 retains unmatched ways in HousenumberGenerator after rules.resolveType returns; actual original polygon finalizer tags already applied at that point.',
   'correction_of_prior_warning':'Baseline polygons already force finalize for addr:housenumber features at line11; their absence of a type is not by itself proof of lost address processing. Lite explicitly forces finalize for all original0x13 building matches, including housename-only cases.',
   'runtime_scope':'Exact upstream source semantics, not a executed style/Java/IMG result.'},
  'file_identity_controls':files,'guarded_lower_priority_rule_count':len(FOLLOWING),
  'feature_controls_to_execute_later':['ordinary building with house6','building with housename only','building+tourism hotel (no replacement polygon)','building+man_made (no replacement polygon)','building+place islet (no replacement polygon)','hospital/school building matched earlier preserved','building=no with tourism preserved','nonbuilding water/park/landuse preserved'],
  'compilation_plan':'run_comparison.py default outputs command only; --execute requires root confirmed resource availability. Separate baseline/lite output directories, same source/map IDs/config to isolate style. These two cannot be enabled together.',
  'validation_required':['Actual style parse and8 semantic fixture controls plus address-tag capture; source-only proof cannot replace them.','Compile same tile twice. Read actual TRE/RGN counts and type distributions:0x13 eliminated/reduced; earlier type controls and all non0x13 output semantics preserved.','Compare bounded component inventory/digests for NET/NOD/LBL/SRT/TRE/RGN. Changed NET/NOD hashes are not route failure proof (label/subdivision offsets may change); equal hashes are strong unchanged-data evidence.','Compare semantic road identities/geometry/access/one-way/classes/speed/turn restriction/boundary connection graph and house/city associations if NET/NOD change; native AP search not rewritten.','Rebuild/futurewhole package retains original36 coverage and exact address/Bluetooth goal scopes; single tile alone is not allTaiwan replacement.','Physical6/150/184 destination+route calculation and same-scene redraw A/B remain required.'],
  'observed_physical_report':'User now says slow redraw/temporary visual damage occurs during actual movement and with stock maps too. Lite is optional reversible diagnostic/optimization, not demonstrated root cause or repair.'}
 (OUT/'source-preparation-proof.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({'source_only':True,'style_files':len(files),'changed_files':1,'guarded_following_rules':len(FOLLOWING),'finalize_identical':True,'Java_launched':False}))
if __name__=='__main__':main()
