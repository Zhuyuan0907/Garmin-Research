#!/usr/bin/env python3
"""Read only NEW compiled roads; reuse frozen decoded original comparison."""
import datetime as dt
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path('/root/garmin');BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'staging/navigation-road-regression-v1'))
import compare_road_cities_v2 as prior

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 out=BASE/'road-city-regression-proof-v2.json';assert not out.exists()
 manifest_path=ROOT/'staging/navigation-repair-v2/build-manifest.json';build=json.loads(manifest_path.read_text())
 assert build['state']=='compiled_candidate_not_device_verified' and build['exit_code']==0
 assert build['family_id']==7053 and build['tile_count']==36
 frozen=ROOT/'staging/navigation-road-regression-v1/old-road-geometry-v2.json'
 original_proof=ROOT/'staging/navigation-road-regression-v1/road-city-regression-proof-v2.json'
 original=json.loads(original_proof.read_text());assert original['all_passed']
 reader_source=ROOT/'staging/navigation-road-regression-v1/ReadRoadGeometryV2.java'
 expected=next(r['sha256'] for r in original['inputs'] if Path(r['path']).name==reader_source.name)
 assert sha(reader_source)==expected
 old=prior.parse_reader_output(frozen.read_text())
 tiles=[ROOT/'staging/navigation-repair-v2/compiled'/f'705300{n:02}.img' for n in (19,20,21)]
 new=prior.reader(tiles,BASE/'new-road-geometry-v2.json')
 anchors=json.loads(prior.SOURCE_PROOF.read_text())['points']
 groups={name:{'old':prior.group_summary(old,g),'new':prior.group_summary(new,g)} for name,g in prior.GROUPS.items()}
 witnesses=[dict(source_anchor=a,new=prior.nearest_label_witness(new,a)) for a in anchors]
 checks={name+'_labels_retained':set(r['new']['street_names'])==set(prior.GROUPS[name]['names']) for name,r in groups.items()}
 checks.update({name+'_only_Taichung_city':r['new']['all_rows_have_only_Taichung_city'] for name,r in groups.items()})
 checks.update({name+'_Taichung_region':r['new']['all_rows_have_Taichung_region'] for name,r in groups.items()})
 checks['all_source_anchor_labels_within_30m']=all(w['new'].get('within_30m',False) for w in witnesses)
 result=dict(all_passed=all(checks.values()),checked_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
  checks=checks,groups=groups,anchor_witnesses=witnesses,
  candidate=dict(path=build['image'],bytes=build['image_bytes'],sha256=build['image_sha256'],whole_IMG_digest_repeated=False),
  inputs_sha256={str(p.relative_to(ROOT)):sha(p) for p in [Path(__file__),reader_source,frozen,original_proof,prior.SOURCE_PROOF,*tiles]},
  original_decoded_roads_reused=True,old_NET_RGN_decoding_repeated=False,
  selector_self_tests_repeated=False,
  reader_join='NEW detailed-level RGN raw NET offsets joined to NET road metadata; real LBL city point references resolved',
  scope='New v2 tiles19/20/21 road names, Taichung city/region association and five source-coordinate anchors; comparison uses previously verified decoded original roads',
  device_search_verified=False,device_routing_verified=False,device_IO=False,
  limitations=['Compiled road entries are not original OSM way or address counts.','No address UI execution, house-number decoding, routing solver or full-country geometry guarantee.'])
 with out.open('x') as f:json.dump(result,f,ensure_ascii=False,indent=2);f.write('\n')
 print(json.dumps(dict(all_passed=result['all_passed'],checks=checks,evidence=str(out.relative_to(ROOT))),ensure_ascii=False))
 raise SystemExit(0 if result['all_passed'] else 1)
if __name__=='__main__':main()
