#!/usr/bin/env python3
"""Reuse the small admin extract for complete native-city boundary checks."""
import hashlib
import json
import os
import subprocess
from datetime import datetime,timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'staging/navigation-repair-v1/taiwan-admin-selected-from-source.osm.pbf'
OUT=ROOT/'staging/navigation-country-city-geometry-v1'


def main():
    assert not OUT.exists()
    roots=json.loads((ROOT/'staging/navigation-road-coverage-v1/native-taiwan-admin-roots.json').read_text())
    closure=json.loads((ROOT/'staging/navigation-road-coverage-v1/native-root-closure-proof.json').read_text())
    known={r['id']:r for r in closure['roots']}
    selected={r['name']:r for r in roots['municipality_city_roots']+roots['county_roots']}
    assert len(selected)==22 and set(known)=={r['id']for r in selected.values()}
    usable={name:r for name,r in selected.items() if known[r['id']]['complete_reference_closed_geometry']}
    assert len(usable)==21 and set(selected)-set(usable)=={'高雄市'}
    before=SOURCE.stat();OUT.mkdir()
    command=['osmium','export','--geometry-types=polygon','-u','type_id','-f','geojsonseq',str(SOURCE)]
    features={};total=0
    with (OUT/'export.stderr.txt').open('x')as err:
        proc=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=err,text=True)
        for line in proc.stdout:
            line=line.lstrip('\x1e').strip()
            if not line:continue
            feature=json.loads(line);total+=1;props=feature.get('properties',{});name=props.get('name')
            if name not in usable:continue
            row=usable[name]
            if props.get('ISO3166-2')!=row['ISO3166-2']:continue
            assert props.get('boundary')=='administrative' and name not in features
            geometry=feature['geometry']
            if geometry['type']=='Polygon':geometry={'type':'MultiPolygon','coordinates':[geometry['coordinates']]}
            assert geometry['type']=='MultiPolygon' and geometry['coordinates']
            features[name]={'source_relation_id':row['id'],'ISO3166-2':row['ISO3166-2'],
                'source_admin_level':props.get('admin_level'),'geometry':geometry,
                'geometry_reference_closed':True}
        proc.stdout.close();code=proc.wait()
    assert code==0 and set(features)==set(usable)
    # Bind the newly exported shared city against the already accepted geometry.
    taichung=json.loads((ROOT/'staging/navigation-taichung-city-geometry-v1/geometry.json').read_text())
    assert features['臺中市']['geometry']==taichung
    assert SOURCE.stat()==before
    raw=(json.dumps(features,ensure_ascii=False,separators=(',',':'))+'\n').encode()
    with (OUT/'city-geometries.json').open('xb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
    proof=dict(created_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,
        source=str(SOURCE.relative_to(ROOT)),source_bytes=before.st_size,
        source_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),source_stat_unchanged=True,
        command=command,actual_export_exit_code=code,features_streamed=total,
        complete_city_geometries=len(features),city_names=list(features),
        geometries_sha256=hashlib.sha256(raw).hexdigest(),geometry_bytes=len(raw),
        incomplete_city_held=[{'name':'高雄市','reason':'Existing source closure proof has missing boundary ways; do not infer a complete polygon.'}],
        taichung_matches_previous_geometry=True,full_Taiwan_PBF_reextracted=False,device_IO=False,
        limits=['Geometry preparation only; source-address membership checks are performed by later merge.',
            'City geometry does not prove district, road entrance, house authenticity or route acceptance.',
            '高雄市 is deliberately excluded until a reference-complete boundary is available.'])
    (OUT/'proof.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
    for p in OUT.iterdir():p.chmod(0o444)
    print(json.dumps({'all_assigned_checks_passed':True,'complete_cities':len(features),'geometry_bytes':len(raw),'held_city':'高雄市'},ensure_ascii=False))


if __name__=='__main__':main()
