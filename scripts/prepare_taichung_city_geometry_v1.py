#!/usr/bin/env python3
"""Reuse the existing admin-only extract for source-address city containment."""
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'staging/navigation-taichung-city-geometry-v1'
SOURCE=ROOT/'staging/navigation-repair-v1/taiwan-admin-selected-from-source.osm.pbf'


def integer_coordinate(value):
    exact=Decimal(str(value))*10_000_000
    if exact!=exact.to_integral_value():raise ValueError('Coordinate exceeds original OSM precision')
    return int(exact)


class Ring:
    """Integer winding-ray crossings with latitude buckets; boundaries included."""
    def __init__(self,coords):
        self.vertices=[(integer_coordinate(x),integer_coordinate(y)) for x,y in coords]
        assert len(self.vertices)>=4 and self.vertices[0]==self.vertices[-1]
        self.buckets={}
        for a,b in zip(self.vertices,self.vertices[1:]):
            for key in range(min(a[1],b[1])//10000,max(a[1],b[1])//10000+1):
                self.buckets.setdefault(key,[]).append((a,b))

    def test(self,x,y):
        inside=False
        for (ax,ay),(bx,by) in self.buckets.get(y//10000,[]):
            dy=by-ay; dx=bx-ax
            cross=(x-ax)*dy-(y-ay)*dx
            if cross==0 and min(ax,bx)<=x<=max(ax,bx) and min(ay,by)<=y<=max(ay,by):return 2
            if (ay>y)!=(by>y):
                if (cross<0 if dy>0 else cross>0):inside=not inside
        return int(inside)


class CityGeometry:
    def __init__(self,geometry):
        assert geometry['type']=='MultiPolygon'
        self.polygons=[[Ring(ring) for ring in polygon] for polygon in geometry['coordinates']]

    def covers(self,latitude,longitude):
        y=integer_coordinate(latitude);x=integer_coordinate(longitude)
        for rings in self.polygons:
            outer=rings[0].test(x,y)
            if outer==2:return True
            if outer==0:continue
            in_hole=False
            for hole in rings[1:]:
                hit=hole.test(x,y)
                if hit==2:return True
                if hit==1:in_hole=True;break
            if not in_hole:return True
        return False


def save(path,value):
    with path.open('x') as f:json.dump(value,f,ensure_ascii=False,separators=(',',':'));f.write('\n');f.flush();os.fsync(f.fileno())
    path.chmod(0o444)


def main():
    assert not OUT.exists();OUT.mkdir()
    original=SOURCE.stat()
    closure=json.loads((ROOT/'staging/navigation-road-coverage-v1/native-root-closure-proof.json').read_text())
    assert next(r for r in closure['roots'] if r['name']=='臺中市')['complete_reference_closed_geometry']
    command=['osmium','export','--geometry-types=polygon','-u','type_id','-f','geojsonseq',str(SOURCE)]
    selected=[];feature_count=0
    with (OUT/'export.stderr.txt').open('x') as err:
        proc=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=err,text=True)
        for line in proc.stdout:
            line=line.lstrip('\x1e').strip()
            if not line:continue
            feature=json.loads(line);feature_count+=1
            props=feature.get('properties',{})
            if props.get('name')=='臺中市' and str(props.get('admin_level'))=='4':selected.append(feature)
        proc.stdout.close();code=proc.wait()
    assert code==0 and len(selected)==1
    feature=selected[0]
    geometry=feature['geometry']
    if geometry['type']=='Polygon':geometry=dict(type='MultiPolygon',coordinates=[geometry['coordinates']])
    city=CityGeometry(geometry)
    # Independent hand-selected topology cases include a hole and boundary.
    square=CityGeometry(dict(type='MultiPolygon',coordinates=[[
        [[0,0],[4,0],[4,4],[0,4],[0,0]],[[1,1],[1,3],[3,3],[3,1],[1,1]]]]))
    assert square.covers('0.5','0.5') and not square.covers('2','2')
    assert square.covers('1','2') and square.covers('0','2') and not square.covers('5','2')
    plan=json.loads((ROOT/'staging/navigation-native-Minquan-append-plan-v1/Minquan-append-only-record-plan-v1.json').read_text())
    checks=[]
    for row in plan['nine_new_source_candidates']:
        coords=row['source_coordinate_strings'];assert city.covers(*coords)
        checks.append(dict(source_id=row['OSM_id'],label=row['label'],coordinates=coords,inside_city=True))
    assert not city.covers('25.0330','121.5654')
    assert not city.covers('22.6273','120.3014')
    after=SOURCE.stat();assert (original.st_size,original.st_mtime_ns)==(after.st_size,after.st_mtime_ns)
    save(OUT/'geometry.json',geometry)
    save(OUT/'proof.json',dict(created_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,
        source=str(SOURCE.relative_to(ROOT)),source_bytes=original.st_size,source_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        source_stat_unchanged=True,command=command,actual_export_exit_code=code,features_streamed=feature_count,
        selected_city_features=len(selected),selected_properties=feature['properties'],
        geometry_sha256=hashlib.sha256((OUT/'geometry.json').read_bytes()).hexdigest(),
        polygon_count=len(geometry['coordinates']),vertices=sum(len(r) for p in geometry['coordinates'] for r in p),
        hand_topology_cases=5,known_source_address_inside_checks=checks,known_other_city_outside_checks=2,
        full_Taiwan_PBF_reextracted=False,device_IO=False,
        scope='Original source coordinate city containment only; not district, road entrance, GPS, navigation or generated-map acceptance.'))
    print(json.dumps(dict(all_assigned_checks_passed=True,polygons=len(geometry['coordinates']),vertices=sum(len(r) for p in geometry['coordinates'] for r in p)),ensure_ascii=False))


if __name__=='__main__':main()
