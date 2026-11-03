#!/usr/bin/env python3
"""Confirm only positive184 label/city pointers, seal bounded house evidence."""
import ast
import hashlib
import json
import mmap
import struct
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
BASE=Path(__file__).resolve().parent


def need(value,message):
    if not value:raise ValueError(message)


def sha(path):
    need(path.stat().st_size<2*1024*1024,'Focused small hash only')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path,value):
    with path.open('x') as stream:stream.write(json.dumps(value,ensure_ascii=False,indent=2)+'\n')


def main():
    seal=BASE/'house184-file-seal-v1.json';need(not seal.exists(),'No completed sealer rerun')
    proofpath=BASE/'house184-compiled-NET-inspection-v1.json'
    need(sha(proofpath)=='91aee29c6092e6bef64f6b4c61d434bfae52133a0bac33f628bca6e02a8d4f6d','Frozen actual result')
    proof=json.loads(proofpath.read_text());hits=[r for r in proof['selected_NET_rows'] if r.get('decoded_ranges_including184')]
    need(len(hits)==1,'Positive184 range scope');hit=hits[0]
    need((hit['tile'],hit['net1_offset'])==('70530020',251374) and hit['number_stream_hex']=='4562ac0db4715a88154986e152','Positive original bytes')
    # Allocation helper definitions only; no original MDR checks are executed.
    helper=ROOT/'staging/navigation-mdr-query-v2/query_candidate_mdr_v3.py'
    need(sha(helper)=='c5b4a317cef765e88da2e29f9e4bda80b8bbc9f1221fe1531b31c29e189b665c','Frozen allocation helper')
    tree=ast.parse(helper.read_text());nodes=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in ['need','uint','Image']]
    scope=dict(mmap=mmap,struct=struct,Counter=Counter);exec(compile(ast.Module(body=nodes,type_ignores=[]),str(helper),'exec'),scope)
    imagepath=ROOT/proof['ROOT_candidate']['path'];before=imagepath.stat();image=scope['Image'](imagepath)
    tile=hit['tile'];h=image.read(tile+'.LBL',0,196)
    need(h[2:12]==b'GARMIN LBL' and h[30]==10 and struct.unpack_from('<3H',h,170)==(65001,19,7053|0x8000),'Target actual Unicode LBL identity')
    labelstart,labelbytes=struct.unpack_from('<II',h,21);multiplier=1<<h[29]
    def name(offset):
        pos=offset*multiplier;need(pos<labelbytes,'Target LBL pointer')
        raw=image.read(tile+'.LBL',labelstart+pos,min(256,labelbytes-pos));end=raw.find(b'\0');need(end>=0,'Bounded label terminator')
        return raw[:end].decode('utf-8')
    streetnames=[name(offset) for offset in hit['label_offsets']]
    need(streetnames==['民權路'],'Positive road actual street label')
    city_index=hit['address_fields']['city']['single_local_index'];need(city_index==139,'Actual NET city index139')
    citystart,citybytes,cityitem=struct.unpack_from('<IIH',h,59)
    need(cityitem==5 and 1<=city_index<=citybytes//cityitem,'Target LBL city bounds')
    city=image.read(tile+'.LBL',citystart+(city_index-1)*cityitem,cityitem)
    info=int.from_bytes(city[3:5],'little');need(not info&0x8000 and not info&0x4000,'This positive city is label/region based')
    cityname=name(int.from_bytes(city[:3],'little'));region_index=info&0x3fff
    regionstart,regionbytes,regionitem=struct.unpack_from('<IIH',h,45)
    need(regionitem==5 and 1<=region_index<=regionbytes//regionitem,'Target region bounds')
    region=image.read(tile+'.LBL',regionstart+(region_index-1)*regionitem,regionitem)
    regionname=name(int.from_bytes(region[2:5],'little'));country_index=int.from_bytes(region[:2],'little')
    countrystart,countrybytes,countryitem=struct.unpack_from('<IIH',h,31)
    need(countryitem==3 and 1<=country_index<=countrybytes//countryitem,'Target country bounds')
    country=image.read(tile+'.LBL',countrystart+(country_index-1)*countryitem,countryitem)
    countryname=name(int.from_bytes(country,'little'))
    need(cityname==regionname=='臺中市','Positive actual city and region naming')
    after=imagepath.stat();need((before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'Candidate unchanged')
    positive=dict(checked_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,
        scope='Only new positive184 NET->LBL street/city/region/country pointer confirmation; no house decoder or MDR suite rerun',
        tile=tile,net1_offset=hit['net1_offset'],actual_street_labels=streetnames,actual_city=cityname,
        actual_region=regionname,actual_country=countryname,local_city_index=city_index,
        actual_range=hit['decoded_ranges_including184'],actual_source_to_road_distance_m=hit['nearest_source_geometry_distance_m'],
        logical_IMG_read_bytes_by_extension=dict(image.read_bytes),candidate_modified=False,
        compiled_range_exists=True,Garmin_UI_query_verified=False,source_node_unique_association_verified=False)
    positive_path=BASE/'positive184-street-city-pointer-check-v1.json';write(positive_path,positive)
    contract=dict(checked_utc=positive['checked_utc'],scope='Exact official r4924 source paths + inherited parser/style/build facts',
        conclusion='184號 is parsed as184 and an actual compiled 民權路/臺中市 NET range includes184; source absence, suffix-only parser drop, and missing numeric range are not supported causes for this observed failure.',
        parser=dict(source='reference/HousenumberGenerator.java',lines=[179,197],regex='\\D*(\\d+)\\D?.*',
            accepts_first_integer=True,Chinese_suffix_ignored=True,actual184_result_inherited='staging/navigation-road-coverage-v1/housenumber-parser.txt',
            range_guard_lines=[219,227],min_inclusive=0,max_inclusive=1000000),
        source_paths=[dict(source='reference/HousenumberGenerator.java',lines=[271,283],path='numbers disabled, mkgmap:numbers=false or area2poi can skip nodes'),
            dict(source='reference/HousenumberGenerator.java',lines=[762,785],path='no matched road -> ignored; warning commented out, build summary is not node-completeness evidence'),
            dict(source='reference/HousenumberGenerator.java',lines=[1753,1850],path='nested RoadSegmentIndex filters explicit street via equalsIgnoreCase; nearby matches and angle/name preferences select a road'),
            dict(source='reference/HousenumberGenerator.java',lines=[909,970],path='duplicate handling groups house numbers by CityInfo and street'),
            dict(source='reference/CityInfo.java',lines=[66,93],path='CityInfo equals compares city/country/region exact strings; no internal 台→臺 transliteration'),
            dict(source='reference/RoadDef.java',lines=[211,237],path='NumberPreparer.prepare false -> Invalid housenumbers warning; positive inspected stream exists'),
            dict(source='reference/NETFileReader.java',lines=[203,226],path='standard map reader fetchNumber skips raw stream instead of filling RoadDef numbersList; hasHouseNumbers false from it does not prove absent encoded data')],
        style=dict(path='staging/navigation-repair-v1/style/inc/address',reused_by_v2=True,
            台中市_to_臺中市_rules_present=True,verified_Taichung_boundary_admin4_policy_present=True,
            addr_street_to_mkgmap_street_present=True,addr_housenumber_to_mkgmap_housenumber_present=True,
            finalize_on_house_nodes_polygons_lines_present=True,full_style_bounds_assignment_reconstructed=False),
        build_log=dict(path='staging/navigation-repair-v2/mkgmap-build.log',summary_only=True,
            MapFailedExceptions=0,ExitExceptions=0,per_node184_diagnostic_present=False),
        compiler_nearest_node184_assignment_proved=False,house_drop_specific_codepath_trigger_observed=False,
        native_address_caller_or_UI_success_verified=False,
        physical_control_from_ROOT='User reports stock CN+Address Point together resolve 民權路 with city/house-number detail; exact184 stock address binary record not decoded by this scope.',
        next_direction='Preserve stock NT/AP and supporting HWM/JAI; investigate their actual lookup carrier/format before any original-map update. No standalone rebuild or replacement.',
        minimal_physical_discrimination=['Same selected city/street with house number skipped versus pure184 isolates whether failure depends on numeric filtering.',
            'Compare exact184 with stock CN+Address Point together and note candidate location; stock success is positive control, not a binary-format decoder.'])
    contract_path=BASE/'house184-parser-association-contract-v1.json';write(contract_path,contract)
    paths=[p for p in BASE.rglob('*') if p.is_file() and p!=seal]
    hashes={str(p.relative_to(ROOT)):sha(p) for p in paths}
    write(seal,dict(sealed_utc=positive['checked_utc'],all_completed_FILE_checks_passed=True,
        scope='Bounded source184/NET positive range and actual street/city pointer evidence; not native/UI compatibility',
        sha256=hashes,compiled184_range_observed=True,actual_city_and_street_pointer_confirmed=True,
        observed_number_range=hit['decoded_ranges_including184'],official_decoder_stream_end_diagnostic_preserved=True,
        exact_original_OSM_node_to_compiler_road_association_proved=False,
        Garmin_UI_house_lookup_verified=False,original_NT_AP_carrier_update_verified=False,
        old20MDR_suite_or_full36tile_scan_rerun=False,whole_IMG_backup_digest_repeated=False,
        candidate_or_canonical_or_USB_modified=False,
        inherited_ROOT_candidate_sha256=proof['ROOT_candidate']['declared_sha256'],
        file_hash_count=len(hashes),self_seal_or_later_terminal_receipts_not_in_hash_registry=True))
    print(json.dumps(dict(all_completed_FILE_checks_passed=True,seal=str(seal),seal_sha256=sha(seal),
        positive_pointer_proof=str(positive_path),street=streetnames,city=cityname,range184=hit['decoded_ranges_including184']),ensure_ascii=False),flush=True)


if __name__=='__main__':main()
