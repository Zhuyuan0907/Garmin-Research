#!/usr/bin/env python3
"""Only new Beitun wrapper/identity controls, no prior geometry suite replay."""
from datetime import datetime,timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent


def main():
    spec=importlib.util.spec_from_file_location('new_Beitun_membership_API',HERE/'beitun_membership.py')
    api=importlib.util.module_from_spec(spec);spec.loader.exec_module(api)
    membership=api.BeitunMembership();cases=[]
    c=json.loads((ROOT/'staging/navigation-native-new-street-source-example-v1/candidate.json').read_bytes())
    source=membership.assess_source_point(c['city'],c['district'],*c['sourcepoint'])
    raw=membership.assess_raw24(c['city'],c['district'],*c['raw24'])
    assert source['eligible'] and raw['eligible']
    cases.append(dict(name='sole_actual_source_and_exact_raw24_same_Beitun_district',passed=True,
                      source_ids=c['source_ids'],sourcepoint=source,raw24=raw))
    result=membership.assess_source_point('新北市','北屯區',*c['sourcepoint']);assert result['status']=='unsupported_native_city'
    cases.append(dict(name='wrong_city_does_not_reassign_source_point',passed=True,result=result))
    result=membership.assess_raw24('台中市','西屯區',*c['raw24']);assert result['status']=='unsupported_native_district'
    cases.append(dict(name='wrong_district_does_not_infer_name_alias',passed=True,result=result))
    result=membership.assess_source_point('台中市','北屯區','25.0330','121.5654');assert not result['eligible']
    cases.append(dict(name='known_Taipei_point_outside_Beitun',passed=True,result=result))
    result=membership.assess_source_point('台中市','北屯區','24.18822441','120.7079937')
    assert result['status']=='source_coordinate_exceeds_OSM_precision'
    cases.append(dict(name='excess_source_precision_not_rounded',passed=True,result=result))
    result=membership.assess_raw24('台中市','北屯區',True,c['raw24'][1]);assert result['status']=='invalid_explicit_raw24_integers'
    cases.append(dict(name='boolean_raw24_not_accepted_as_point',passed=True,result=result))
    with tempfile.TemporaryDirectory(prefix='corrupt-geometry-control-',dir=HERE) as tmp:
        directory=Path(tmp)
        for name in api.PINS:(directory/name).write_bytes((HERE/name).read_bytes())
        rawfile=directory/'geometry.json';value=bytearray(rawfile.read_bytes());value[-2]^=1;rawfile.write_bytes(value)
        error=None
        try:api.BeitunMembership(directory)
        except ValueError as ex:error=str(ex)
        assert error and 'Unverified membership input' in error
        cases.append(dict(name='changed_geometry_bytes_refused_before_membership',passed=True,refusal=error,
                          only_temporary_fixture_modified=True))
    proof=dict(schema='new-Beitun-source-membership-wrapper-controls/v1',created_utc=datetime.now(timezone.utc).isoformat(),
        all_assigned_new_wrapper_checks_passed=True,controls=cases,control_count=len(cases),
        source_API_sha256=hashlib.sha256((HERE/'beitun_membership.py').read_bytes()).hexdigest(),
        source_script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        previous_city_KH_flat_geometry_or_CPU_cases_executed=False,
        original_PBF_not_opened_by_wrapper_controls=True,temporary_fixture_removed=True,
        official_street_alias_or_native_UI_proved=False,device_IO=False,install_candidate=False)
    raw=(json.dumps(proof,ensure_ascii=False,indent=2)+'\n').encode()
    with (HERE/'new-membership-control-proof.json').open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    print(json.dumps(dict(all_assigned_new_wrapper_checks_passed=True,controls=len(cases),
        proof_sha256=hashlib.sha256(raw).hexdigest(),source_API_sha256=proof['source_API_sha256'],
        source_and_raw24_same_district=True),ensure_ascii=False),flush=True)


if __name__=='__main__':main()
