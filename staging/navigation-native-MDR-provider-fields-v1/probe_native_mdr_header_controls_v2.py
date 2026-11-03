#!/usr/bin/env python3
"""Two new bounded negative controls; no stock/parser proof replay."""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode=True
ROOT=Path('/root/garmin'); HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE));sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage,EXPECTED
from probe_native_mdr_header_v1 import invoke


def main():
    source=ROOT/'staging/navigation-mdr-query-v2/query_candidate_mdr_v2.py'
    spec=importlib.util.spec_from_file_location('frozen_img_reader',source)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    image_path=ROOT/'staging/navigation-repair-v2/compiled/gmapsupp.img'
    before=image_path.stat()
    disk=module.Image(image_path)
    names=[name for name in disk.components if name.endswith('.MDR')]
    if len(names)!=1:raise ValueError('Expected selectedcandidate singleMDR')
    name=names[0];first=disk.read(name,0,2);length=struct.unpack('<H',first)[0]
    if length!=568:raise ValueError('Exactcandidate header568 required')
    header=disk.read(name,0,length)
    if struct.unpack_from('<4H',header,21)!=(65001,19,7053,14):
        raise ValueError('Candidate MDR identity mismatch')
    actual_readbytes=dict(disk.read_bytes);disk.data.close();disk.stream.close()
    after=image_path.stat()
    if (before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns):
        raise ValueError('Candidatefile stat changed duringreadonly header read')
    stock=NativeImage();cases=[invoke(stock,header,'actual_v2_MDR_header')]
    altered=bytearray(header);struct.pack_into('<H',altered,21,950)
    cases.append(invoke(stock,bytes(altered),'synthetic_same_v2_header_CP950_only'))
    for case in cases:
        if not case['success'] or case['native_context_offset2b8'] or case['native_context_offset2c0']:
            raise ValueError('Negativecontrol guardexpectation failed')
    evidence=dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        stock_MAIN_sha256=EXPECTED,
        script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        nativeparser_source_sha256=hashlib.sha256((HERE/'probe_native_mdr_header_v1.py').read_bytes()).hexdigest(),
        smallIMGreader_source=dict(path=str(source.relative_to(ROOT)),sha256=hashlib.sha256(source.read_bytes()).hexdigest()),
        actual_candidate_header=dict(path=str(image_path.relative_to(ROOT)),component=name,
            header_bytes=length,hex=header.hex(),sha256=hashlib.sha256(header).hexdigest(),
            IMGcomponent_read_bytes=actual_readbytes,wholeIMGhash_rerun=False,
            stat_signature_unchanged=True),
        cases=cases, all_negative_controls_passed=True,
        synthetic_control_is_not_a_map_candidate=True,
        synthetic_codepage_variant_written_to_device_or_IMG=False,
        stockcases_or_priorproofs_rerun=False,device_IO=False,physical_query_verified=False,
        conclusion='Original native parser leaves mandatory context2B8/2C0 zero for actual568-byte v2 header and CP950-only syntheticmetadata control. OriginalAP772-byte header reaches bothnonzero fields in separatefrozenv1proof. NeitherchangingCPmetadata nor collatorfixsupplies thatmissing descriptor.',
        scope='Header-onlysyntheticfilesystem; originalnativeparser/readwrapper/division. Not IMGdiscovery/query/UI/decryption or installedmodified map.')
    target=HERE/'native-MDR-header-negative-controls-proof-v2.json'
    if target.exists():raise ValueError('Refuse overwrite completedproof')
    target.write_text(json.dumps(evidence,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(output=str(target),passed=True,candidate_MDR_header_bytes=568,
        controls=2,mandatory_native_fields=[[c['native_context_offset2b8'],c['native_context_offset2c0']] for c in cases],physical_query_verified=False)))


if __name__=='__main__':main()
