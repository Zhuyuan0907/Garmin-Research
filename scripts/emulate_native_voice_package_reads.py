#!/usr/bin/env python3
"""Reproduce rejected sparse and corrected contiguous VPM native readback."""
from datetime import datetime,timezone
import json
from pathlib import Path
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from analyze_tts_vpm import parse_image,sha,require
from analyze_native_loader import INIT,IMAGE,DESCRIPTOR
from emulate_native_vpm_filesystem import VpmFilesystem


def main():
    stock=NativeImage();current=json.loads((ROOT/'staging/native-voice-package-fixture/manifest.json').read_text())
    mismatch=json.loads((ROOT/'evidence/firmware-analysis/native-voice-sparse-read-mismatch.json').read_text())
    cases=[]
    for name,path,expected,h in [('rejected_sparse_fixture',mismatch['package'],False,mismatch['package_sha256']),
        ('corrected_contiguous_fixture',current['package'],True,current['package_sha256'])]:
        data=(ROOT/path).read_bytes();require(sha(data)==h,'Fixture changed');files,g=parse_image(data)
        vm=VpmFilesystem(stock,data);require(vm.mount(),'Embedded parser did not mount fixture')
        status,handle=vm.open('dllimg.bin');require(status==0 and handle,'Original binary lookup failed')
        actual=vm.read_file(handle);vm.close(handle);vm.verify_closed_files();binary=files['DLLIMG.BIN']['content']
        require((actual==binary)==expected,'Native readback outcome changed')
        first=None if expected else next(i for i,(a,b) in enumerate(zip(actual,binary)) if a!=b)
        if not expected:
            require(first==0x230800 and sha(actual)==mismatch['native_read_sha256'],'Sparse mismatch was not reproduced')
        require(not vm.visits[INIT] and not any(IMAGE<=a<DESCRIPTOR for a in vm.visits),'Read test executed module')
        cases.append({'name':name,'passed':True,'package':path,'package_sha256':h,
            'native_read_bytes':len(actual),'native_read_sha256':sha(actual),'independent_module_sha256':sha(binary),
            'native_matches_independent_extraction':expected,'first_difference_offset':first,
            'first_difference_native_hex':None if first is None else actual[first:first+16].hex(),
            'first_difference_expected_hex':None if first is None else binary[first:first+16].hex(),
            'closed_file_and_read_output_guards_intact':True,'modified_module_not_executed':True,
            'lower_region_byte_IO_kernel_inventory_are_fixtures':True})
    deps=[Path(__file__),ROOT/'scripts/emulate_native_vpm_filesystem.py',ROOT/'scripts/analyze_tts_vpm.py',
        ROOT/'scripts/analyze_native_sections.py',ROOT/'scripts/analyze_native_voice_acceptance.py']
    out={'updated_utc':datetime.now(timezone.utc).isoformat(),'MAIN_sha256':EXPECTED,'case_count':2,'all_passed':True,
        'cases':cases,'source_sha256':{str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in deps},
        'device_io':False,'modified_module_instructions_executed':False,'device_install_candidate':False,
        'scope':'Original embedded parser/open/read/seek/tell compares full DLL bytes. Independent parser passes both fixtures; native readback rejects sparse DLL extension and matches corrected contiguous allocation. Compact-header/full-format semantics and real outer mounting remain unverified; no global device filesystem defect or installation claim.'}
    path=ROOT/'evidence/firmware-analysis/native-voice-package-read-emulation.json';path.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'evidence':str(path.relative_to(ROOT)),'case_count':2,'all_passed':True}))


if __name__=='__main__':main()
