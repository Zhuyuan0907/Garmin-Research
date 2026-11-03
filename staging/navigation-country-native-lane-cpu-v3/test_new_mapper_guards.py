#!/usr/bin/env python3
"""NEW 57KiB independent AP8K fixture/binding controls; no real IMG/CPU."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent;ROOT = HERE.parents[1]
sys.path.insert(0,str(HERE))
from strict_ap8k_reader import Candidate8K,NAMES,stat


def check(ok,message):
    if not ok:
        raise AssertionError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def row(name,size,blocks,root=False):
    raw = bytearray(512);raw[0] = 1
    a,b = name.split('.');raw[1:9] = a.encode().ljust(8,b' ');raw[9:12] = b.encode().ljust(3,b' ')
    struct.pack_into('<I',raw,12,size);raw[16] = 3 if root else 0
    struct.pack_into('<240H',raw,32,*(blocks+[65535]*(240-len(blocks))))
    return bytes(raw)


def fixture():
    source = json.loads((ROOT/'staging/navigation-native-current-profile-cow-writer-v1/actual-current-source-layout.json').read_text())
    header = bytearray.fromhex(source['header_hex']);header[15] = 0;header[98] = 4
    struct.pack_into('<H',header,24,32);struct.pack_into('<H',header,95,32);struct.pack_into('<I',header,458,524288)
    raw = bytearray(7*8192);raw[:512] = header;raw[4096:4608] = row('.',8192,[0],True)
    components = []
    for i,name in enumerate(NAMES):
        r = row(name,17,[i+1]);at = 4608+i*512;raw[at:at+512] = r
        raw[(i+1)*8192:(i+1)*8192+17] = bytes([13+i])*17
        components.append({'name':name,'size':17,'blocks':[i+1],
                           'parts':[{'part':0,'size':17,'blocks':[i+1],'row_hex':r.hex()}]})
    layout = {'schema':'garmin-native-ap-explicit8k-cow-layout/v1','profile':'AP8K-9+4-32768blocks-524288sectors',
              'block_bytes':8192,'candidate_bytes':len(raw),'metadata_bytes':8192,
              'metadata_prefix_sha256':sha(raw[:8192]),'components':components}
    return bytes(raw),layout


def main():
    result_path = HERE/'new-mapper-guards-proof.json';check(not result_path.exists(),'Refuse overwrite controls')
    raw,layout = fixture();guards = []
    with tempfile.TemporaryDirectory(prefix='tiny-mapper-',dir=HERE) as temp:
        p = Path(temp)/'fixture.img';p.write_bytes(raw);p.chmod(0o444)
        with_reader = Candidate8K(p,layout,stat(p))
        receipt,data = with_reader.read('I053061A.GMP',2,11,'independent_tiny_FAT_offset')
        check(data == bytes([16])*11 and receipt['FAT_mapping'][0]['physical_offset'] == 4*8192+2,'Independent logical allocation')
        with_reader.close()
        def reject(name,rawbytes=None,descriptor=None,expected_stat=None,readonly=True):
            p.chmod(0o644);p.write_bytes(raw if rawbytes is None else rawbytes)
            if readonly:
                p.chmod(0o444)
            try:
                reader = Candidate8K(p,layout if descriptor is None else descriptor,stat(p) if expected_stat is None else expected_stat)
            except ValueError as e:
                guards.append({'case':name,'rejected':True,'reason':str(e)})
            else:
                reader.close();raise AssertionError('No rejection:'+name)
        reject('writable_uncompleted_input',readonly=False)
        reject('source_stat_mismatch',expected_stat=[0,0,0,0,0])
        d = copy.deepcopy(layout);d['block_bytes'] = 4096;reject('wrong_block_descriptor',descriptor=d)
        d = copy.deepcopy(layout);d['profile'] = 'stock4K';reject('foreign_profile',descriptor=d)
        b = bytearray(raw);b[98] = 3;reject('wrong_actual_exponent',rawbytes=bytes(b))
        b = bytearray(raw);b[15] = 1;reject('wrong_header_checksum_byte15_contract',rawbytes=bytes(b))
        b = bytearray(raw);b[458:462] = struct.pack('<I',262144);reject('wrong_capacity_sectors',rawbytes=bytes(b))
        b = bytearray(raw);b[512] = 1;reject('metadata_hash_mismatch',rawbytes=bytes(b))
        b = bytearray(raw);b[4608+32:4608+34] = b'\0\0'
        d = copy.deepcopy(layout);d['metadata_prefix_sha256'] = sha(b[:8192]);reject('component_root_alias',rawbytes=bytes(b),descriptor=d)
        b = bytearray(raw);b[4608+32:4608+34] = b'\xfe\xff'
        d = copy.deepcopy(layout);d['metadata_prefix_sha256'] = sha(b[:8192]);reject('FAT_outside_actual_EOF',rawbytes=bytes(b),descriptor=d)
        b = bytearray(raw);b[4608+34:4608+36] = b'\x02\0'
        d = copy.deepcopy(layout);d['metadata_prefix_sha256'] = sha(b[:8192]);reject('allocated_block_after_sentinel_or_alias',rawbytes=bytes(b),descriptor=d)
        d = copy.deepcopy(layout);d['components'][0]['parts'][0]['row_hex'] = '00'*512;reject('descriptor_actual_FAT_row_mismatch',descriptor=d)
    proof = {'schema':'new-finite-v3-AP8K-mapper-guards/v1','all_assigned_controls_passed':True,
             'positive_cases':1,'rejecting_cases':len(guards),'guards':guards,'independent_fixture_bytes':len(raw),
             'mapper_sha256':sha((HERE/'strict_ap8k_reader.py').read_bytes()),'test_source_sha256':sha(Path(__file__).read_bytes()),
             'actual_candidate_IMG_opened':False,'native_CPU_executed':False,'old_suites_or_cases_run':False,'device_IO':False}
    with result_path.open('x') as f:
        json.dump(proof,f,indent=2);f.write('\n')
    print(json.dumps({'passed':True,'positive_cases':1,'rejecting_cases':len(guards),'fixture_bytes':len(raw)}))


if __name__ == '__main__':
    main()
