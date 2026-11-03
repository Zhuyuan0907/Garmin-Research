#!/usr/bin/env python3
"""New segment-boundary and single-record-removal controls, no old suite replay."""
import hashlib
import importlib.util
import json
from pathlib import Path
import random
import sys
import tempfile

sys.dont_write_bytecode=True
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent


def main():
    source=ROOT/'scripts/build_country_native_address_candidate_v2.py'
    spec=importlib.util.spec_from_file_location('new_candidate_v2_splicer_only',source)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    generator=random.Random(176451);cases=[]
    with tempfile.TemporaryDirectory(prefix='new-splice-controls-',dir=HERE) as temporary:
        directory=Path(temporary)
        for index,lengths in enumerate([(126,126),(68,68),(128,128),(0,126,68),(1,2,3,4,5,6,7),
                                         (126,65536*8+11,68),(65536*8+6,126,68),(7,65536*8+4,9)]):
            segments=[];values=[]
            for ordinal,bits in enumerate(lengths):
                value=generator.getrandbits(bits);values.append(value)
                path=directory/f'{index}-{ordinal}.bin';path.write_bytes(value.to_bytes((bits+7)//8,'little'))
                segments.append((path,0,bits))
            combined=0;cursor=0
            for value,bits in zip(values,lengths):combined|=value<<cursor;cursor+=bits
            expected=combined.to_bytes((cursor+7)//8,'little')
            actual=b''.join(module.bit_splice(segments))
            assert actual==expected
            cases.append({'name':'multi_segment_'+str(index),'valid_bit_lengths':list(lengths),'passed':True})
        first=[1,3,5,7];second=[9,11]
        before=directory/'remove-one-record-source.bin';after=directory/'second-source.bin'
        before.write_bytes(b''.join(v.to_bytes(16,'little') for v in first));after.write_bytes(b''.join(v.to_bytes(16,'little') for v in second))
        actual=b''.join(module.bit_splice([(before,0,128),(before,32,256),(after,0,256)]))
        expected=b''.join(v.to_bytes(16,'little') for v in [1,5,7,9,11])
        assert actual==expected
        cases.append({'name':'remove_exactly_one_128bit_record_then_append','passed':True})
        bad=directory/'bad-padding.bin';bad.write_bytes(b'\xff')
        try:list(module.bit_splice([(bad,0,6)]))
        except ValueError:pass
        else:raise AssertionError('Nonzero segment high padding accepted')
        cases.append({'name':'segment_nonzero_padding_rejected','passed':True})
        try:list(module.bit_splice([(bad,0,16)]))
        except ValueError:pass
        else:raise AssertionError('Declared segment overrun accepted')
        cases.append({'name':'segment_bounds_rejected','passed':True})
    proof={'schema':'new-country-candidate-v2-bit-splice-controls/v1','all_assigned_new_controls_passed':True,
           'new_controls':cases,'new_controls_count':len(cases),'source_script_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
           'old_suites_or_native_CPU_executed':False,'device_IO':False,'large_inputs_read':False,
           'reference':'Independent combined integer at declared significant-bit positions; includes 64KiB boundary and empty segments.'}
    with (HERE/'new-bit-splice-controls.json').open('x') as output:json.dump(proof,output,sort_keys=True,separators=(',',':'));output.write('\n')
    print(json.dumps({'all_assigned_new_controls_passed':True,'new_controls_count':len(cases)}))


if __name__=='__main__':main()
