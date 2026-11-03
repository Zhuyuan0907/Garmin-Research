#!/usr/bin/env python3
"""One new synthetic raw13 record control; no old or geometry suite replay."""
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import merge_policy


def main():
    base=merge_policy.country_helpers()
    # Real L5 field position, arbitrary synthetic record significant bits.
    raw13=(13<<69)|(7<<39)|(3<<60)|(111222<<78)|(555666<<102)|(80<<20)|1
    other=(99<<20)|1
    original=[raw13,other]
    new=[{'number':2,'label':'2號','value':(50<<20)|1}]
    result=base.merge_numeric(original,['1之3號','8號'],new)
    assert result[0]==[raw13,new[0]['value'],other]
    retained=[value for index,value in enumerate(result[0]) if index not in set(result[1].values())]
    assert retained==original and (retained[0]>>69)&511==13
    assert (retained[0]>>39)&((1<<21)-1)==7 and (retained[0]>>60)&511==3
    assert (retained[0]>>78)&((1<<24)-1)==111222 and (retained[0]>>102)&((1<<24)-1)==555666
    proof={'schema':'kaohsiung-new-raw13-preservation-control/v1','all_new_controls_passed':True,
           'synthetic_existing_L5_raw13_significant_bits_unchanged':True,
           'synthetic_subnumber_relative_order_childrefs_and_coords_unchanged':True,
           'actual_original_raw13_device_record_test':False,'old_country_suite_rerun':False,'device_IO':False,
           'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    with (HERE/'raw13-control-proof.json').open('x') as output:
        json.dump(proof,output,ensure_ascii=False,sort_keys=True,separators=(',',':'));output.write('\n')
    print(json.dumps({'all_new_controls_passed':True,'synthetic_raw13_unchanged':True,'actual_original_raw13_checked':False}))


if __name__=='__main__':main()
