#!/usr/bin/env python3
"""New small synthetic allocation/bit-window controls. No actual IMG is opened."""
from pathlib import Path
import hashlib
import importlib.util
import io
import json
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('independent',HERE/'review_actual_v3.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
checks=[]


def check(name,callback,reject=False):
    if reject:
        try:callback()
        except (ValueError,UnicodeError,KeyError):checks.append(dict(name=name,passed=True,rejected=True));return
        raise AssertionError(name+' did not reject')
    callback();checks.append(dict(name=name,passed=True,rejected=False))


def fixture():
    raw=bytearray(8*8192);raw[16:23]=b'DSKIMG\0';raw[65:72]=b'GARMIN\0';raw[510:512]=b'\x55\xaa'
    raw[64]=8;raw[97:99]=bytes([9,4]);raw[3]=165
    struct.pack_into('<H',raw,99,32768);struct.pack_into('<I',raw,458,524288)
    def row(at,name,size,flag,blocks):
        raw[at]=1;raw[at+1:at+12]=name;struct.pack_into('<I',raw,at+12,size);raw[at+16]=flag
        struct.pack_into('<240H',raw,at+32,*(blocks+[65535]*(240-len(blocks))))
    row(4096,b' '*11,8192,3,[0]);block=1;payloads={}
    for i,name in enumerate(m.NAMES):
        base,extension=name.split('.');length=8201 if i==0 else 37+i
        content=bytes((j+i)%251 for j in range(length));n=(length+8191)//8192
        row(4608+i*512,base.encode().ljust(8,b' ')+extension.encode(),length,0,list(range(block,block+n)))
        raw[block*8192:block*8192+length]=content;block+=n;payloads[name]=content
    return raw,payloads


base,payloads=fixture()


def mapping():
    image=m.Image8K(io.BytesIO(base))
    assert image.header[3]==165 and image.directory_end==8192 and image.capacity==268435456
    for name,content in payloads.items():assert image.logical(name,0,len(content),'synthetic control')==content
    assert image.logical(m.NAMES[0],8187,14,'synthetic crossblock')==payloads[m.NAMES[0]][8187:8201]


check('exact six components with unknown header byte and cross8192 logical read',mapping)


def mutated(at,value):
    raw=bytearray(base);raw[at:at+len(value)]=value;return lambda:m.Image8K(io.BytesIO(raw))


for name,at,value in [
    ('XOR profile',0,b'\x01'),('block exponent',98,b'\x03'),('capacity coherence',458,struct.pack('<I',524287)),
    ('root part',4113,b'\x01\0'),('root extent alignment',4108,struct.pack('<I',8193)),
    ('root allocation identity',4128,struct.pack('<H',1)),('duplicate physical component allocation',5152,struct.pack('<H',1)),
    ('out of EOF physical block',4640,struct.pack('<H',8)),('block after sentinel',4646,struct.pack('<H',2)),
    ('duplicate component path',5121,b'00004171MD2'),('unordered continuation part',5137,b'\x01\0'),
    ('logical-size allocation mismatch',4620,struct.pack('<I',8192)),('nonzero unused directory row',7681,b'\x01'),
    ('noncanonical component path',4609,b'a'),('second root component row',5136,b'\x03')]:
    check(name,mutated(at,value),True)
check('whole input block alignment',lambda:m.Image8K(io.BytesIO(base[:-1])),True)
check('orphan trailing physical block',lambda:m.Image8K(io.BytesIO(base+bytes(8192))),True)
image=m.Image8K(io.BytesIO(base))
check('logical component EOF guard',lambda:image.logical(m.NAMES[0],8200,2,'synthetic guard'),True)
check('unknown path guard',lambda:image.logical('NOFILE.MDR',0,1,'synthetic guard'),True)
check('physical bounded read guard',lambda:image.physical(0,1000001,'synthetic guard'),True)


def table(level):
    widths,refs,stride=m.PROFILES[level-1];return dict(widths=widths,refs=refs,stride=stride)


def wide_parent():
    value=1|(12345<<1)|(5000000<<20)|(93<<43)|(4<<55)|(0x123456<<64)|(0xabcdef<<88)
    r=m.decode(value,table(3))
    assert (r['first_child'],r['child_count'],r['raw_flags'],r['primary_ref'],r['raw_location_a'],r['raw_location_b'])==(5000000,93,4,12345,0x123456,0xabcdef)
    assert value.bit_length()<=112


check('L3 true23bit first child above22bit and independent explicit offsets',wide_parent)


def shifted_level5():
    values=[1|(((1<<19)-1)<<1)|((i+1)<<20)|((100+i)<<39)|(9<<60)|(13<<69)|((0x234567+i)<<78)|((0x345678+i)<<102)for i in range(4)]
    for start in [0,2,4,6]:
        word=sum(v<<(start+i*126)for i,v in enumerate(values));raw=word.to_bytes((start+4*126+7)//8,'little')
        for i,value in enumerate(values):
            actual=m.extract(raw,start+i*126,126);assert actual==value
            r=m.decode(actual,table(5));assert (r['raw_flags'],r['next_level'],r['secondary_ref'],r['first_child'],r['child_count'])==(13,5,None,100+i,9)


check('L5 126bit shifts0/2/4/6 retain unknown13 without following it',shifted_level5)


def shifted_level6():
    values=[1|((i+5)<<1)|((0x123456+i)<<20)|((0xabcdef+i)<<44)for i in range(4)]
    for start in [0,4]:
        word=sum(v<<(start+i*68)for i,v in enumerate(values));raw=word.to_bytes((start+4*68+7)//8,'little')
        for i,value in enumerate(values):
            r=m.decode(m.extract(raw,start+i*68,68),table(6));assert r['primary_ref']==i+5 and r['first_child']==r['child_count']==0


check('L6 68bit shift0/4 coordinates and leaf fields',shifted_level6)
check('bit EOF without lookahead expansion',lambda:m.extract(bytes(16),3,126),True)
check('negative bit offset',lambda:m.extract(bytes(16),-1,8),True)
bad=table(5);bad['stride']=128
check('descriptor stride mismatch',lambda:m.decode(0,bad),True)
result=dict(schema='new-independent-v3-reader-small-controls/v1',all_assigned_checks_passed=True,
    source_sha256=hashlib.sha256((HERE/'review_actual_v3.py').read_bytes()).hexdigest(),
    test_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    controls=checks,control_count=len(checks),synthetic_input_only=True,actual_IMG_CPU_device_or_old_suite_not_read_or_run=True)
m.saved('new-reader-controls.json',result)
print(json.dumps(dict(all_assigned_checks_passed=True,control_count=len(checks),source_sha256=result['source_sha256'])),flush=True)
