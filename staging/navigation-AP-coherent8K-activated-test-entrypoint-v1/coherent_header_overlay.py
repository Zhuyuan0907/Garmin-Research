#!/usr/bin/env python3
"""Fixed, read-only coherent8K inverse view for the unchanged closed helper.

No IMG open, path discovery, output, installation or CLI. Future caller owns a
read-only candidate descriptor. Synthetic tests use a separate private engine.
"""
from dataclasses import dataclass
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import types

ROOT=Path(__file__).resolve().parents[2]
CONTROL_STAGE='staging/navigation-AP-coherent-geometry-virtual-controls-v2/'
PACKAGE='staging/navigation-country-address-package-v3/'
CHUNK=1048576
RAW_LIMIT=2097152
PLAIN_LIMIT=4194304
STOCK_BYTES=96739328
STOCK_SHA='864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2'
V3_BYTES=153346048
V3_SHA='1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360'
COHERENT8_SHA='9af1e68e1308bf28deeb7f7d4c7cfab88efd0063c38f4f2df77fcde352990dd3'
EXPANDED4_BYTES=153337856
EXPANDED4_SOURCE_SHA='cc019c5f83c7fce442d0a6b64d8cc216dbc39e1cfa08dfe3f57c757f3bdfbfe9'
EXPANDED4_COHERENT_SHA='8749b2614f0ef4cfb3ac631dd316b35dd3551e3ab97d2ac058f13a89052f50f6'
FIXED_INPUTS={
 CONTROL_STAGE+'prepared-control-plan.json':(5276,'dc636ce504acb7ef3a8b0980d4f91b796f05fc6f07dcbb52aed9d73c6740f655'),
 CONTROL_STAGE+'proof.json':(2853,'dace2db29b3a7d36dc74e775b78501bbe0d9673da77e8f524a05fe7b662e7683'),
 CONTROL_STAGE+'sealed-files.json':(2064,'b3365a9aa57c0181adcbebf80ce3ac3c58463706b9e773280db3433e9eba67da'),
 CONTROL_STAGE+'eightK_end_mirror-header.bin':(512,'b6eafaf1f5a2414fef59da913645ab62d7c9b151ea1e6662b913323bad0e2c5b'),
 CONTROL_STAGE+'expanded_fourK_geometry-header.bin':(512,'63ad71122370c5c5954520f34861c15cccac506ce0692f51856ec0cf4cc162c6'),
 PACKAGE+'native_8k_stock_restore.py':(26503,'43e041518baa72bfbdbc26c627d435749c4bf85adf7882e47ffcfb655c46fe5f'),
 PACKAGE+'restore-layout.json.gz':(879499,'6e1381006e3f56a466c8cdd93134f418eab18ee592cbfd5e57f1a55c2950c0a7'),
 PACKAGE+'actual-stock-restore-binding.json':(292144,'0884c9d705c40d84a84512c691ba124cef419e2cee6d432155e45cee6ed1dd89'),
 'staging/navigation-native-8k-layout-restore-api-v1/sealed-files.json':(4882,'7bef13e816951f51c32e75b2f9e00940b9104f971ba67a7f67d3684e5561af04'),
 'staging/navigation-country-native-lane-restore-v3/sealed-files.json':(3015,'78c11001e46ae749568cb6066b7edc4381412dee309d1fd10947480a111e1048'),
 'staging/navigation-country-native-lane-restore-v3/proof.json':(8102,'bebeb18b29fd934d048111f5a0c05c7dd5a9c93f8d7899159f3fe69b8c5dea9a')}


def require(ok,message):
    if not ok:raise ValueError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def _statpin(s):return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink,s.st_mode)


def _identity(stream):
    s=os.fstat(stream.fileno())
    require(stat.S_ISREG(s.st_mode),'Borrowed source must be a regular file')
    require(getattr(stream,'mode',None)=='rb' and fcntl.fcntl(stream.fileno(),fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDONLY,
            'Borrowed source must be an actual read-only rb descriptor')
    return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink]


def _fixed_read(relative,expected,receipts):
    path=ROOT/relative;before=path.lstat();size,digest=expected
    require(stat.S_ISREG(before.st_mode) and before.st_size==size,'Pinned small input regular/size')
    require(sum(r['bytes'] for r in receipts)+size<=RAW_LIMIT,'Aggregate fixed small raw-input cap')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as f:
        opened=os.fstat(f.fileno());raw=f.read(size+1)
        require(_statpin(opened)==_statpin(before) and f.read(1)==b'','Fixed input inode/EOF')
    after=path.lstat()
    require(len(raw)==size and sha(raw)==digest and _statpin(after)==_statpin(before),'Fixed small content/stat binding')
    receipts.append({'path':relative,'bytes':size,'sha256':digest,
                     'stat_before':[before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns,before.st_nlink],
                     'stat_after':[after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns,after.st_nlink]})
    return raw


@dataclass(frozen=True)
class _OverlaySpec:
    size:int
    corrected_header:bytes
    original_header:bytes
    corrected_full_sha:str
    inverse_full_sha:str


@dataclass(frozen=True)
class FixedInputs:
    helper:object
    stock:object
    old_binding:dict
    spec:_OverlaySpec
    receipts:tuple
    design:dict


def prepare_fixed_inputs():
    """Pinned small evidence only; no IMG open/stat/read and no restoration."""
    receipts=[];raw={p:_fixed_read(p,pin,receipts) for p,pin in FIXED_INPUTS.items()}
    plan=json.loads(raw[CONTROL_STAGE+'prepared-control-plan.json'])
    proof=json.loads(raw[CONTROL_STAGE+'proof.json']);seal=json.loads(raw[CONTROL_STAGE+'sealed-files.json'])
    helperpath=PACKAGE+'native_8k_stock_restore.py'
    helper=types.ModuleType('_closed_ap8k_restore_'+sha(raw[helperpath])[:12]);helper.__file__=str(ROOT/helperpath)
    sys.modules[helper.__name__]=helper
    exec(compile(raw[helperpath],helper.__file__,'exec'),helper.__dict__)
    require(helper.RECIPE_PLAIN_BYTES==1779988 and helper.RECIPE_PLAIN_BYTES<=PLAIN_LIMIT,'Pinned decompressed recipe bound')
    stock=helper._decode_recipe(raw[PACKAGE+'restore-layout.json.gz'],False)
    require(stock.data['original_bytes']==STOCK_BYTES and stock.data['original_sha256']==STOCK_SHA,'Exact stock identity')
    binding=json.loads(raw[PACKAGE+'actual-stock-restore-binding.json'])
    require(binding==helper.prepare_restore_binding(stock,binding['candidate_layout']),'Unchanged strict old binding reconstruction')
    d=binding['candidate_layout']
    require(d['candidate_bytes']==V3_BYTES and d['candidate_sha256']==V3_SHA and d['block_bytes']==8192,
            'Exact old-v3 layout/source identity')
    old_expected=helper._expected_header(bytes.fromhex(stock.data['original_prefix_hex'])[:4096],8192)
    corrected=raw[CONTROL_STAGE+'eightK_end_mirror-header.bin'];original=bytearray(corrected);original[452]=208
    p=plan['eightK_end_mirror'];v=proof['controls']['eightK_end_mirror']
    require(p['bytes']==V3_BYTES and p['sha256']==V3_SHA and v['virtual_full_SHA256']==COHERENT8_SHA
            and p['changed_byte_offsets']==[452] and p['original_byte_values']==[208] and p['new_byte_values']==[224]
            and corrected[452]==224 and sha(original)==p['source_header_sha256'] and bytes(original)==old_expected[:512],
            'Exact corrected512/inverse512/old helper header crossbinding')
    rows={r['path']:r for r in seal['files']}
    require(rows[CONTROL_STAGE+'eightK_end_mirror-header.bin']['sha256']==sha(corrected),'Closed corrected header seal')
    other=plan['expanded_fourK_geometry'];ov=proof['controls']['expanded_fourK_geometry']
    require(other['bytes']==EXPANDED4_BYTES and other['sha256']==EXPANDED4_SOURCE_SHA
            and ov['virtual_full_SHA256']==EXPANDED4_COHERENT_SHA,'Other coherent candidate identity remains explicit')
    previous=json.loads(raw['staging/navigation-country-native-lane-restore-v3/proof.json'])
    require(previous['all_assigned_checks_passed'] and previous['original']['exact_reconstructed_sha256']==STOCK_SHA,
            'Inherited old-v3 actual stock reconstruction evidence')
    s=_OverlaySpec(V3_BYTES,corrected,bytes(original),COHERENT8_SHA,V3_SHA)
    design={'schema':'fixed-coherent-AP-rollback-design/v1','supported_control':'eightK_end_mirror',
            'coherent_candidate':{'bytes':V3_BYTES,'sha256':COHERENT8_SHA,'corrected_header_sha256':sha(corrected)},
            'inverse_virtual_old_v3':{'bytes':V3_BYTES,'sha256':V3_SHA,'original_header_sha256':sha(original),
                                     'unchanged_binding_sha256':FIXED_INPUTS[PACKAGE+'actual-stock-restore-binding.json'][1]},
            'stock':{'bytes':STOCK_BYTES,'sha256':STOCK_SHA,'recipe_sha256':stock.compressed_sha256},
            'expanded_fourK_geometry':{'bytes':EXPANDED4_BYTES,'source_sha256':EXPANDED4_SOURCE_SHA,
                                      'coherent_sha256':EXPANDED4_COHERENT_SHA,'adapter_supported':False,
                                      'required':'Separate actual expanded4K FAT/layout binding and strict supported-profile restore API; old4K geometry/32768-block limits remain.'},
            'old_helper_sha256':FIXED_INPUTS[helperpath][1],
            'decompressed_recipe_bytes':helper.RECIPE_PLAIN_BYTES,'actual_old_stock_hash_inherited_only':True,
            'metadata_header_inverse_overlay_bytes':512,'physically_changed_byte_offsets':[452],
            'direct_old_helper_accepts_corrected_header':False,'checksum_policy_or_UI_or_renderer_rootcause_known':False,
            'real_inverse_stock_hash_validation_executed':False,'installable':False}
    return FixedInputs(helper,stock,binding,s,tuple(receipts),design)


class _InverseHeaderView:
    """Borrowed descriptor: read/seek/tell/fileno only; never closes or writes it."""
    mode='rb'
    def __init__(self,stream,spec,before,receipt):
        self._stream=stream;self._spec=spec;self._before=before;self.receipt=receipt
    def _stable(self):require(_identity(self._stream)==self._before,'Source changed after full verification')
    def fileno(self):self._stable();return self._stream.fileno()
    def tell(self):self._stable();return self._stream.tell()
    def seek(self,offset,whence=0):
        self._stable();require(type(offset) is int and whence in (0,1,2),'Bounded seek arguments')
        target=(0 if whence==0 else self._stream.tell() if whence==1 else self._spec.size)+offset
        require(0<=target<=self._spec.size,'Seek outside verified file');return self._stream.seek(target)
    def read(self,count):
        self._stable();require(type(count) is int and 0<=count<=CHUNK,'Only explicit bounded read lengths supported')
        at=self._stream.tell();raw=self._stream.read(count);self._stable()
        if at<512:
            length=min(len(raw),512-at);raw=self._spec.original_header[at:at+length]+raw[length:]
        self.receipt['inverse_view_bytes_returned']+=len(raw)
        return raw


def _verify_inverse_overlay(stream,spec):
    """Private fixture engine; production wrapper always supplies fixed spec."""
    require(type(spec) is _OverlaySpec and spec.size>=512 and len(spec.original_header)==len(spec.corrected_header)==512,
            'Exact bounded overlay spec')
    require([i for i,(a,b) in enumerate(zip(spec.corrected_header,spec.original_header)) if a!=b]==[452]
            and spec.corrected_header[452]==224 and spec.original_header[452]==208,'Only exact declared byte452 inverse')
    before=_identity(stream);require(before[2]==spec.size,'Exact coherent candidate fullsize')
    stream.seek(0);header=stream.read(512);require(header==spec.corrected_header,'Actual corrected first512 header mismatch')
    actual=hashlib.sha256(header);inverse=hashlib.sha256(spec.original_header);count=512
    while True:
        b=stream.read(min(CHUNK,spec.size-count+1))
        if not b:break
        count+=len(b);require(count<=spec.size,'Candidate longer than exact pinned bytes');actual.update(b);inverse.update(b)
    require(count==spec.size and actual.hexdigest()==spec.corrected_full_sha,'Actual coherent fullSHA/EOF mismatch')
    require(inverse.hexdigest()==spec.inverse_full_sha,'Computed inverse old-v3 fullSHA mismatch')
    require(_identity(stream)==before,'Candidate changed during verification')
    receipt={'actual_corrected_full_sha256':actual.hexdigest(),'computed_inverse_full_sha256':inverse.hexdigest(),
             'candidate_bytes_read':count,'source_stat_before':before,'source_stat_after_full_verify':_identity(stream),
             'inverse_view_bytes_returned':0,'overlay_bytes':512,'changed_offsets':[452],
             'physical_source_write_bytes':0,'borrowed_handle_owned_by_caller':True,'stock_hash_verified':False}
    stream.seek(0)
    return _InverseHeaderView(stream,spec,before,receipt)


def verified_eightk_overlay(candidate_stream,inputs,control='eightK_end_mirror'):
    """Future full actual candidate validation, then a declared inverse view.

    Not invoked on a real map in this preparation. The caller must first bind
    the actual coherent materialization's final stat/path/receipt in its own
    immutable manifest, and close the borrowed descriptor after EOF.
    """
    require(control=='eightK_end_mirror','Expanded4K/unknown control is not supported by this8K adapter')
    require(type(inputs) is FixedInputs and inputs.spec.size==V3_BYTES and inputs.spec.corrected_full_sha==COHERENT8_SHA
            and inputs.spec.inverse_full_sha==V3_SHA,'Fixed production coherent8K identities')
    require(inputs.old_binding==inputs.helper.prepare_restore_binding(inputs.stock,inputs.old_binding['candidate_layout']),
            'Strict old-v3 binding unchanged')
    return _verify_inverse_overlay(candidate_stream,inputs.spec)


def restored_eightk_control_stock_blocks(candidate_stream,inputs,read_receipts=None):
    """Future stream only, no restored IMG output. Consume complete generator."""
    view=verified_eightk_overlay(candidate_stream,inputs)
    yield from inputs.helper.restored_stock_blocks(view,inputs.stock,inputs.old_binding,read_receipts)
    view._stable();view.receipt['stock_hash_verified']=True
