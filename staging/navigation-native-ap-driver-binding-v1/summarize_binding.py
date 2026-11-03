#!/usr/bin/env python3
"""Validate exact cached instruction/data provenance and freeze this scope."""
from pathlib import Path
import argparse
import hashlib
import json
import os

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def stat(p):
    s=p.stat();return[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def write_new(name,value):
    p=HERE/name;assert not p.exists();p.write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n')


def prepare():
    ledger=json.loads((HERE/'read-ledger.json').read_bytes())
    assert ledger['bytes']==11328 and ledger['bytes']<=65536
    assert stat(ROOT/'evidence/firmware-analysis/main_02bd.bin')==ledger['MAIN_stat']
    byaddr={};captures=[];windows=[]
    for row in ledger['batches']:
        p=ROOT/row['path'];assert sha(p)==row['sha256'];d=json.loads(p.read_bytes())
        assert d['MAIN_stat_before']==d['MAIN_stat_after']==ledger['MAIN_stat']
        assert d['source_sha256']==sha(HERE/'capture_windows.py')
        assert all(w['depth']<=3 for w in d['windows'])
        captures.append(d);windows.extend(d['windows'])
        for w in d['windows']:
            assert hashlib.sha256(bytes.fromhex(w['raw_hex'])).hexdigest()==w['sha256']
            # Name-pool bytes are never interpreted as executable evidence.
            if 'data_only_not_code'in w['name']:continue
            for i in w['instructions']:byaddr[int(i['address'],16)]=i
    assert sum(d['explicit_read_bytes']for d in captures)==ledger['bytes']
    def ins(address,expected):
        i=byaddr[address];assert i['bytes']==expected,(hex(address),i,expected);return i
    def extract(address,count):
        hits=[]
        for w in windows:
            a=int(w['runtime_start'],16);b=bytes.fromhex(w['raw_hex'])
            if a<=address and address+count<=a+len(b):hits.append(b[address-a:address-a+count])
        assert hits and all(h==hits[0]for h in hits)
        return hits[0]
    for a,b in [(0x10fb90,b'MPS\0'),(0x10fb94,b'TRE\0'),(0x10fb98,b'GMP\0'),
                (0x10ffb4,b'LBL\0'),(0x10ffb8,b'RGN\0'),(0x10ffbc,b'NET\0'),
                (0x10ffc0,b'NOD\0'),(0x10ffc4,b'MDR\0'),(0x10ffc8,b'SRT\0')]:
        assert extract(a,len(b))==b
    assert extract(0x1ee460,5)==b'%d%s\0'
    cpu=json.loads((HERE/'slot-getter-cpu-proof.json').read_bytes())
    assert cpu['source_sha256']==sha(HERE/'emulate_slot_getter.py')
    assert cpu['instruction_semantics_or_return_hooks']==[]
    assert all(r['actual']==r['expected']for r in cpu['fixtures'])
    inherited_path=ROOT/'staging/navigation-v3-expanded4k-offline-isolation-v1/proof.json'
    inherited_before=stat(inherited_path);ib=inherited_path.read_bytes();inherited=json.loads(ib)
    assert stat(inherited_path)==inherited_before
    assert inherited['all_six_logical_components_byte_identical_to_v3']is True
    assert inherited['installable']is False and inherited['original_AP_renderer_or_complete_query_executed']is False

    witnesses=[
      dict(name='Component enum supplies actual descriptor and byte position to native fread',
        instructions=[ins(a,b)for a,b in [(0x10fad0,'2948'),(0x10fad2,'0068'),
                                          (0x10fad4,'0161'),(0x10fad6,'069a'),
                                          (0x10fad8,'0399'),(0x10fada,'22f2edfc')]],
        interpretation='Literal F004EC is address of global file-descriptor pointer. Dereference at10FAD2 produces r0=file descriptor; store+10 writes byte position. r1=destination, r2=512 from SP+18. No address-of-handle is passed to3324B8.'),
      dict(name='Wrapper and lower reader receive same descriptor pointer',
        instructions=[ins(a,b)for a,b in [(0x3324ba,'0700'),(0x3324ee,'3c69'),
                                          (0x3324f4,'f968'),(0x332510,'6112'),
                                          (0x332512,'3800'),(0x332514,'f1f504fa')]],
        interpretation='r7=r0 at entry; r4=file+10 byte position. Before BL123920 r1=r4>>9 and r0=r7. Therefore these two functions use the same descriptor; +14 must not be assigned two different object meanings.'),
      dict(name='Native descriptor resolves actual volume record and block geometry fields',
        instructions=[ins(a,b)for a,b in [(0x12392c,'e18c'),(0x12392e,'7423'),
                                          (0x123930,'5948'),(0x123932,'5943'),
                                          (0x123934,'c069'),(0x123936,'4518'),
                                          (0x123940,'a878'),(0x123942,'8140')]],
        interpretation='volume=(*(F7B3DC+1c)) + u16(file+26)*0x74. volume+2 supplies dynamic sectors-per-block shift; volume+4e declared blocks shifted to cache sentinel. The actual runtime volume array is unobserved mutable RAM, not a proved AP instance.'),
      dict(name='Lower sector read boundary and successful cache-index assignment',
        instructions=[ins(a,b)for a,b in [(0x123a66,'e368'),(0x123a68,'2069'),
                                          (0x123a76,'2000'),(0x123a78,'f9f7fefd'),
                                          (0x123a80,'0c98'),(0x123a8c,'6061')]],
        interpretation='11D678 is the next unfollowed sector-read helper. On its successful path123A80 loads requested logical sector and123A8C writes file+14: current cache-sector index, not logical start. No driver callback was substituted or executed.'),
      dict(name='True GMP and MDR literal comparisons are separately bound',
        instructions=[ins(a,b)for a,b in [(0x10fb58,'0fa0'),(0x10fb5a,'39f2ddfb'),
                                          (0x10fc5a,'daa0'),(0x10fc5c,'39f25cfb')]],
        exact_data=[dict(address='0x10fb98',bytes='474d5000',ASCII='GMP'),
                    dict(address='0x10ffc4',bytes='4d445200',ASCII='MDR'),
                    dict(address='0x10fb90',bytes='4d505300',ASCII='MPS')],
        interpretation='ADR10FB58 reaches10FB98 GMP; ADR10FC5A reaches10FFC4 MDR. MPS at10FB90 is a different branch and was explicitly corrected during this scope.'),
    ]
    file_fields=[
      dict(offset='0x00..0x0a',type='8+3 name bytes',status='122FBC parses numeric volume: filename to an uppercase 8.3-shaped descriptor name; input AP physical filename not bound'),
      dict(offset='0x0b',type='u8 flags',status='Wrapper checks bit6;123920 passes bit7 to11D5D0; open ORs two FAT attribute bits. Other semantics held'),
      dict(offset='0x0c',type='u32 byte length',status='2FBA38 copies from FAT-buffer+0c;3324F4 bounds position+request against it'),
      dict(offset='0x10',type='u32 byte position',status='Map enum writes row_index<<9;3324EE reads;33253C updates after copy'),
      dict(offset='0x14',type='u32 cached logical sector or declared-capacity sentinel',status='332504 compares against bytepos>>9;123A80/A8C stores requested sector on success. Initial open uses declaredblocks<<blockshift'),
      dict(offset='0x18',type='u32 initial sector',status='2FB9DE copies volume+6c default; special volume flag copies FAT firstblock<<blockshift;123964 adds requested sector'),
      dict(offset='0x1c',type='u32 unknown cache/bookkeeping field',status='123926 saves it and123A5C later uses it. Lifetime/meaning not resolved'),
      dict(offset='0x20',type='pointer to shared512-byte buffer',status='33252E uses it for data copy;1239CE temporarily indexes FAT blocklist at+20. Do not name it permanently FAT buffer;11D678 buffer lifetime remains untraced'),
      dict(offset='0x24',type='u16 mirror/cached block',status='2FBA1A stores low16 of file+18 before special firstblock shift. Exact eventual role held'),
      dict(offset='0x26',type='u16 volume ordinal',status='122FBC obtains it from numeric path prefix;12392C uses it to index116-byte volume records'),
    ]
    volume_fields=[
      dict(offset='0x00',type='u8 active',status='Open checks nonzero'),
      dict(offset='0x02',type='u8 sectors-per-block shift',status='Used by2FBA2E/4C and123942/3A46; no delta==3 guard in selected consumers'),
      dict(offset='0x45',type='u8 flag',status='Low bit selects special firstblock-based file+18 initialization'),
      dict(offset='0x48',type='u16 sector bytes',status='21195E exports value to output+0'),
      dict(offset='0x4c',type='u16 mask',status='12397C reads for remainder masking; exact producer derivation inherited only'),
      dict(offset='0x4e',type='u16 declared block count',status='Open/reader initial cache sentinel is count<<blockshift'),
      dict(offset='0x60',type='u32 base subtraction term',status='123A62 reads during mapped-sector arithmetic; origin not followed here'),
      dict(offset='0x64',type='u32 division term',status='12396C/974 and123990 use it for native division; producer not followed here'),
      dict(offset='0x6c',type='u32 default starting sector',status='2FB9D8..DE uses for file+18 when open r2=ffff'),
      dict(offset='0x70',type='allocation bitmap pointer',status='1239DE..3A28 path handlesFFFF block; no actual mutation/execution in this scope'),
    ]
    chains=[
      dict(seed='1101EA',calls=[['1102C0','10F8D8',1],['10FADA','3324B8',2],['332514','123920',3]],unfollowed_next=['123A78→11D678','1239B6→123F6C','12394C→11D5D0']),
      dict(seed='1101EA',calls=[['110508','2FBA70',1],['2FBA84','2FB988',2],['2FB99E','122FBC',3]],
           short_path_note='110508 is in captured seed continuation. The longer1102C0→10F8D8→2FBA70 route would make122FBC depth4 and was not used to justify its follow.',unfollowed_next=['122FDC→2BF698']),
      dict(seed='2CABBC',calls=[['2CABFE','2CAB14',1]],status='Registry/property iteration, not a renderer'),
      dict(seed='2CA82C',calls=[['2CA8AA','2CA670',1]],status='Registry/property prepare/update, not a renderer'),
    ]
    names=[dict(address=hex(a),raw_hex=extract(a,4).hex(),ASCII=extract(a,3).decode('ascii'))
           for a in [0x10fb90,0x10fb94,0x10fb98,0x10ffb4,0x10ffb8,0x10ffbc,0x10ffc0,0x10ffc4,0x10ffc8]]
    proof=dict(schema='bounded-native-map-record-file-driver-binding/v1',
       outcome='Concrete native component-enumeration→descriptor→volume/sector-reader bridge; AP physical instance and driver vtable/render consumer unresolved at depth boundary',
       MAIN_SHA_inherited=captures[0]['MAIN_SHA_inherited'],MAIN_stat=ledger['MAIN_stat'],
       startup_copy_translation_used=True,conditional_runtime44_54_not_needed=True,
       all_capture_sha_and_stats_passed=True,code_and_literal_read_bytes=ledger['bytes'],read_operations=ledger['operations'],
       code_read_budget=65536,maximum_followed_callee_depth=3,call_paths=chains,
       witnesses=witnesses,exact_component_name_literals=names,
       file_descriptor_fields=file_fields,volume_record_stride=116,volume_fields=volume_fields,
       shared_global=dict(runtime='0xf7b3dc',volume_pointer_offset='0x1c',device_count_offset='0x20',actual_runtime_contents_not_read=True),
       ABI=dict(open_wrapper='2FBA70(r0=address_of_file_pointer,r1=numeric-volume:8.3 path,r2=startselector);2FB988 dereferences*[r0]',
                fread='3324B8(r0=file descriptor,r1=destination,r2=byte_count)',
                logical_sector_resolver='123920(r0=same file descriptor,r1=requested bytepos>>9)',
                next_sector_reader='11D678(r0=same file descriptor,r1=mapped sector,r2=read/extent-control flag): not yet traced',
                fixed_callback='10F146 BLXr6 with prior PC literal10C605 is a selected fixed helper, not proof of physical IMG driver vtable'),
       original_slot_getter_fixture=dict(proof='slot-getter-cpu-proof.json',sha256=sha(HERE/'slot-getter-cpu-proof.json'),
                fixture_group_count=1,fixtures=4,all_passed=True,CPU='ARM1176',no_semantic_or_return_hooks=True,
                scope='Original FE67E byte getter only; does not instantiate an AP volume or driver'),
       inherited_offline_4K_isolation=dict(path=str(inherited_path.relative_to(ROOT)),bytes=len(ib),sha256=hashlib.sha256(ib).hexdigest(),
                immutable_stat=inherited_before,all_six_logical_components_equal=True,
                IMG_was_not_opened_by_this_scope=True,installable=False,
                checksum_CHS_renderer_unknown_preserved=True),
       scope_corrections=[
         'MPS10FB90 was initially verbally mislabeled MDR; final bytes bind MDR at10FFC4 separately.',
         '3324B8 +14 initially verbally called logicalstart; original same-pointer setup and successful STR prove current cache-sector. +18 is initialsector.',
         'Capture labels are search hypotheses. The label map_backend_kind_getter actually exports volume information, and driver_binding_open_leaf122FBC is an8.3 parser. No label name is semantic evidence.',
         'component_name_pool_data_only_not_code disassembly/literal guesses are excluded from executable evidence, while all its explicit reads remain counted.',
       ],
       remaining_questions=[
         'True physical AP filename/device index→active volume instance registration and device operations/vtable callback selection.',
         '11D678 actual low-level reader/buffer mapping and its device callback;123F6C blocklist refresh;11D5D0 status gate.',
         'Actual native logicaloffset/cross-block read comparison among original4K, v3_8K, expanded4K. Requires separate next scope/input authorization.',
         'How native component records reach NT/drawing consumer and its additional admission/geometry checks.',
       ],
       AP_physical_file_instance_bound=False,driver_vtable_bound=False,actual_IMG_metadata_or_GMP_read=False,
       actual_map_admission_or_drawing_tested=False,hard_8K_limit_proved=False,hard_128MiB_limit_proved=False,
       old_closed_CPU_suite_executed=False,no_whole_MAIN_IMG_hash=True,no_IMG_USB_device_access=True,
       no_original_or_sealed_inputs_modified=True,all_handles_closed=True,
       all_assigned_finite_checks_passed=True,bounded_gap_preserved=True,full_address_update_complete=False)
    write_new('proof.json',proof)
    receipts=dict(schema='native-driver-binding-actual-tool-receipts/v1',
      captures=[dict(tag=t,chunk=c,exit_code=0,source='capture_windows.py',artifact='windows-'+t+'.json')
                for t,c in [('seeds','264b28'),('first','c026af'),('second','6b3746'),
                            ('dispatch','4eda04'),('finalcode','a594ef'),('binding','f029ce'),
                            ('nameformatter','a4ded7')]],
      CPU=dict(chunk='5d8e34',exit_code=0,source='emulate_slot_getter.py',fixtures=4,
               original_instructions=True,semantic_or_return_hooks=[],IMG_or_MAIN_not_opened=True),
      local_cached_instruction_reads=['c1ec1f','69b5e0','f57e3d','9ecb21','bb9e8d','6dc2d9','4358c8','29efe4','6b55a7'],
      original_bytes_replayed_from_cache_only=True,old_main_or_CPU_suite_not_run=True,
      tiny_root_isolation_proof_read=dict(chunk='dfe236',exit_code=0,bytes=4214),
      original_code_and_literal_bytes=ledger['bytes'],explicit_read_operations=ledger['operations'],
      no_software_performance_benchmark=True,all_handles_closed=True)
    write_new('actual-tool-receipts.json',receipts)
    handoff='''NEW bounded native AP driver binding scope 已停止；不改前sealed scope。

真 component enum chain：1101EA→10F8D8→3324B8→123920，深度3。
10FAD0 2948(LDR literalF004EC)、10FAD2 0068(deref)、10FAD4 0161(storefile+10)
再10FADA22f2edfc(BL3324B8)讀512B。3324BA0700(r7=r0)、3325106112(pos>>9)、
3325123800(r0=r7)、332514f1f504fa(BL123920)：同一個file descriptor。
open2FBA70收到&file_pointer；fread3324B8收到file_pointer，兩者勿混為同一層handle ABI。

file+0c length、+10 bytepos、+14 current cached logicalsector/sentinel、+18 initialsector、
+20 shared512Bbuffer、+26 volumeordinal；+1c含義仍held。volume=globalF7B3DC+1c所指陣列
+u16(file+26)*0x74，+2是sectors/block shift、+4e declaredblocks；真正activeRAM未讀。
相同buffer會暫作FAT blocklist再供wrapper拷sectordata，不能永久稱FATbuffer。

真文字：MPS10FB90、TRE10FB94、GMP10FB98、LBL10FFB4、RGN10FFB8、NET10FFBC、
NOD10FFC0、MDR10FFC4、SRT10FFC8。GMP比較10FB58/5A；MDR比較10FC5A/5C。
MPS→MDR口頭誤標與+14誤称已在proof保留更正，不以disasm假設名稱當原始證據。
MDR分支還見ctx+4ee0+10 count<10、13byte entries/namecopy；不是全平台容量上限。

短路徑110508→2FBA70→2FB988→122FBC是另一深度3：122FBC只解析numeric volume:
8.3 filename，並非driver vtable。更長1102C0→10F8D8路徑不拿來偷算depth。
只讀11328B原MAIN code/literals、<=64KiB，全部用sealed startupcopy metadata翻runtime。
未抽全MAIN、重strings/fullhash、未讀IMG；literaldata的偽disasm/calls完全排除證據。

原FE67E getter實際ARM1176/Thumb單fixturegroup四案通過（slot2→63、98→64、
99/FFFFFFFF→FF；guard案table未mapped）。沒有return或指令語意hook；只read-only observer。
這只驗bytegetter，不證明driver、8K/128MiB、AP admission、UI或畫圖。

最小新scope入口：11D678（123A78f9f7fefd BL），原r0=file、r1=mappedsector、
r2=readcontrol；另123F6C blocklist refresh及11D5D0 status。需沿device operations/vtable
拿到真callback，才能在新授權scope把原4K/v3_8K/root expanded4K同logicaloffset、跨block
實际metadata/GMP bytes送入原reader。當前沒有该callback/AP physicalinstance绑定，
也未啟新IMG讀取。Root4K實驗6component相同僅引用4214B proof，不把其rendererunknown改成功。

全handles已closed；不碰USB/裝置/ZIP/report/canonical/firmware。全台更新未完成。
'''
    (HERE/'HANDOFF.txt').write_text(handoff)
    print(json.dumps(dict(read_bytes=ledger['bytes'],depth=3,getter_cases=4,
                          proof_sha256=sha(HERE/'proof.json'),driver_vtable_bound=False,handles_closed=True)))


def seal():
    assert not(HERE/'sealed-files.json').exists()
    rows=[]
    for p in sorted(HERE.iterdir()):
        assert p.is_file()
        os.chmod(p,0o444);rows.append(dict(path=str(p.relative_to(ROOT)),bytes=p.stat().st_size,sha256=sha(p),mode='0444'))
    write_new('sealed-files.json',dict(schema='native-driver-binding-scope-seal/v1',files=rows,
         all_assigned_finite_checks_passed=True,AP_renderer_and_driver_binding_still_unresolved=True,
         original_getter_fixture_only=True,no_IMG_or_device_reads=True,all_handles_closed=True))
    os.chmod(HERE/'sealed-files.json',0o444)
    print(json.dumps(dict(files=len(rows)+1,seal_sha256=sha(HERE/'sealed-files.json'),
                          proof_sha256=sha(HERE/'proof.json'),handles_closed=True)))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--seal',action='store_true');a=p.parse_args()
    seal()if a.seal else prepare()
