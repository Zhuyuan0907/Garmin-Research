#!/usr/bin/env python3
"""Normal map-data COW + 4K virtual stream, finite captures and inverse. No IMG file."""
import sys
sys.dont_write_bytecode = True
import hashlib
import importlib.util
import json
import os
import struct
import traceback
from pathlib import Path

from stream_support_v1 import (need, BudgetFile, InverseMDR, CaptureHashSink,
                              SparseVirtualHandle, diff_runs)
import captured_ap_reader_v1 as reader

ROOT = Path('/root/garmin')
OUT = Path(__file__).resolve().parent
CAP = ROOT/'staging/navigation-minimal-lane-render-isolation-plan-v1'
V2 = ROOT/'staging/navigation-country-native-candidate-v2/gmapprom1.img'
V2_SHA = '925a515b668f3878ef0acea3e1c79188c15216f1af7f039c0e426942907ebefb'
MDR_SHA = '8cd9c672aa96b224ffa9ca2a1beb1e18149c0c470cfec69a0ef908b6df901fec'
NORMAL_PINS = []
EXPECTED = {
 '00004171.MD2':'0ede52caef0319594e0380ceb29b4a33bfcb9dbe530d18163aad75d74b64df67',
 '00004171.MDR':MDR_SHA,
 '00004171.SRT':'54505d7f3a30b1848f0d967367974f229df74978dae63ab664716f79094713fd',
 'I053061A.GMP':'92d4a1aa7cf84ff17b092d74302fb4d432691bd6cd563ba8da4d7ed51f8d73bd',
 'I053061A.SRT':'4046e27464f957ea71220b270f78e2b9ecacf9fd92bf92f71040626e26d00be8',
 'MAPSOURC.MPS':'d098b0ee8914924fa9e059c4877291c1a521cd5141d5e6803b06f8ef271c7767'}

def sha(b): return hashlib.sha256(b).hexdigest()
def stat(p):
    s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def save(name,value):
    b=(json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode()
    need(len(b)<=65536,'Small JSON output bound')
    (OUT/name).write_bytes(b)
def pin(p,digest,as_json=True):
    before=stat(p);b=p.read_bytes()
    need(sha(b)==digest and stat(p)==before,'Input pin/stat changed: '+str(p))
    NORMAL_PINS.append({'path':str(p.relative_to(ROOT)),'bytes':len(b),'SHA256':digest,
                        'stat_before':before,'stat_after':stat(p)})
    return json.loads(b) if as_json else b
def module(name,p,digest):
    pin(p,digest,False)
    spec=importlib.util.spec_from_file_location(name,p)
    m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
def compact_layout(p):
    return {k:v for k,v in p.items() if k!='allocations'}|{'allocations':{
        k:{'first_block':v[0],'count':len(v),'last_block':v[-1]} for k,v in p['allocations'].items()}}
def logical(image,name,at,n):
    return b''.join(image.iter_component(name,offset=at,length=n))
def metadata(base,image,p):
    b=bytearray(image.prefix)
    b.extend(base._dir_row(image.root_row,'.',p['directory_end'],0,tuple(range(p['metadata_blocks'])),flag=3))
    for name in image.order:
        c=image.components[name];allocated=p['allocations'][name]
        for part,first in enumerate(range(0,len(allocated),240)):
            b.extend(base._dir_row(c.rows[min(part,len(c.rows)-1)],name,p['sizes'][name],part,allocated[first:first+240]))
    b.extend(bytes(p['directory_end']-len(b)));return bytes(b)

class OriginalMDRDigest:
    """Hash original logical MDR once in order while the virtual supplier reads it."""
    def __init__(self,image):
        self.image=image;self.active=False;self.digest=hashlib.sha256();self.bytes=0;self.spans=[]
    def add(self,b): self.digest.update(b);self.bytes+=len(b)
    def read(self,at,n): return logical(self.image,'00004171.MDR',at,n)
    def chunks(self,at,n):
        if self.active:
            need((at,n)==self.expected.pop(0),'Original supplier span/order differs')
            if at==self.old2start: self.add(self.oldL3)
            self.spans.append({'offset':at,'bytes':n})
        for b in self.image.iter_component('00004171.MDR',offset=at,length=n):
            if self.active:self.add(b)
            yield b
        if self.active and at==self.old2start:self.add(self.oldDIR)
    def begin(self,plan,old_header,old_directory,oldroot):
        self.active=True;self.oldDIR=old_directory;self.old2start=plan.old_tables[1]['start']
        self.oldL3=bytearray(plan.L3);self.oldL3[(1153-1)*14:1153*14]=oldroot
        need(sha(self.oldL3)==plan.report['original_L3_sha256'],'Restore actual original L3 cache')
        t=plan.old_tables
        self.expected=[(772,t[5]['start']-772)]+[(t[i-1]['start'],t[i-1]['bytes']) for i in [6,5,4]]+[(t[1]['start'],plan.old_directory_start-t[1]['start'])]
        self.add(old_header)
    def finish(self):
        need(not self.expected and self.bytes==124255307 and self.digest.hexdigest()==MDR_SHA,'Original logical MDR source digest')
        return {'bytes':self.bytes,'SHA256':self.digest.hexdigest(),'source_spans':self.spans,
          'method':'Original772/header + actual supplier prefix/6/5/4 including old padding + restored planning L3 cache + actual L2/L1 + original DIR, original logical order. No second full source hash.'}

class ActualTree:
    def __init__(self,sink):
        self.handle=SparseVirtualHandle(sink)
        self.img=reader.Image('actual-forward-virtual',self.handle,sink.position,4096)
        h=self.img.logical('00004171.MDR',0,772,'actual output MDR header')
        need(h[2:12]==b'GARMIN MDR' and struct.unpack_from('<H',h)[0]==772,'Actual MDR header')
        at,n,item,flags=struct.unpack_from('<4I',h,600)
        need((n,item,flags)==(120,20,1) and at+120==self.img.components['00004171.MDR']['size'],'Actual six DIR EOF')
        self.directory=self.img.logical('00004171.MDR',at,120,'actual output DIR')
        self.tables={}
        for level in range(1,7):
            a,b,stride,w,x=struct.unpack_from('<5I',self.directory,(level-1)*20)
            self.tables[level]={'start':a,'bytes':b,'stride':stride,'count':b*8//stride,
                'widths':[w>>18&63,w>>24&63,w>>12&63,w>>6&63,w&63,x&63,x>>11&63,x>>17&63],
                'refs':[w>>30&1,w>>31&1]}
        g=self.img.logical('I053061A.GMP',0,57,'actual output GMP header')
        need(g[2:12]==b'GARMIN GMP','Actual GMP signature')
        self.lbl_at=struct.unpack_from('<7I',g,25)[2]
        lbl=self.img.logical('I053061A.GMP',self.lbl_at,661,'actual output LBL header')
        need(lbl[2:12]==b'GARMIN LBL','Actual LBL signature')
        self.pool,self.poolbytes=struct.unpack_from('<II',lbl,21);self.shift=lbl[29]
        need((self.pool,self.poolbytes,self.shift,lbl[30],struct.unpack_from('<H',lbl,170)[0])==(6566,3805432,3,10,950),'Actual CP950 descriptor')
        self.labels={}
    def label(self,ref):
        if ref is None:return None
        if ref not in self.labels:
            offset=ref<<self.shift;need(offset<self.poolbytes,'Actual labelref pool bound')
            b=self.img.logical('I053061A.GMP',self.pool+offset,min(64,self.poolbytes-offset),'actual output label '+str(ref))
            end=b.find(b'\0');need(end>=0,'Complete label within64 actual bytes')
            self.labels[ref]={'text':b[:end].decode('cp950'),'CP950_hex':b[:end].hex(),'window_SHA256':sha(b)}
        return self.labels[ref]['text']
    def record(self,level,ID,decode_label=True):
        t=self.tables[level];need(1<=ID<=t['count'],'Record actual bound')
        at,shift=divmod((ID-1)*t['stride'],8)
        b=self.img.logical('00004171.MDR',t['start']+at,(shift+t['stride']+7)//8,'actual output L'+str(level)+' ID'+str(ID))
        r=reader.decode_parent(b,shift,t)
        need(r['mapordinal']==1,'Actual mapordinal')
        r.update({'level':level,'ID':ID,'label':self.label(r['primary_ref']) if decode_label else None,
                  'significant_bits_hex':r.pop('raw_record_value').to_bytes((t['stride']+7)//8,'little').hex()})
        return r

def run():
    need(not (OUT/'stream-receipt.json').exists(),'No replay of already completed virtual stream')
    base=module('sealed_AP4K_delta_v1',ROOT/'staging/navigation-native-general-writer-v1/native_ap_writer.py',
        'cb190d5f3c70f0e81e9d49808dff044e4717b5061f749e7720af56aee39b0cf8')
    cow=module('sealed_current_MDR_delta_v1',ROOT/'staging/navigation-native-current-profile-cow-writer-v1/current_profile_cow_writer.py',
        '71673de65c6e94da664ad8bc8b81307c37a6dfbf94d819eebfa888274b688c9e')
    seal=pin(CAP/'sealed-files.json','f75df572296f74087edff8bd7790677dfd242d4d0605f1849c698dbfd06c0042')
    proof=pin(CAP/'proof.json','755b415428188252935a2cd79262fd566dba7f2525ea699286d2b7bdba4d6f05')
    meta=pin(CAP/'actual-raw-capture-metadata.json','e323b7f2836d36f92b3ce1718f2f158818a66a65fb82b77a77ff5e9320530211')
    rows=pin(CAP/'actual-v2-v3-records.json','992f82194ed89201765f07f971c8774fdd3d52c73af6035ba604f3aed7203b9b')
    minplan=pin(CAP/'minimal-cow-plan.json','d4e37f8c109c06e804086e10b634ec2852c8cd8b15877232985219576c51a972')
    selected=pin(CAP/'selected-control.json','03dfdc178b1297919f619e271a45283f5252a0de9a99fa46aa9f76b8e40fb6f2')
    rootraw=pin(CAP/'v2-root-raw-window.bin','c9403b512e2ab687132f7cb962c8c6ef854746d8830c96fb5c8dd9893f1c970a',False)
    oldhousewindow=pin(CAP/'v2-lane-raw-window.bin','d50e3e2a6854a79cd303c64ed17d250b340ad9243e7cd801d51fecaa159cdde8',False)
    new2=pin(CAP/'v3-selected-2-house-significant-bits.bin','58036f5bf4a1a71760e2ece4e785133ab61301900f808b26f126a069bc0ded49',False)
    controls=pin(ROOT/'staging/navigation-single-lane-minquan-controls-extraction-v1/actual-minquan-controls.json',
        'e76816528eecbe433a189415bfd6b499530d99545af9b8ecba73cd16817813ed')
    v2seal=pin(V2.parent/'sealed-files.json','659ae2d149b45098542fd90cd0a3000e74e3c9e2d76077f4d1ecdbbeec022766')
    imagepin=next(r for r in v2seal['files'] if r['path']==str(V2.relative_to(ROOT)))
    need(imagepin['sha256']==V2_SHA and imagepin['bytes']==128356352,'Exact inherited v2 whole pin')
    before=stat(V2);need(before[:4]==imagepin['stat_at_seal'][:4],'Exact v2 dev/inode/size/mtime')
    root=rows['v2']['root'];lane=rows['v2']['lane'];old=rows['v2']['house_children'];siblings=rows['v2']['root_children']
    v3old=[r for r in rows['v3']['house_children'] if r['label'] in [x['label'] for x in old]]
    need([r['payload'] for r in v3old]==[r['payload'] for r in old],'Actual v3 oldfour bits/order identical')
    v3new=rows['v3']['selected_house'];need(len(v3new)==1 and v3new[0]['ordinal']==2 and bytes.fromhex(v3new[0]['payload'])==new2,'Actual v3 unique2 insertion ordinal2')
    need([r['label'] for r in old]==['+ 交叉路口 +','1號','4號','7號'] and [r['raw_flags'] for r in old]==[6,8,0,0],'Actual nonterminal flags retained')
    need(len(siblings)==267 and root['ID']==1153 and lane['ordinal']==5 and lane['ID']==2134706,'Exact v2 parent/family')
    need(len(rootraw)==4272 and all(rootraw[i*16:(i+1)*16].hex()==r['payload'] for i,r in enumerate(siblings)),'Captured original267 rawbits')
    w=int.from_bytes(oldhousewindow,'little')
    need(all(((w>>(4+i*126))&((1<<126)-1)).to_bytes(16,'little').hex()==r['payload'] for i,r in enumerate(old)),'Original oldfour full126bits/shift4')
    clone4=bytearray(rootraw)
    oldv=int.from_bytes(clone4[5*16:6*16],'little');mask4=((1<<32)-1)<<39
    newv=(oldv&~mask4)|(2667574<<39)|(5<<61)
    need((newv&~mask4)==(oldv&~mask4),'L4 onlyfirst/count fields')
    clone4[5*16:6*16]=newv.to_bytes(16,'little')
    clone5rows=[bytes.fromhex(r['payload']) for r in old];clone5rows.insert(2,new2)
    spec4=cow.PackedAppend.from_records(4,267,lambda:iter(bytes(clone4[i:i+16]) for i in range(0,len(clone4),16)))
    spec5=cow.PackedAppend.from_records(5,5,lambda:iter(clone5rows))
    clone5=b''.join(spec5.chunks())
    need(len(clone5)==79,'Packedfive126bit bytes')
    (OUT/'append-L4-267-significant.bin').write_bytes(clone4)
    (OUT/'append-L5-5-significant.bin').write_bytes(clone5)
    (OUT/'new2-source-bound126bits.bin').write_bytes(new2)
    budget=None;sink=None;raw=None
    try:
        raw=V2.open('rb');budget=BudgetFile(raw)
        image=base.StreamIMG(budget)
        need(image.size==128356352 and image.capacity==134217728,'Actual4K original capacity')
        # Validate actual small source windows; cached capture is never substituted for source body.
        need(logical(image,'00004171.MDR',97229136,4272)==rootraw,'Actual original L4 family read')
        need(logical(image,'00004171.MDR',23734483,64)==oldhousewindow,'Actual original L5 four read')
        oldroot=logical(image,'00004171.MDR',123595568,14)
        need(oldroot.hex()==root['payload'],'Actual original L3 root bits')
        auditor=OriginalMDRDigest(image)
        source=cow.CurrentMDRSource(image.components['00004171.MDR'].size,auditor.read,auditor.chunks,
                                    lambda:stat(V2)==before,V2_SHA)
        plan=cow.plan_current_mdr(source,appends={4:spec4,5:spec5,6:cow.PackedAppend.empty(6)},
              selected_ranges=(cow.SelectedRange(1153,3781595,267,4,4),))
        need(plan.size==124259658 and tuple(t['count'] for t in plan.new_tables)==(22,343,47870,3781861,2667578,1984066),'Exact current-profile counts')
        oldheader=auditor.read(0,772);olddir=auditor.read(plan.old_directory_start,120)
        oldpad=auditor.read(plan.old_tables[4]['start']+plan.old_tables[4]['bytes']-1,1)[0]
        old_layout=base.plan_repack(image,{})
        need(old_layout['image_bytes']==image.size and old_layout['directory_end']==image.directory_end,'Original physical allocation extent')
        for name in image.order:
            need(image.components[name].blocks==old_layout['allocations'][name],'Original physical component order is contiguous')
        replacement=base.Replacement(plan.size,plan.chunks)
        layout=base.plan_repack(image,{'00004171.MDR':plan.size})
        need(layout['image_bytes']==128360448 and layout['directory_end']==73728,'Exact4K compact projected output')
        oldmetadata=image.physical(0,image.directory_end,'actual original inverse metadata')
        preview=metadata(base,image,layout)
        need(preview[:4096]==image.prefix and preview[:512]==image.header,'Exact wholeheader/checksum/CHS/prefix preservation')
        mdiff=diff_runs(oldmetadata,preview)
        tails={}
        for name in image.order:
            c=image.components[name];n=(-c.size)%4096
            tails[name]=image.physical(c.blocks[-1]*4096+(c.size%4096),n,'actual original inverse component padding') if n else b''
        # Actual LBL metadata is only used to schedule finite output label windows.
        gh=logical(image,'I053061A.GMP',0,57);lblat=struct.unpack_from('<7I',gh,25)[2]
        lh=logical(image,'I053061A.GMP',lblat,661)
        pool,poolsize=struct.unpack_from('<II',lh,21)
        need((pool,poolsize,lh[29],lh[30],struct.unpack_from('<H',lh,170)[0])==(6566,3805432,3,10,950),'Actualsource CP950 pool')
        ranges=[(0,layout['directory_end'])]
        def capture(name,at,n):
            blocks=layout['allocations'][name]
            while n:
                i,within=divmod(at,4096);take=min(n,4096-within)
                ranges.append((blocks[i]*4096+within,take));at+=take;n-=take
        def capture_record(level,ID,count=1):
            t=plan.new_tables[level-1];at,shift=divmod((ID-1)*t['stride'],8)
            capture('00004171.MDR',t['start']+at,(shift+count*t['stride']+7)//8)
        capture('00004171.MDR',0,772);capture('00004171.MDR',plan.new_directory_start,120)
        capture_record(3,1153);capture_record(3,16707)
        capture_record(4,3781595,267);capture_record(5,2667574,5);capture_record(6,120119)
        for c in controls['controls']:capture_record(4,c['ID'])
        capture('I053061A.GMP',0,57);capture('I053061A.GMP',lblat,661)
        minqroot=logical(image,'00004171.MDR',plan.old_tables[2]['start']+(16707-1)*14,14)
        need(minqroot.hex()==controls['parent']['significant_rawbits_hex'],'Actual Minquan root pin')
        minqref=(int.from_bytes(minqroot,'little')>>1)&((1<<19)-1)
        refs={root['primary_ref'],lane['primary_ref'],v3new[0]['primary_ref'],minqref}
        refs.update(r['primary_ref'] for r in siblings+old);refs.update(c['primary_ref'] for c in controls['controls'])
        refs.update(r['secondary_ref'] for r in old if r['secondary_ref'] is not None)
        for ref in refs:
            off=ref<<3;need(off<poolsize,'Actual selectedref bound')
            capture('I053061A.GMP',pool+off,min(64,poolsize-off))
        inverse=InverseMDR(plan.old_tables,plan.new_tables,oldheader,olddir,oldroot,1153,oldpad)
        need(inverse.old_size==124255307,'Inverse original logical size')
        sink=CaptureHashSink(layout,old_layout,mdiff,len(oldmetadata),tails,inverse,ranges)
        newroot=plan.L3[(1153-1)*14:1153*14]
        # The inverse byte runs are losslessly packed; verbose JSON exceeded its small-output guard.
        packed_diff=bytearray()
        for r in mdiff:
            a,b=bytes.fromhex(r['old_hex']),bytes.fromhex(r['new_hex'])
            need(len(a)==len(b)<=65535,'Inverse metadata finite run')
            packed_diff.extend(struct.pack('<IH',r['offset'],len(a)));packed_diff.extend(a);packed_diff.extend(b)
        (OUT/'inverse-metadata-runs.bin').write_bytes(packed_diff)
        inverse_metadata={'schema':'exact-v2-inverse-from-forward-virtual/v1','original_IMG_SHA256':V2_SHA,
          'original_IMG_bytes':image.size,'original_MDR_SHA256':MDR_SHA,'original_MDR_bytes':source.size,
          'old_layout':compact_layout(old_layout),'new_layout':compact_layout(layout),
          'metadata_diff_run_count':len(mdiff),'metadata_diff_runs_artifact':'inverse-metadata-runs.bin',
          'metadata_diff_runs_SHA256':sha(packed_diff),'metadata_diff_runs_format':'Repeated little-endian uint32 offset,uint16 length,old[length],new[length]; complete original metadata length in old_layout.directory_end.',
          'old_component_padding_hex':{k:v.hex() for k,v in tails.items()},
          'MDR_keep_new_offset_old_length':inverse.keep,
          'MDR_byte_masks':[{'new_offset':at,'mask':m,'original_masked_value':v} for at,(m,v) in sorted(inverse.byte_patches.items())],
          'old_ROOT1153_hex':oldroot.hex(),'new_ROOT1153_hex':newroot.hex(),
          'inverse_method':'Consume actual forward virtual bytes in physical order; restore recorded metadata bytes, skip appended significant spans, restore original header/DIR/root masks and original L5 high padding, emit original actual component padding. Every other byte comes from actual forward output.'}
        save('inverse-metadata.json',inverse_metadata)
        save('delta-manifest.json',{'schema':'compact-family-current-v2-4K-COW/v1','input_source_failure_preserved':'initial 1fcd04 EXIT1, all-zero terminal assumption; capture-only a1b085 EXIT0; not one successful initial attempt',
          'source_group':3508619,'source_node':12084620255,'source_native24':[1164928,5660270],
          'original_street_ID':1153,'original_lane_ID':2134706,'new_family_first':3781595,'new_lane_ID':3781600,
          'old_L5_first':169831,'new_L5_first':2667574,'new_leaf_ID':2667576,'new_leaf_ordinal':2,
          'new_L5_labels':['+ 交叉路口 +','1號','2號','4號','7號'],
          'appended_L4_count':267,'appended_L5_count':5,'appended_L6_count':0,'MDR_growth_bytes':4351,
          'image_growth_bytes':4096,'current_profile_preserved':[23,112],
          '4K_adapter':'Direct sealed normal AP4K Replacement(plan.size, plan.chunks), plan_repack and repack_stream; no bind_container/from_container/eight() calls.',
          'sealed_COW_report_scope_correction':'Inherited explicit8K_binding_required_before_container_output flag describes old binding API. This NEW independently bound AP4K adapter preserves original4K header; old report/source unchanged.',
          'COW_report':plan.report,'layout':compact_layout(layout),'all_original_unknown_flags_preserved':True,
          'all_original_L4_siblings_except_selected_range_bits_preserved':True,'old4_all126bits_lowerptr_order_preserved':True,
          'new2_source_bound_bits':new2.hex(),'v3_extra3_not_imported':True,'v3_other_root_ptrs_not_imported':True})
        auditor.begin(plan,oldheader,olddir,oldroot)
        returned=base.repack_stream(image,sink,{'00004171.MDR':replacement})
        # Persist complete stream receipt before any readback assertion; no automatic whole replay.
        sr=sink.receipt()
        sr.update({'sealed_AP4K_return':returned,'source_read_receipt':budget.receipt(),
                   'source_stat_before':before,'source_stat_after_stream':stat(V2)})
        save('stream-receipt.json',sr)
        orig=auditor.finish();save('original-MDR-source-digest.json',orig)
        need(sr['source_inverse_IMG_SHA256']==V2_SHA,'Actual full inverse IMG original whole hash')
        need(sr['inverse_MDR_SHA256']==MDR_SHA and sr['inverse_MDR_bytes']==source.size,'Actual inverse MDR hash')
        hashes={r['name']:r['SHA256'] for r in sr['independent_physical_output_component_hashes']}
        need(all(hashes[k]==v for k,v in EXPECTED.items() if k!='00004171.MDR'),'Allfive nonMDR complete output component hashes')
        need(hashes=={r['name']:r['sha256'] for r in returned['components']},'Independent physical output hashes equal writer receipt')
        need(bytes(sink.metadata)==preview,'Actual metadata matches finite planning preview')
        capturedata=bytearray();captureindex=[]
        for w in sink.windows:
            captureindex.append({'physical_offset':w['start'],'bytes':len(w['bytes']),'artifact_offset':len(capturedata),'SHA256':sha(w['bytes'])})
            capturedata.extend(w['bytes'])
        (OUT/'actual-stream-windows.bin').write_bytes(capturedata)
        save('actual-stream-windows-index.json',captureindex)
        tree=ActualTree(sink)
        need(tree.directory==plan.directory and tree.img.header==image.header,'Actualoutput profile/DIR/header')
        foundroot=tree.record(3,1153)
        need(foundroot['label']=='四川路二段' and foundroot['raw_flags']==4 and foundroot['first_child']==3781595 and foundroot['child_count']==267,'Actual newstreet root exact')
        childrows=[]
        for i,r in enumerate(siblings):
            observed=tree.record(4,3781595+i)
            expected=bytes(clone4[i*16:(i+1)*16]).hex()
            need(observed['significant_bits_hex']==expected and observed['label']==r['label'],'Actual cloned sibling fullbit/label '+str(i))
            childrows.append(observed)
        lanes=[r for r in childrows if r['label']=='4巷'];need(len(lanes)==1,'Actual exactunique4巷 among267')
        foundlane=lanes[0]
        need(foundlane['next_level']==5 and foundlane['raw_flags']==5 and foundlane['first_child']==2667574 and foundlane['child_count']==5,'Actual selected lane range')
        houses=[tree.record(5,2667574+i) for i in range(5)]
        need([r['label'] for r in houses]==['+ 交叉路口 +','1號','2號','4號','7號'],'Actual finite five-house order')
        need(all(r['significant_bits_hex']==clone5rows[i].hex() for i,r in enumerate(houses)),'Actual fullfive126bits')
        need([houses[i]['significant_bits_hex'] for i in [0,1,3,4]]==[r['payload'] for r in old],'Actual preserved originalfour significantbits/order')
        found2=houses[2]
        need(found2['primary_ref']==19 and found2['raw_flags']==0 and found2['next_level']==0 and
             [found2['raw_location_a'],found2['raw_location_b']]==[1164928,5660270],'Actual unique2 source-bound ref/point')
        need(houses[0]['first_child']==120119 and houses[0]['child_count']==1 and houses[0]['next_level']==6,'Actual old intersection lowerpointer remains')
        nested=tree.record(6,120119,decode_label=False)
        minq=tree.record(3,16707)
        need(minq['significant_bits_hex']==controls['parent']['significant_rawbits_hex'] and minq['label']=='民權路','Actual unchanged Minquan parent')
        minqchecks=[]
        for c in controls['controls']:
            r=tree.record(4,c['ID']);lbl=tree.labels[c['primary_ref']]
            need(r['significant_bits_hex']==c['significant_rawbits_hex'] and r['label']==c['label'] and
                 r['primary_ref']==c['primary_ref'] and [r['raw_location_a'],r['raw_location_b']]==c['raw24'] and
                 lbl['CP950_hex']==c['actual_label_bytes_hex'] and lbl['window_SHA256']==c['actual_label_window_SHA256'],'Actual unchanged control '+c['label'])
            minqchecks.append(r)
        # Compact proof: 267-row rawclone artifact + complete equality counts; no whole-tree/labelcache dump.
        save('actual-captured-readback-proof.json',{'schema':'independent-normal-captured-forward-stream-readback/v1','all_passed':True,
          'exact_path':['四川路二段','4巷','2號'],'exact_uniques':[1,1,1],'root':foundroot,'lane':foundlane,
          'new2':found2,'old_and_new_five_houses':houses,'retained_original_intersection_L6_child':nested,
          'all267_siblings_fullbits_and_exact_primary_labels_checked':True,'sibling_records_checked':267,
          'old4_payload_bits_pointers_flags_relative_order_preserved':True,'old_flags':[6,8,0,0],
          'unknown_flags_preserved_without_semantic_inference':True,'unchanged_Minquan_parent':minq,'unchanged_three_controls':minqchecks,
          'readback_physical_calls':len(reader.READS),'readback_actual_captured_bytes_requested':sum(r['bytes'] for r in reader.READS),
          'readback_callorder_SHA256':sha(json.dumps(reader.READS,sort_keys=True,separators=(',',':')).encode()),
          'unique_actual_CP950_labels_decoded':len(tree.labels),'labelref_source':'Actual unchanged GMP/LBL bytes from forward output capture.',
          'parser_source':'captured_ap_reader_v1.py copied from pinned independent normal reader; no writer import',
          'full_output_file_readback':False,'full_output_virtual_stream_hash':True,'native_CPU_UI_lookup_route_render':False})
        need(stat(V2)==before,'Source stat unchanged at completion')
        save('proof.json',{'schema':'single-lane-current-v2-4K-virtual-delta/v1','all_passed':True,
          'complete_forward_virtual_stream_SHA256':sr['virtual_IMG_SHA256'],'virtual_IMG_bytes':sr['virtual_IMG_bytes'],
          'earlier_prestream_failure':{'actual_tool_chunk':'9afefc','EXIT':1,'source_bytes':836507,'stream_position':0,
             'reason':'Verbose inverse JSON exceeded small-output bound; lossless packed byte-run metadata replaces verbose representation, no map semantics changed.'},
          'actual_full_inverse_SHA256':sr['source_inverse_IMG_SHA256'],'original_full_SHA256':V2_SHA,
          'actual_inverse_equals_original_full_image':True,'original_source_MDR_and_output_inverse_MDR_SHA256':MDR_SHA,
          'complete_other_five_component_hashes_unchanged':True,'whole4K_header128MiB_capacity_checksum_CHS_prefix_unchanged':True,
          'actualforward_captured_windows_bytes':len(capturedata),'source_actual_reads':budget.receipt(),
          'original_source_pin_validation':'Inherited sealed full hash + exact dev/inode/size/mtime before; entire original inverse hash actually reconstructed from new virtual stream. Source wholefile not separately rehashed.',
          'source_stat_before':before,'source_stat_after':stat(V2),'source_handle_closed_after_finally':True,
          'normal_inputs':NORMAL_PINS,'input_initial_failure':'1fcd04 EXIT1 zero-flags assumption retained by input seal; a1b085 separate capture-only EXIT0',
          'candidate_source':{'group_ID':3508619,'node_ID':12084620255,'sourcepoint':['24.996635','121.4562137'],
            'native24':[1164928,5660270],'floor_unit':0,'noaliastransform':True,'city_geometry_source_bound_inherited':True,
            'district_polygon_verified':False,'source_fullmembers_pin':'selected-control.json pinned above; not reopened source gzip/PBF'},
          'actual_parser_result':'New2 exact, oldfour full126bits/lowerpointer/order, all267 full128bits except proven selected first/count and three original Minquan controls verified from actual forward captured bytes.',
          'bounds':{'base_IMG_read_limit':150000000,'outputs_sum_limit':262144,'actualcapture_limit':131072},
          'not_created':['full IMG file','ZIP','installer','public bundle','JAI/DB/labels/recordID reservation'],
          'limitations':['Virtual image only; fullstream hashed, finite actual-output captures parsed. No persisted/reopened full output.',
             'Original native comparator, binarylookup/UI/search/routing/rendering and physical v3 road-loss root cause remain unverified.',
             'Map data delta is not installable acceptance; no device touched; source city polygon only, district polygon not claimed.'],
          'falseflags':{'nativeCPU':False,'UI':False,'route':False,'render':False,'install':False,'device':False,
             'App':False,'directPhoneA2DP':False,'musicBackendOwner':False,'STOP_DONE':False,'speaker':False,'fullTaiwanGoal':False}})
        print(json.dumps({'all_passed':True,'virtual_IMG_bytes':sink.position,'virtual_IMG_SHA256':sr['virtual_IMG_SHA256'],
          'actual_inverse_SHA256':sr['source_inverse_IMG_SHA256'],'source_actual_bytes':budget.bytes,
          'capture_bytes':len(capturedata),'readback_records':276,'source_unchanged':stat(V2)==before,'no_fullIMG_created':True}))
    except BaseException:
        save('actual-failure.json',{'exception':traceback.format_exc(),'source_reads':budget.receipt() if budget else None,
             'stream_position':sink.position if sink else None,'source_stat_before':before,'source_stat_after':stat(V2),
             'actual_EXIT0_pass_claim':False,'no_automatic_fullstream_replay':True})
        raise
    finally:
        if raw:raw.close()
        save('handle-closure.json',{'source_path':str(V2.relative_to(ROOT)),'readonly_source_handle_closed':raw.closed if raw else None,
          'stat_before':before,'stat_after':stat(V2),'source_unchanged':stat(V2)==before,
          'destination':'In-memory hash/capture sink, never filesystem IMG','same_source_destination_handle':False})

if __name__=='__main__':run()
