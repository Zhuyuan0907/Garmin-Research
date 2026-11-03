#!/usr/bin/env python3
"""Focused~2MiB synthetic controls; no original component bytes/USB/Java."""
import datetime,hashlib,io,json,os,struct,sys,tempfile
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1];sys.path.insert(0,str(HERE))
from ap_8k_writer import Source4K,Replacement,AP_NAMES,MDR,plan_repack,repack_stream,repack_new_path,_row

def expect(ok,msg):
    if not ok:raise AssertionError(msg)

def digest(b):return hashlib.sha256(b).hexdigest()

def payload(seed,n):
    pattern=bytes((seed+i*37)%256 for i in range(251))
    return (pattern*((n+250)//251))[:n]

def make_row(name,length,part,blocks,marker,root=False):
    row=bytearray(512);row[0]=1
    a,b=name.split('.');row[1:9]=a.encode().ljust(8,b' ');row[9:12]=b.encode().ljust(3,b' ')
    row[12:16]=(length if part==0 else 0).to_bytes(4,'little');row[16]=3 if root else 0
    row[17:19]=part.to_bytes(2,'little');row[19:32]=bytes([marker])*13
    row[32:]=b''.join(v.to_bytes(2,'little') for v in blocks)+b'\xff\xff'*(240-len(blocks))
    return bytes(row)

def fixture(mdrsize=241*8192-7):
    cap=json.loads((ROOT/'staging/navigation-img-capacity-header-comparison-v1/stock-header-comparison.json').read_text())
    h=bytes.fromhex(next(x['header_hex'] for x in cap['headers'] if x['source'].endswith('gmapprom1.img')))
    sizes=[17,mdrsize,37,8193,53,11]
    logical={n:payload(31+i,s) for i,(n,s) in enumerate(zip(AP_NAMES,sizes))}
    counts=[(n+4095)//4096 for n in sizes]
    rows=1+sum((n+239)//240 for n in counts)
    end=((4096+rows*512+4095)//4096)*4096
    metas=end//4096;cursor=metas;spec=[]
    for name,count in zip(AP_NAMES,counts):
        blocks=list(range(cursor,cursor+count));cursor+=count
        if name==MDR:blocks=blocks[1::2]+blocks[::2]  # Noncontiguous input logical allocation.
        spec.append((name,blocks))
    raw=bytearray(cursor*4096);raw[:512]=h
    raw[512:4096]=payload(173,4096-512)
    raw[4096:4608]=make_row('.',end,0,list(range(metas)),223,True)
    pos=4608
    for i,(name,blocks) in enumerate(spec):
        for part,start in enumerate(range(0,len(blocks),240)):
            raw[pos:pos+512]=make_row(name,len(logical[name]),part,blocks[start:start+240],81+i);pos+=512
        data=logical[name]
        for k,block in enumerate(blocks):
            d=data[k*4096:(k+1)*4096];at=block*4096
            raw[at:at+len(d)]=d;raw[at+len(d):at+4096]=b'\xee'*(4096-len(d))
    return bytes(raw),logical


def independent_read(stream, *, padding_zero=False):
    """Independent sector/FAT walking plus rolling hashes; no writer parser/plan."""
    stream.seek(0,2);length=stream.tell();stream.seek(0);h=stream.read(512)
    bsize=1<<(h[97]+h[98]);first=h[64]*512
    stream.seek(first);root=stream.read(512);end=int.from_bytes(root[12:16],'little')
    expect(end%bsize==0,'independent directory alignment')
    rootids=[]
    for off in range(32,512,2):
        v=int.from_bytes(root[off:off+2],'little')
        if v!=65535:rootids.append(v)
    expect(rootids==list(range(end//bsize)),'independent root extent/allocation')
    owned=set(rootids);files={};current=None
    stream.seek(first+512)
    for offset in range(first+512,end,512):
        row=stream.read(512)
        if row[0]==0:expect(row==bytes(512),'inactive row nonzero');continue
        expect(row[0]==1 and row[16]!=3,'row used/type')
        name=row[1:9].decode().strip()+'.'+row[9:12].decode().strip()
        part=int.from_bytes(row[17:19],'little');size=int.from_bytes(row[12:16],'little')
        if part==0:
            expect(name not in files,'independent duplicate');files[name]={'bytes':size,'blocks':[],'rows':[]};current=name
        else:expect(current==name and size==0,'independent continuation name/size')
        c=files[name];expect(part==len(c['rows']),'independent sequence');c['rows'].append(row)
        padding=False
        for off in range(32,512,2):
            v=int.from_bytes(row[off:off+2],'little')
            if v==65535:padding=True;continue
            expect(not padding and v not in owned and (v+1)*bsize<=length,'independent FAT alias/bounds/padding')
            c['blocks'].append(v);owned.add(v)
    for name,c in files.items():
        expect(len(c['blocks'])==(c['bytes']+bsize-1)//bsize,'independent allocated count')
        remain=c['bytes'];sha=hashlib.sha256()
        for v in c['blocks']:
            stream.seek(v*bsize);block=stream.read(bsize);expect(len(block)==bsize,'independent short block')
            take=min(remain,bsize);sha.update(block[:take]);remain-=take
            if padding_zero:expect(block[take:]==bytes(bsize-take),'independent nonzero output tail')
        expect(remain==0,'independent remaining logical');c['sha256']=sha.hexdigest()
    return {'block':bsize,'header':h,'end':end,'length':length,'files':files,'root':root}


def main():
    output=HERE/'8k-writer-focused-proof.json';expect(not output.exists(),'Refuse overwrite completed test scope')
    guards=[];positives=[]
    def rejected(name,f):
        try:f()
        except (ValueError,FileExistsError,OSError,RuntimeError) as e:guards.append({'case':name,'rejected':True,'error_type':type(e).__name__,'reason':str(e)})
        else:raise AssertionError('No rejection: '+name)
    raw,expected=fixture();source=Source4K(io.BytesIO(raw));original_header=source.header
    expect(source.read_log and all(not r['purpose'].startswith('logical:') for r in source.read_log),'Source construction read payload')
    first_output=io.BytesIO();r=repack_stream(source,first_output)
    independent=independent_read(first_output,padding_zero=True)
    expect(independent['block']==8192 and len(independent['files'])==6,'8K exact six independent')
    for name,b in expected.items():expect(independent['files'][name]['sha256']==digest(b),'identity preservation:'+name)
    expect(len(independent['files'][MDR]['rows'])==2,'241 output blocks require2FATrows')
    expect(independent['files'][MDR]['rows'][1][12:16]==bytes(4),'continuation length must0')
    allowed={15,24,25,95,96,98,458,459,460,461}
    changed=[i for i,(a,b) in enumerate(zip(original_header,independent['header'])) if a!=b]
    expect(set(changed)<=allowed and changed==r['changed_header_byte_offsets'],'changed header subset')
    expect(independent['header'][99:101]==original_header[99:101],'0x63 preserved')
    expect(first_output.getvalue()[512:4096]==raw[512:4096],'metadata prefix preservation')
    expect(independent['root'][19:32]==source.root_row[19:32],'root unknown metadata preservation')
    for n,c in source.components.items():
        for row in independent['files'][n]['rows']:
            expect(row[:12]==c.rows[0][:12] and row[16:17]==c.rows[0][16:17] and row[19:32]==c.rows[0][19:32],'component unknown metadata preserved')
    positives.append({'case':'noncontiguous4K_to8K_identity_conversion','all6_logical_hashes_match':True,'MDR_output_blocks':241,'MDR_FAT_parts':2,'dir_end':independent['end'],'actual_changed_header_offsets':changed,'output_bytes':r['image_bytes'],'tail_padding_verified':True})
    #240→241 outputblock continuation threshold, variable supplier chunks.
    for blocks in [240,241]:
        data=payload(211,blocks*8192-3);calls=[]
        def chunks():
            calls.append(1);cursor=0;cut=[7,4093,13,8192,65536];i=0
            while cursor<len(data):
                n=cut[i%len(cut)];yield data[cursor:cursor+n];cursor+=n;i+=1
        out=io.BytesIO();receipt=repack_stream(Source4K(io.BytesIO(raw)),out,{MDR:Replacement(len(data),chunks)})
        j=independent_read(out,padding_zero=True)
        expect(j['files'][MDR]['sha256']==digest(data),'MDR supplier digest')
        expect(len(j['files'][MDR]['rows'])==(1 if blocks==240 else 2),'240/241 output continuation threshold')
        expect(calls==[1],'Supplier invoked once')
        for name,b in expected.items():
            if name!=MDR:expect(j['files'][name]['sha256']==digest(b),'Other5 independent preservation')
        positives.append({'case':f'explicit_streaming_MDR_{blocks}_8Kblocks','MDR_FAT_parts':len(j['files'][MDR]['rows']),'output_bytes':receipt['image_bytes'],'other5_hashes_preserved':True,'supplier_called_once':True,'max_chunk_bytes':max(x['max_chunk_bytes'] for x in receipt['components'])})
    # Plan only exact maximum268MiB boundary; no large output allocation.
    maxplan=None
    for n in range(32768,32000,-1):
        try:maxplan=plan_repack(Source4K(io.BytesIO(raw)),{MDR:Replacement(n*8192,lambda:())});break
        except ValueError:pass
    expect(maxplan and maxplan['image_bytes']==268435456,'Explicit profile exact capacity')
    maxsize=maxplan['sizes'][MDR]
    positives.append({'case':'268MiB_arithmetic_boundary_only','MDR_declared_bytes':maxsize,'image_bytes':maxplan['image_bytes'],'large_output_allocated':False,'maximum_block_index':max(maxplan['allocations'][MDR])})
    rejected('268MiB_one_byte_excess',lambda:plan_repack(Source4K(io.BytesIO(raw)),{MDR:Replacement(maxsize+1,lambda:())}))
    rejected('MDR_u32_overflow',lambda:plan_repack(Source4K(io.BytesIO(raw)),{MDR:Replacement(1<<32,lambda:())}))
    rejected('MDR_bool_size',lambda:plan_repack(Source4K(io.BytesIO(raw)),{MDR:Replacement(True,lambda:())}))
    rejected('MDR_zero_size',lambda:plan_repack(Source4K(io.BytesIO(raw)),{MDR:Replacement(0,lambda:())}))
    rejected('replacement_unknown_component',lambda:plan_repack(Source4K(io.BytesIO(raw)),{'I053061A.GMP':Replacement(10,lambda:())}))
    replacement=Replacement(3,lambda:iter([b'abc']))
    rejected('duplicate_explicit_MDR',lambda:plan_repack(Source4K(io.BytesIO(raw)),[(MDR,replacement),(MDR,replacement)]))
    rejected('invalid_supplier_type',lambda:plan_repack(Source4K(io.BytesIO(raw)),{MDR:object()}))
    rejected('supplier_not_callable',lambda:plan_repack(Source4K(io.BytesIO(raw)),{MDR:Replacement(3,None)}))
    for name,size,chunks in [('short_supplier',4,[b'abc']),('long_supplier',2,[b'abc']),('empty_chunk',3,[b'']),('nonbytes_chunk',3,['abc']),('chunk_over1MiB',1048577,[b'x'*1048577])]:
        rejected(name,lambda size=size,chunks=chunks:repack_stream(Source4K(io.BytesIO(raw)),io.BytesIO(),{MDR:Replacement(size,lambda:iter(chunks))}))
    def raising():yield b'a';raise RuntimeError('supplier interruption')
    rejected('supplier_exception',lambda:repack_stream(Source4K(io.BytesIO(raw)),io.BytesIO(),{MDR:Replacement(3,raising)}))
    rejected('output_nonempty',lambda:repack_stream(Source4K(io.BytesIO(raw)),io.BytesIO(b'existing')))
    ss=Source4K(io.BytesIO(raw));rejected('output_same_stream',lambda:repack_stream(ss,ss.stream))
    class ZeroWrite(io.BytesIO):
        def write(self,data):return 0
    rejected('output_stalled_write',lambda:repack_stream(Source4K(io.BytesIO(raw)),ZeroWrite()))
    class ShortWrite(io.BytesIO):
        def write(self,data):return super().write(data[:17])
    out=ShortWrite();repack_stream(Source4K(io.BytesIO(raw)),out,{MDR:Replacement(3,lambda:iter([b'abc']))});j=independent_read(out,padding_zero=True)
    expect(j['files'][MDR]['sha256']==digest(b'abc'),'Real short-write loop control');positives.append({'case':'partial_output_writes','independent_digest_match':True})
    def mutated(offset,value):
        b=bytearray(raw);b[offset:offset+len(value)]=value;return io.BytesIO(b)
    rejected('source_nonwhole4K',lambda:Source4K(io.BytesIO(raw[:-1])))
    rejected('source_wrong_exponent',lambda:Source4K(mutated(0x62,b'\x04')))
    rejected('source_wrong_sector_profile',lambda:Source4K(mutated(0x18,b'\x20\x00')))
    rejected('source_wrong_capacity_profile',lambda:Source4K(mutated(0x63,b'\x01\x00')))
    rejected('source_XOR',lambda:Source4K(mutated(0,b'\x69')))
    rejected('source_bad_magic',lambda:Source4K(mutated(16,b'BADIMG')))
    rejected('source_bad_55AA',lambda:Source4K(mutated(510,b'\x00\x00')))
    rejected('source_wrong_dirStart',lambda:Source4K(mutated(64,b'\x01')))
    rejected('source_component_duplicate_name',lambda:Source4K(mutated(4608+512,raw[4608:4608+512])))
    rejected('source_component_root_alias',lambda:Source4K(mutated(4608+32,b'\x00\x00')))
    rejected('source_component_uint16_outside',lambda:Source4K(mutated(4608+32,b'\xfe\xff')))
    # First MDR row at5120, part1 at5632; these nonallocation fields would be lost when row count shrinks.
    rejected('source_nonuniform_continuation_metadata',lambda:Source4K(mutated(5632+19,b'\x55')))
    rejected('source_continuation_size',lambda:Source4K(mutated(5632+12,b'\x01\x00\x00\x00')))
    rejected('source_continuation_duplicate_part',lambda:Source4K(mutated(5632+17,b'\x00\x00')))
    # Synthetic arithmetic/helper guards, not valid stock source/profile paths.
    ss=Source4K(io.BytesIO(raw));ss.directory_end=241*8192
    rejected('root_more240_blocks_arithmetic',lambda:plan_repack(ss))
    rejected('FAT_uint16_reserved_sentinel',lambda:_row(source.components[MDR].rows[0],MDR,3,0,[65535]))
    tiny,tiny_payloads=fixture(17)
    with tempfile.TemporaryDirectory(prefix='small-fixture-',dir=HERE) as tmp:
        folder=Path(tmp);src=folder/'source.img';dst=folder/'out.img';src.write_bytes(tiny)
        # Iterable replacement pair normalized once, not consumed during plan.
        pairs=iter([(MDR,Replacement(3,lambda:iter([b'xyz'])))])
        rr=repack_new_path(src,dst,pairs)
        with dst.open('rb') as f:j=independent_read(f,padding_zero=True)
        expect(j['files'][MDR]['sha256']==digest(b'xyz'),'One-shot replacement pair consumed once')
        positives.append({'case':'exclusive_new_path_with_pair_iterator','independent_digest_match':True,'partial_path_cleanup_supported':True})
        rejected('path_existing_destination',lambda:repack_new_path(src,dst))
        rejected('path_same_source',lambda:repack_new_path(src,src))
        alias=folder/'hardlink.img';os.link(src,alias)
        rejected('path_hardlink_existing',lambda:repack_new_path(src,alias))
        with src.open('rb') as a,alias.open('r+b') as b:
            rejected('same_inode_distinct_streams',lambda:repack_stream(Source4K(a),b))
        before=digest(src.read_bytes());expect(before==digest(tiny),'Alias rejection touched source')
        link=folder/'dangling.img';link.symlink_to(folder/'missing')
        rejected('path_dangling_symlink',lambda:repack_new_path(src,link))
        for name,size,supplier in [('short',4,lambda:iter([b'abc'])),('error',3,raising)]:
            bad=folder/(name+'.img');rejected('path_'+name+'_supplier_cleanup',lambda bad=bad,size=size,supplier=supplier:repack_new_path(src,bad,{MDR:Replacement(size,supplier)}))
            expect(not bad.exists(),'Failed exclusive output not cleaned')
        expect(digest(src.read_bytes())==before,'Failed path operation changed source')
    result={'schema':'garmin-ap-8k-focused-tests/v1','created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'all_passed':True,'positive_controls':positives,'rejection_controls':guards,'synthetic_source_bytes':len(raw),'source_construction_bytes_read':sum(r['bytes'] for r in Source4K(io.BytesIO(raw)).read_log),'source_fixture_noncontiguous_MDR':True,'original_component_bytes_read':False,'original97MB_image_copied_or_repacked':False,'large268MiB_output_generated':False,'supplier_replaces_MDR_only':True,'header_checksum_rule_known':False,'byte15_zero_on_output':True,'device_acceptance_verified':False,'MDR_semantics_or_native_CPU_verified':False,'full_Taiwan_updated':False,'Java_or_map_compilation':False,'scope_limits':['Only exact XOR0/AP4K source geometry six-name profile supported.','268MiB is this explicit AP8K profile, not GarminOS platform maximum.','Synthetic independent reader/rolling hashes prove container allocation/content; original parser/firmware/device acceptance remains untested.','Directory root<=240blocks, uniform unknown per-component continuation metadata required.']}
    output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'all_passed':True,'positive_controls':len(positives),'rejection_controls':len(guards),'synthetic_source_bytes':len(raw)}))
if __name__=='__main__':main()
