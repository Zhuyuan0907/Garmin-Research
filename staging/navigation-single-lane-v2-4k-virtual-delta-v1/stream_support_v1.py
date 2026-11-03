"""Ordinary bounded source reads, streamed hash/capture and exact inverse masks."""
import hashlib
from pathlib import Path


def need(x, reason):
    if not x:
        raise ValueError(reason)


class BudgetFile:
    def __init__(self, raw, limit=150000000):
        self.raw, self.limit = raw, limit
        self.bytes = self.calls = 0
        self.digest = hashlib.sha256()
        self.first_calls, self.last_calls = [], []

    @property
    def name(self):
        return self.raw.name

    def fileno(self):
        return self.raw.fileno()

    def seek(self, *args):
        return self.raw.seek(*args)

    def tell(self):
        return self.raw.tell()

    def read(self, n=-1):
        need(type(n) is int and n >= 0, 'Unbounded source read forbidden')
        need(self.bytes+n <= self.limit, '150000000-byte source-read limit')
        at = self.raw.tell()
        b = self.raw.read(n)
        self.bytes += len(b)
        self.calls += 1
        self.digest.update(b)
        row = {'offset':at,'bytes':len(b),'SHA256':hashlib.sha256(b).hexdigest()}
        if len(self.first_calls)<8:
            self.first_calls.append(row)
        self.last_calls=(self.last_calls+[row])[-8:]
        return b

    def receipt(self):
        return {'source_path':self.name,'actual_bytes_read':self.bytes,'actual_read_calls':self.calls,
            'source_read_limit':self.limit,'concatenated_actual_reads_SHA256':self.digest.hexdigest(),
            'digest_scope':'Actual call order including repeated small planning/range reads; not whole-source file order.',
            'first_read_calls':self.first_calls,'last_read_calls':self.last_calls}


def merge_ranges(entries):
    ranges=[]
    for at,n in sorted(entries):
        need(n>0 and at>=0,'Finite capture range')
        end=at+n
        if ranges and at<=ranges[-1][1]:
            ranges[-1][1]=max(ranges[-1][1],end)
        else:
            ranges.append([at,end])
    need(sum(b-a for a,b in ranges)<=131072,'Actual stream captures exceed128KiB')
    return ranges


def diff_runs(old, new):
    need(len(old)<=len(new),'Inverse metadata needs no unrecorded growth')
    result=[]
    at=0
    while at<len(old):
        if old[at]==new[at]:
            at+=1
            continue
        start=at
        while at<len(old) and old[at]!=new[at]:
            at+=1
        result.append({'offset':start,'old_hex':old[start:at].hex(),'new_hex':new[start:at].hex()})
    return result


class InverseMDR:
    def __init__(self, old_tables,new_tables,old_header,old_directory,old_root,root_ID,old_pad_byte):
        old6,old5,old4,old3,old2,old1=[old_tables[i-1] for i in [6,5,4,3,2,1]]
        new6,new5,new4,new3,new2,new1=[new_tables[i-1] for i in [6,5,4,3,2,1]]
        self.keep=[(0,old6['start'])]
        for level in [6,5,4,3]:
            self.keep.append((new_tables[level-1]['start'],old_tables[level-1]['bytes']))
        self.keep.append((new2['start'],old2['bytes']+old1['bytes']))
        self.keep.append((new1['start']+new1['bytes'],120))
        self.byte_patches={}
        def patch(at,old,mask=None):
            for i,value in enumerate(old):
                m=255 if mask is None else mask[i]
                if m:
                    self.byte_patches[at+i]=(m,value&m)
        patch(600,old_header[600:604])
        for level in range(6):
            patch(self.keep[-1][0]+level*20,old_directory[level*20:level*20+8])
        bits=((1<<35)-1)<<20
        mask=bits.to_bytes(14,'little')
        patch(new3['start']+(root_ID-1)*14,old_root,mask)
        tail=old5['count']*old5['stride']%8
        need(tail==6 and old_pad_byte>>tail==0,'Actual currentL5 two-pad-bit contract')
        patch(new5['start']+old5['bytes']-1,bytes([old_pad_byte]),bytes([255^((1<<tail)-1)]))
        self.old_size=sum(n for _,n in self.keep)
        self.digest=hashlib.sha256()
        self.count=0
        self.input_cursor=0

    def consume(self, at, raw, inverse_whole):
        need(at==self.input_cursor,'New MDR sequential actual output')
        self.input_cursor+=len(raw)
        for start,n in self.keep:
            low,high=max(at,start),min(at+len(raw),start+n)
            if low>=high:
                continue
            b=bytearray(raw[low-at:high-at])
            for pos,(mask,value) in self.byte_patches.items():
                if low<=pos<high:
                    b[pos-low]=(b[pos-low]&~mask)|value
            self.digest.update(b)
            inverse_whole.update(b)
            self.count+=len(b)


class CaptureHashSink:
    def __init__(self,layout,old_layout,metadata_delta,old_metadata_size,old_tails,inverse_mdr,capture_ranges):
        self.layout,self.old_layout=layout,old_layout
        self.metadata_delta,self.old_metadata_size=metadata_delta,old_metadata_size
        self.old_tails,self.inverse_mdr=old_tails,inverse_mdr
        self.position=0
        self.whole=hashlib.sha256()
        self.inverse_whole=hashlib.sha256()
        self.metadata=bytearray()
        self.metadata_restored=False
        self.windows=[{'start':a,'end':b,'bytes':bytearray(b-a),'filled':0} for a,b in merge_ranges(capture_ranges)]
        self.component_hashes={k:hashlib.sha256() for k in layout['sizes']}
        self.component_counts={k:0 for k in layout['sizes']}
        self.component_done=set()
        self.closed=False
        self.physical_components={k:(v[0]*4096,layout['sizes'][k]) for k,v in layout['allocations'].items()}

    def fileno(self):
        raise OSError('Memory hash sink has no filesystem destination')

    def seek(self, at, whence=0):
        need((at==0 and whence==2 and self.position==0) or (whence==0 and at==self.position),'Hash sink permits no rewrite')
        return self.position

    def tell(self):
        return self.position

    def truncate(self,n=None):
        need(n==self.position==self.layout['image_bytes'],'Complete virtual image length')

    def write(self, raw):
        raw=bytes(raw);at=self.position
        need(at+len(raw)<=self.layout['image_bytes'],'Virtual output beyond planned image')
        self.whole.update(raw)
        for w in self.windows:
            low,high=max(at,w['start']),min(at+len(raw),w['end'])
            if low<high:
                w['bytes'][low-w['start']:high-w['start']]=raw[low-at:high-at]
                w['filled']+=high-low
        if at<self.layout['directory_end']:
            n=min(len(raw),self.layout['directory_end']-at)
            need(at==len(self.metadata),'Actual metadata sequential')
            self.metadata.extend(raw[:n])
            if len(self.metadata)==self.layout['directory_end']:
                b=bytearray(self.metadata[:self.old_metadata_size])
                for r in self.metadata_delta:
                    old,new=bytes.fromhex(r['old_hex']),bytes.fromhex(r['new_hex'])
                    pos=r['offset'];need(b[pos:pos+len(new)]==new,'Inverse metadata newbytes mismatch')
                    b[pos:pos+len(old)]=old
                self.inverse_whole.update(b)
                self.metadata_restored=True
        for name,(start,size) in self.physical_components.items():
            low,high=max(at,start),min(at+len(raw),start+size)
            if low>=high:
                continue
            need(self.metadata_restored,'Actual inverse metadata precedes components')
            b=raw[low-at:high-at]
            self.component_hashes[name].update(b)
            self.component_counts[name]+=len(b)
            if name=='00004171.MDR':
                self.inverse_mdr.consume(low-start,b,self.inverse_whole)
            else:
                need(size==self.old_layout['sizes'][name],'Only MDR replacement allowed')
                self.inverse_whole.update(b)
            if high==start+size:
                need(name not in self.component_done and self.component_counts[name]==size,'Each component completes once')
                self.inverse_whole.update(self.old_tails[name])
                self.component_done.add(name)
        self.position+=len(raw)
        return len(raw)

    def read_window(self,at,n):
        for w in self.windows:
            if w['start']<=at and at+n<=w['end']:
                need(w['filled']==w['end']-w['start'],'Actual stream capture incomplete')
                return bytes(w['bytes'][at-w['start']:at-w['start']+n])
        raise ValueError('Uncaptured actual virtual range '+str((at,n)))

    def receipt(self):
        need(self.position==self.layout['image_bytes'],'Complete whole virtual hash')
        need(len(self.component_done)==6,'All six output component bodies consumed')
        need(all(w['filled']==w['end']-w['start'] for w in self.windows),'Every planned actual stream window captured')
        return {'virtual_IMG_bytes':self.position,'virtual_IMG_SHA256':self.whole.hexdigest(),
            'source_inverse_IMG_SHA256':self.inverse_whole.hexdigest(),
            'inverse_MDR_bytes':self.inverse_mdr.count,'inverse_MDR_SHA256':self.inverse_mdr.digest.hexdigest(),
            'independent_physical_output_component_hashes':[{'name':k,'bytes':self.component_counts[k],
                'SHA256':self.component_hashes[k].hexdigest()} for k in self.component_counts],
            'actual_stream_capture_bytes':sum(len(w['bytes']) for w in self.windows),
            'full_virtual_stream_hashed_once':True,'full_output_persisted_or_reopened':False}


class SparseVirtualHandle:
    def __init__(self,sink):
        self.sink,self.pos=sink,0
        self.reads=[]

    def seek(self,at,whence=0):
        self.pos=at if whence==0 else self.pos+at if whence==1 else self.sink.position+at
        need(0<=self.pos<=self.sink.position,'Sparse virtual seek bounds')
        return self.pos

    def tell(self):
        return self.pos

    def read(self,n):
        b=self.sink.read_window(self.pos,n)
        self.reads.append({'offset':self.pos,'bytes':n,'SHA256':hashlib.sha256(b).hexdigest()})
        self.pos+=n
        return b
