#!/usr/bin/env python3
"""Execute stock DSKIMG parsing/open/read on backup VPM bytes, offline.

The mapped-region byte I/O, mutex/IRQ services and initialized cache/heap
inventory are fixtures. Container parsing, directory search, allocation
translation, file read/seek/tell and standard memory/string routines execute
the original instructions. No navigator is accessed and no package is saved.
"""
from collections import Counter
from datetime import datetime, timezone
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from unicorn import Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import (UC_CPU_ARM_1176, UC_ARM_REG_R0, UC_ARM_REG_R1,
    UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR,
    UC_ARM_REG_PC, UC_ARM_REG_CPSR)
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from analyze_sdp_activation import trace
from analyze_tts_vpm import parse_image
from analyze_native_loader import INIT, IMAGE, DESCRIPTOR, STUBS
from emulate_native_loader import simulate

CONTEXT = 0xf7b3dc
COUNT = 99
DRIVE = 7
REGION = 99
VOLUMES = 0x08000000
REGIONS = 0x08010000
FILES = 0x08012000
BUCKETS = 0x08013000
CACHE = 0x08014000
SECTOR = 0x08015000
SCRATCH = 0x08016000
HANDLE_OUT = 0x08017000
PATH = 0x08018000
TCB = 0x08019000
OUTPUT = 0x08100000
STACK = 0x085ff000
RETURN = 0x10000
REGS = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)


def sha(data): return hashlib.sha256(data).hexdigest()
def require(condition, message):
    if not condition: raise ValueError(message)


class VpmFilesystem:
    def __init__(self, stock, data):
        self.stock, self.data = stock, data
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.uc.ctl_set_cpu_model(UC_CPU_ARM_1176)
        for region in stock.copies:
            start = region['runtime_start'] & ~4095
            end = (region['runtime_end']+4095) & ~4095
            self.uc.mem_map(start, end-start)
            self.uc.mem_write(region['runtime_start'],
                              stock.read(region['load_start'], region['size']))
        # Only additional RAM reached by this filesystem experiment is mapped.
        self.uc.mem_map(0xf73000, 0x10000)
        # errno storage reached by the original ASCII drive-number parser.
        self.uc.mem_map(0x3aae000, 4096)
        self.uc.mem_map(0x08000000, 0x600000)
        self.uc.mem_map(0x02d4b000, 0x301000)
        self.uc.mem_map(RETURN, 4096)
        self.reads, self.calls, self.visits = [], [], Counter()
        self.mutexes = Counter()
        self.handles = {}
        self.allocations = []
        self.next_heap = 0x08040020
        self.returned = False
        self.hooks = {0x2d3380: 'region_read', 0x3009a0: 'mutex_lock',
                      0x3008b0: 'mutex_unlock', 0x21b6cc: 'irq_save',
                      0x21b6dc: 'irq_restore',0x38853c:'allocate_handle',
                      0x388804:'lock_handle',0x388b22:'unlock_handle',
                      0x3887a2:'release_handle',0x221d2c:'cache_sync'}
        self.uc.hook_add(UC_HOOK_CODE, self.observe)
        for offset, value in {0x18: REGIONS, 0x1c: VOLUMES, 0x20: COUNT,
            0x2c: FILES, 0x30: 4, 0x40: CACHE, 0x44: CACHE,
            0x58: BUCKETS, 0x60: 1, 0x64: 1}.items():
            self.put(CONTEXT+offset, value)
        self.put(CACHE+0xc, 0xffffffff)
        self.put(CACHE+0x14, SECTOR)
        self.put(0xf09090, TCB)
        # Original strtol uses a CRT locale pointer initialized outside this
        # scope. Fixtures use ASCII names without whitespace; only the blank
        # classification bit is reached, and all supplied path bytes are
        # nonblank. This is not a recovered production locale initializer.
        self.put(0x3aaec60, 0x0801a000)
        require(bytes(self.uc.mem_read(0xf00114+DRIVE, 1))[0] == REGION,
                'Expected original drive7 -> mapped-region99 translation')

    def word(self, address): return struct.unpack('<I', self.uc.mem_read(address, 4))[0]
    def put(self, address, value): self.uc.mem_write(address, struct.pack('<I', value))

    def observe(self, uc, address, size, _):
        self.visits[address] += 1
        if address == RETURN:
            self.returned = True; uc.emu_stop(); return
        name = self.hooks.get(address)
        if name is None: return
        args = [uc.reg_read(reg) for reg in REGS]
        value = 0
        if name == 'region_read':
            region, offset, count, destination = args
            require(region == REGION and 0 < count <= 4096,
                    'Unexpected lower region-read arguments')
            available = max(0, min(count, len(self.data)-offset))
            require(0x08000000 <= destination < 0x08600000,
                    'Region read outside fixture RAM')
            if available: uc.mem_write(destination, self.data[offset:offset+available])
            self.reads.append({'offset': offset, 'requested': count, 'returned': available})
            value = available
        elif name == 'mutex_lock': self.mutexes[args[0]] += 1
        elif name == 'mutex_unlock':
            require(self.mutexes[args[0]] > 0, 'Unbalanced synthetic mutex')
            self.mutexes[args[0]] -= 1
        elif name == 'irq_restore': require(args[0] == 0, 'Unexpected IRQ fixture token')
        elif name == 'allocate_handle':
            length,kind,out=args[:3]
            require(0 < length < 4096 and kind in (0,1),'Unexpected handle allocation')
            handle=0xd0000000+len(self.handles)+1
            pointer=self.next_heap;self.next_heap+=(length+127)&~63
            require(self.next_heap<0x080f0000,'Fixture heap exhausted')
            self.uc.mem_write(pointer-32,b'\xa5'*(length+64))
            self.handles[handle]={'pointer':pointer,'length':length,'locks':0,'freed':False}
            self.put(out,handle);self.allocations.append({'length':length,'kind':kind})
        elif name in ('lock_handle','unlock_handle'):
            entry=self.handles[args[0]]
            require(not entry['freed'],'Use of freed fixture handle')
            if name=='lock_handle':entry['locks']+=1;value=entry['pointer']
            else:
                require(entry['locks']>0,'Unbalanced handle unlock');entry['locks']-=1
        elif name=='release_handle':
            entry=self.handles[self.word(args[0])]
            require(not entry['freed'] and entry['locks']==0,'Unsafe fixture handle release')
            entry['freed']=True;self.put(args[0],0)
        elif name=='cache_sync':
            self.uc.ctl_remove_cache(IMAGE,DESCRIPTOR)
        uc.reg_write(UC_ARM_REG_R0, value)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    def call(self, address, args):
        self.returned = False
        for reg, value in zip(REGS, args): self.uc.reg_write(reg, value)
        self.uc.reg_write(UC_ARM_REG_SP, STACK)
        self.uc.reg_write(UC_ARM_REG_LR, RETURN | 1)
        try:
            self.uc.emu_start(address | 1, RETURN+2, count=6000000, timeout=30000000)
        except UcError as error:
            raise RuntimeError(f'{address:#x}: {error}; PC={self.uc.reg_read(UC_ARM_REG_PC):#x}; '
                               f'reads={self.reads[-5:]}') from error
        require(self.returned, f'Stock call did not return, PC={self.uc.reg_read(UC_ARM_REG_PC):#x}')
        value = self.uc.reg_read(UC_ARM_REG_R0)
        self.calls.append({'entry': hex(address), 'result': hex(value)})
        require(not any(self.mutexes.values()), 'Mutex left held at native return')
        return value

    def mount(self):
        # Execute real cache invalidation/remount -> DSK/DSD parser. One
        # retained sector cache and no optional allocation bitmap are fixtures.
        self.call(0x1e86ce, (DRIVE, 1, 0))
        active = bytes(self.uc.mem_read(VOLUMES+DRIVE*116, 1))[0]
        return active == 1

    def open(self, name):
        self.uc.mem_write(PATH, f'{DRIVE}:{name}'.encode('ascii')+b'\0')
        self.put(HANDLE_OUT, 0)
        status = self.call(0x2fba70, (HANDLE_OUT, PATH, 0xffff))
        return status, self.word(HANDLE_OUT)

    def read_file(self, handle):
        length = self.word(handle+12)
        require(0 < length < 0x300000, 'Unexpected test file size')
        self.uc.mem_write(OUTPUT-32, b'\xa5'*(length+64))
        self.call(0x1fb3ce, (handle, 0, 2))
        require(self.call(0x1fb3e4, (handle,)) == length, 'Original seek/tell length differs')
        self.call(0x1fb3ce, (handle, 0, 0))
        require(self.call(0x1fb3a2, (OUTPUT, 1, length, handle)) == length,
                'Original file-read count differs')
        require(self.call(0x1fb3e4, (handle,)) == length, 'Original read did not advance cursor')
        require(bytes(self.uc.mem_read(OUTPUT-32, 32)) == b'\xa5'*32 and
                bytes(self.uc.mem_read(OUTPUT+length, 32)) == b'\xa5'*32,
                'File-read crossed its buffer boundary')
        return bytes(self.uc.mem_read(OUTPUT, length))

    def close(self, handle):
        self.put(HANDLE_OUT, handle)
        require(self.call(0x3c44bc, (HANDLE_OUT,)) == 0,
                'Original public file close failed')
        require(self.word(HANDLE_OUT) == 0, 'Closed file handle retained')

    def load_original(self, binary, ram_bytes):
        # Original initializer, file callbacks and module bootstrap now share
        # this filesystem VM; none of the five loader file callbacks is hooked.
        # The current voice slot uses the original mapping to drive7.
        self.uc.mem_write(0xf09658+8,bytes([REGION]))
        self.uc.mem_write(IMAGE,b'\xa5'*ram_bytes)
        callbacks=(0x1fb2f8,0x1fb304,0x1fb3a2,0x1fb3ce,0x1fb3e4)
        before={a:self.visits[a] for a in callbacks}
        original_callbacks=self.stock.read(0x1fb2f8,0xf0)
        require(bytes(self.uc.mem_read(0x1fb2f8,0xf0))==original_callbacks,
                'Stock file callbacks changed before load')
        status=self.call(INIT,())
        require(status==11,'Stock DLL initializer did not return11')
        counts={hex(a):self.visits[a]-before[a] for a in callbacks}
        require(all(counts.values()),'A stock loader file callback was not executed')
        require(bytes(self.uc.mem_read(0x1fb2f8,0xf0))==original_callbacks,
                'Stock file callbacks changed during load')
        control,result=simulate(self.stock,'original_voice',module_bytes=binary,
            module_ram_bytes=ram_bytes,poison_module_ram=True,return_session=True)
        original=bytes(control.mem_read(IMAGE,ram_bytes))
        loaded=bytes(self.uc.mem_read(IMAGE,ram_bytes))
        require(loaded==original,'Filesystem-loaded runtime differs from independent loader control')
        trampolines=bytes(self.uc.mem_read(STUBS,40*12))
        require(trampolines==bytes(control.mem_read(STUBS,40*12)),
                'Filesystem load changed original40 export trampolines')
        for entry in self.handles.values():
            pointer,length=entry['pointer'],entry['length']
            require(entry['freed'] and entry['locks']==0,'Temporary pathname handle retained')
            require(bytes(self.uc.mem_read(pointer-32,32))==b'\xa5'*32 and
                    bytes(self.uc.mem_read(pointer+length,32))==b'\xa5'*32,
                    'Stock pathname wrapper crossed fixture allocation')
        return {'status':status,'runtime_bytes':ram_bytes,'runtime_sha256':sha(loaded),
                'matches_independent_original_loader_control':True,
                'original40_trampolines_match':True,
                'all_five_loader_file_callbacks_are_original':True,
                'file_callback_entries_executed_during_load':counts,
                'stock_callback_block_unchanged_before_after_sha256':sha(original_callbacks),
                'temporary_path_handle_allocations':self.allocations}

    def verify_closed_files(self):
        require(all(bytes(self.uc.mem_read(FILES+n*44+11,1))[0]&0x40==0
                    for n in range(4)),'A native file object remained active')
        require(self.word(CONTEXT+0x54)==0,'Directory cache retained a reader')
        require(bytes(self.uc.mem_read(CACHE+0x12,2))==b'\0\0',
                'Directory cache retained a reference count')


def run(stock, row, data=None, kind='original',load=False):
    data = (ROOT/row['file']).read_bytes() if data is None else data
    if kind=='original':require(sha(data)==row['sha256'],'Backup package changed')
    files, geometry = parse_image(data)
    fs = VpmFilesystem(stock, data)
    require(fs.mount(), 'Original DSK image did not become active')
    status, handle = fs.open('dllimg.bin')
    require(status == 0 and handle != 0, 'Original directory open failed')
    binary = fs.read_file(handle)
    require(binary == files['DLLIMG.BIN']['content'], 'Original read differs from independent extraction')
    fs.close(handle)
    # SIG is just another directory member at this layer. Read it through the
    # same original path; this does not establish high-level verification.
    status, handle=fs.open('dllimg.sig')
    require(status == 0 and handle != 0, 'Original SIG directory open failed')
    signature=fs.read_file(handle)
    require(signature == files['DLLIMG.SIG']['content'], 'SIG read differs')
    fs.close(handle)
    loader=fs.load_original(binary,row['module']['image_header_ram_bytes']) if load else None
    status,missing=fs.open('missing.bin')
    require(status==0xfffffffd and missing==0,'Missing-file control was accepted')
    fs.verify_closed_files()
    require(not any(OUTPUT<=address<OUTPUT+len(binary) for address in fs.visits),
            'File-read output was executed as code')
    if not load:
        require(not any(IMAGE<=address<DESCRIPTOR for address in fs.visits),
                'Modified module bytes were executed')
    require(all(fs.visits[a]>0 for a in (0x1e86ce,0x1e8046,0xfeb36,
        0x2fb988,0x123f6c,0x11d678,0x123920,0x3324b8)),
        'Original filesystem path was not executed')
    return {'voice': Path(row['file']).name, 'kind':kind,'package_sha256': sha(data),
            'mount_parser_active': True, 'original_file_open_status': status,
            'dll_bytes': len(binary), 'dll_sha256': sha(binary),
            'signature_bytes':len(signature),'signature_sha256':sha(signature),
            'original_loader':loader,
            'metadata_expected_byte_sum':int(row['module']['metadata']['dll_chksum'],0),
            'actual_dll_byte_sum':sum(binary)&0xffffffff,
            'metadata_byte_sum_matches':int(row['module']['metadata']['dll_chksum'],0)==(sum(binary)&0xffffffff),
            'missing_file_rejected':True,'all_native_file_objects_closed':True,
            'file_read_output_executed_as_code':False,
            'modified_instructions_executed':False if kind!='original' else None,
            'equals_independent_extraction': True, 'geometry': geometry,
            'native_calls': fs.calls, 'lower_reads': fs.reads,
            'original_functions_executed': {hex(a): fs.visits[a] for a in
                (0x1e86ce,0x1e8046, 0xfeb36, 0x2fba70, 0x2fb988, 0x122fbc,
                 0x123f6c, 0x11d678, 0x123920, 0x3324b8, 0x1fb3a2,0x3c44bc,
                 0x1fb304,INIT,0x3b3294,0x3b331a,0x2356bc)},
            'all_passed': True}


def mutate_member(data, record, geometry, transform):
    # In-memory only: file allocation/size/metadata stay unchanged. No modified
    # package, module or SIG is written to disk or installed.
    changed=bytearray(data);payload=bytearray(record['content']);transform(payload)
    block_bytes=geometry['block_bytes']
    for n,block in enumerate(record['blocks']):
        chunk=payload[n*block_bytes:(n+1)*block_bytes]
        changed[block*block_bytes:block*block_bytes+len(chunk)]=chunk
    return bytes(changed)


def controls(stock,row):
    original=(ROOT/row['file']).read_bytes();files,g=parse_image(original)
    flipped=mutate_member(original,files['DLLIMG.BIN'],g,
                          lambda payload:payload.__setitem__(0x100,payload[0x100]^1))
    zeros=mutate_member(original,files['DLLIMG.SIG'],g,
                        lambda payload:payload.__setitem__(slice(None),bytes(len(payload))))
    changed=[run(stock,row,flipped,'dll_payload_changed_metadata_sum_stale'),
             run(stock,row,zeros,'signature_content_zeroed')]
    require(not changed[0]['metadata_byte_sum_matches'],'DLL control did not change byte sum')
    require(changed[1]['metadata_byte_sum_matches'],'SIG control unexpectedly changed DLL')
    rejected=[]
    for kind,offset,value in [('bad_image_magic',0x10,original[0x10]^1),
                             ('bad_vendor_magic',0x41,original[0x41]^1),
                             ('invalid_sector_size',0x61,8),
                             ('short_initial_sector',None,None)]:
        data=bytearray(original)
        if offset is None:data=data[:400]
        else:data[offset]=value
        fs=VpmFilesystem(stock,bytes(data));active=fs.mount()
        require(not active,'Malformed header became an active DSK volume')
        rejected.append({'kind':kind,'original_remount_and_parser_executed':
                         fs.visits[0x1e86ce]>0 and fs.visits[0x1e8046]>0,
                         'active_volume':active,'lower_reads':fs.reads,'all_passed':True})
    return changed,rejected


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--diagnostic',action='store_true')
    args=parser.parse_args()
    stock=NativeImage()
    rows=[r for r in json.loads((ROOT/'evidence/firmware-analysis/tts-vpm-containers.json').read_text())['containers']
          if r['native_module_container']]
    if args.diagnostic: rows=rows[:1]
    cases=[run(stock,row,load=True) for row in rows]
    changed,rejected=([],[]) if args.diagnostic else controls(stock,rows[0])
    dependencies={str(Path(__file__).relative_to(ROOT)):sha(Path(__file__).read_bytes())}
    for module in list(sys.modules.values()):
        path=getattr(module,'__file__',None)
        if path and Path(path).resolve().parent==ROOT/'scripts' and path.endswith('.py'):
            dependencies[str(Path(path).resolve().relative_to(ROOT))]=sha(Path(path).read_bytes())
    for path in [ROOT/'evidence/firmware-analysis/tts-vpm-containers.json',
                 *[ROOT/row['file'] for row in rows]]:
        dependencies[str(path.relative_to(ROOT))]=sha(path.read_bytes())
    out={'updated_utc':datetime.now(timezone.utc).isoformat(), 'stock_sha256':EXPECTED,
         'cases':cases,'all_passed':True,'diagnostic_only':args.diagnostic,
         'memory_only_content_controls':changed,'header_rejection_controls':rejected,
         'source_sha256':dependencies,
         'lower_filesystem_reads_do_not_gate_on_dllinfo_checksum_or_SIG_in_tested_cases':True,
         'original_loader_initialized_three_original_modules':not args.diagnostic,
         'device_io':False,'device_install_candidate':False,
         'signature_enforcement_verified':False,
         'limits':'Original cache remount/parser/directory/read/close and original DLL initializer/bootstrap via all five original file callbacks. Three original modules match the independent synthetic-callback loader runtime and40 trampolines. Modified-content controls only mount/read/close; modified instructions are never executed. Byte I/O, initialized filesystem/cache inventory, temporary pathname heap, cache sync, mutex, IRQ and nonblank ASCII CRT classification are fixtures. The outer generic FAT open/mapped-region manager, high-level voice-selection/metadata/checksum/SIG policy and real hardware are not exercised. No changed VPM is saved. This is not proof a modified package can be installed or high-level signatures are unused.'}
    if not args.diagnostic:
        path=ROOT/'evidence/firmware-analysis/native-vpm-filesystem-emulation.json'
        path.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'diagnostic_only':args.diagnostic,'cases':len(cases),
                      'dll_bytes':[r['dll_bytes'] for r in cases],
                      'memory_content_controls':len(changed),'header_rejection_controls':len(rejected),
                      'recorded_dependencies':len(dependencies),'all_passed':True}))


if __name__=='__main__':main()
