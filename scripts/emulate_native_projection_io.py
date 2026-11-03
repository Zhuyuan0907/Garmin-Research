#!/usr/bin/env python3
"""Offline USB-device and SGA ABI probes for a native projection receiver.

Exact stock instructions execute against synthetic RAM/register images. The
only function fixture is kernel event publication in the USB transmit probe.
No host controller, real register, display, phone, device or firmware write.
"""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import sys

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import UC_PROT_READ, UC_PROT_EXEC
from unicorn.arm_const import (UC_CPU_ARM_1176, UC_ARM_REG_R0,
    UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP,
    UC_ARM_REG_LR, UC_ARM_REG_PC)
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from analyze_sdp_activation import trace

REGS = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)
RETURN, STACK = 0x10000, 0x0800f000
DEVICE, CONFIG = 0x02d1ff2c, 0x02d1ff3f
TXBUF, TXREC, RXREC = 0x02d1452c, 0x02d1653c, 0x02d1652c
CSWBUF, BOT = 0x0127b600, 0x00f003f4
USB, SGA = 0x10200000, 0x101c2000
SGACTX, L1 = 0x034dd21c, 0x03e00000
IDS = [2, 0x62, 0x2d, 0, 0xd, 0xf0, 5, 0xb1]


def sha(blob): return hashlib.sha256(blob).hexdigest()
def require(condition, message):
    if not condition: raise ValueError(message)


class Probe:
    def __init__(self, stock):
        self.uc = uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.ctl_set_cpu_model(UC_CPU_ARM_1176)
        for section in stock.copies:
            start = section['runtime_start'] & ~4095
            end = (section['runtime_end']+4095) & ~4095
            uc.mem_map(start, end-start)
            uc.mem_write(section['runtime_start'],
                         stock.read(section['load_start'], section['size']))
            if section['runtime_start'] != 0xf00000:
                uc.mem_protect(start, end-start, UC_PROT_READ | UC_PROT_EXEC)
        for start, size in [(RETURN,4096),(0x08000000,0x10000),
                            (0x127b000,0x2000),(0x2d14000,0x3000),
                            (0x2d1f000,0x2000),(0x34dd000,4096),
                            (L1,0x4000),(USB,4096),(SGA,4096)]:
            uc.mem_map(start,size)
        self.visits, self.fixtures = Counter(), []
        self.done = False
        uc.hook_add(UC_HOOK_CODE,self.observe)

    def put(self, address, value):
        self.uc.mem_write(address,struct.pack('<I',value & 0xffffffff))

    def word(self, address):
        return struct.unpack('<I',self.uc.mem_read(address,4))[0]

    def data(self, address, size): return bytes(self.uc.mem_read(address,size))

    def guarded(self, address, size):
        self.uc.mem_write(address-32,b'\xa5'*(size+64))

    def guard_ok(self, address, size):
        require(self.data(address-32,32) == self.data(address+size,32) == b'\xa5'*32,
                'Synthetic buffer guard modified')

    def observe(self, uc, address, size, user):
        if address == RETURN:
            self.done=True
            uc.emu_stop()
            return
        self.visits[address]+=1
        if address == 0x2fcf44:
            # Transmit enqueue wakes a worker; the worker/IRQ is not emulated.
            require(uc.reg_read(UC_ARM_REG_LR) == 0x1bffcf,
                    'Unexpected event-publication caller')
            args=[uc.reg_read(r) for r in REGS[:2]]
            require(args == [0x12345678,0x400], 'Unexpected queue event')
            self.fixtures.append({'function':'0x2fcf44',
                'boundary':'kernel_event_publication_only','arguments':args})
            uc.reg_write(UC_ARM_REG_R0,0)
            uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))

    def call(self, entry, *arguments, thumb=True):
        self.done=False
        for reg,value in zip(REGS,arguments): self.uc.reg_write(reg,value)
        self.uc.reg_write(UC_ARM_REG_SP,STACK)
        self.uc.reg_write(UC_ARM_REG_LR,RETURN+1)
        self.uc.emu_start(entry+int(thumb),0,timeout=5_000_000,count=100_000)
        require(self.done,'Original function did not return within bound')
        require(self.uc.reg_read(UC_ARM_REG_SP)==STACK,'Stack was not restored')
        return self.uc.reg_read(UC_ARM_REG_R0)


def descriptors(stock, mode, bulk_packet, interrupt_packet):
    p=Probe(stock)
    p.guarded(DEVICE,CONFIG+39-DEVICE)
    p.uc.mem_write(0xf08fd1,bytes([mode]))
    p.put(0xf08fb4,bulk_packet)
    p.put(0xf08fb8,bulk_packet)
    p.put(0xf08fb0,interrupt_packet)
    p.call(0x1bcf6c)
    device=p.data(DEVICE,18)
    pid=0x2548 if mode else 3
    expected=bytes([18,1,0,2,0 if mode else 255,0 if mode else 255,
                    0 if mode else 255,64])+struct.pack('<HH',0x91e,pid)
    expected+=bytes([9,5,0,0,5,1] if mode else [1,0,0,0,0,1])
    require(device==expected,'Native USB device descriptor differs')
    header=bytes([9,2,32 if mode else 39,0,1,1,0,0x80,250])
    interface=bytes([9,4,0,0,2 if mode else 3,
                     8 if mode else 255,6 if mode else 255,
                     0x50 if mode else 255,0])
    def endpoint(address,kind,packet,interval=0):
        return bytes([7,5,address,kind])+struct.pack('<H',packet)+bytes([interval])
    config=header+interface+endpoint(0x83,2,bulk_packet)
    if not mode: config+=endpoint(0x82,3,interrupt_packet,1)
    config+=endpoint(1,2,bulk_packet)
    require(p.data(CONFIG,len(config))==config,'Native USB configuration differs')
    require(p.data(DEVICE+18,1)==b'\xa5','Unexpected gap write')
    require(p.data(CONFIG+len(config),39-len(config))==b'\xa5'*(39-len(config)),
            'Inactive descriptor tail changed')
    p.guard_ok(DEVICE,CONFIG+39-DEVICE)
    require(not p.fixtures,'Descriptor builder used function fixture')
    return {'mode_flag':mode,'mode_flag_address':'0xf08fd1',
            'fixture_packet_sizes':{'bulk':bulk_packet,'interrupt':interrupt_packet},
            'device_descriptor_hex':device.hex(),'configuration_hex':config.hex(),
            'VID':hex(0x91e),'PID':hex(pid),
            'interface_class_subclass_protocol':list(interface[5:8]),
            'endpoint_addresses':[0x83,1] if mode else [0x83,0x82,1],
            'role':'USB device descriptor, not USB host',
            'all_passed':True,'buffer_guards_intact':True,'function_fixtures':[]}


def transmit(stock, busy):
    p=Probe(stock)
    p.guarded(CSWBUF,13);p.guarded(TXBUF,13);p.guarded(TXREC,16)
    p.put(0xf08fd4,0x12345678)
    p.put(BOT+8,0x5a6b7c8d)
    p.put(BOT+0x1c,0xdeadbeef)
    p.uc.mem_write(BOT,b'\x01')
    p.uc.mem_write(BOT+5,bytes([busy]))
    returned=p.call(0x1be664,0x11223344,2)
    packet=struct.pack('<IIIB',0x53425355,0x5a6b7c8d,0x11223344,2)
    require(p.data(CSWBUF,13)==packet,'Native13-byte CSW differs')
    require(p.data(BOT,1)==b'\0','Native CSW completion flag not cleared')
    require(p.data(BOT+5,1)==b'\x01','In-flight gate differs')
    if busy:
        require(returned==0 and p.word(BOT+0x1c)==0xdeadbeef,
                'Busy request altered transfer accounting')
        require(p.data(TXBUF,13)==b'\xa5'*13 and p.data(TXREC,16)==b'\xa5'*16,
                'Busy request queued USB payload')
        require(not p.fixtures and not p.visits[0x378c80],
                'Busy request reached copy/event boundary')
    else:
        require(returned==13 and p.word(BOT+0x1c)==0,'Queued result differs')
        require(p.data(TXBUF,13)==packet,'Actual stock ARM copy did not copy packet')
        require([p.word(TXREC+n) for n in range(0,16,4)]==[13,13,TXBUF,TXBUF],
                'Native queue record differs')
        require(len(p.fixtures)==1 and p.visits[0x378c80]==1,
                'Native copy/queue path not executed')
        require(all(p.visits[a]==1 for a in (0x1be63c,0x23c1c4,0x1bffc0)),
                'Native transport chain bypassed')
    for address,size in ((CSWBUF,13),(TXBUF,13),(TXREC,16)):p.guard_ok(address,size)
    return {'in_flight_fixture':busy,'native_status':returned,
            'CSW_hex':packet.hex(),'transfer_queued':not bool(busy),
            'original_ARM_copy_executed':bool(p.visits[0x378c80]),
            'function_fixtures':p.fixtures,'all_passed':True,
            'buffer_guards_intact':True,'worker_IRQ_real_transfer_executed':False}


def receive(stock, mode):
    p=Probe(stock);p.guarded(RXREC,16)
    p.uc.mem_write(0xf08fd0,bytes([mode]))
    p.uc.mem_write(USB+0xe,b'\xa5')
    p.uc.mem_write(USB+0x16,struct.pack('<H',0x55ab))
    p.call(0x23c14c,37)
    require([p.word(RXREC+n) for n in range(0,16,4)]==
            [0,37,0x2d1552c,0x2d1552c],'Receive record differs')
    expected=b'\xa5' if mode else b'\x01'
    require(p.data(USB+0xe,1)==expected,'Endpoint-selection write differs')
    require(p.data(USB+0x16,2)==struct.pack('<H',0x55ab if mode else 0x55aa),
            'Native register-bit clear differs')
    require(p.visits[0x1c00f2]==1 and not p.fixtures,'Receive native path bypassed')
    p.guard_ok(RXREC,16)
    return {'controller_path_flag_fixture':mode,'requested_bytes':37,
            'native_queue_record':[p.word(RXREC+n) for n in range(0,16,4)],
            'synthetic_register_index':p.data(USB+0xe,1)[0],
            'synthetic_register16':p.data(USB+0x16,2).hex(),
            'all_passed':True,'buffer_guards_intact':True,'function_fixtures':[]}


def graphics(stock, bad_id=None, valid_translation=True):
    p=Probe(stock);p.guarded(SGACTX,24)
    p.put(L1+(SGA>>20)*4,0x10100002 if valid_translation else 0)
    ids=IDS.copy()
    if bad_id is not None: ids[bad_id]^=1
    for index,value in enumerate(ids):p.put(SGA+0x7e0+index*4,value)
    translated=p.call(0x221e46,SGA)
    require(translated==(SGA if valid_translation else 0),'Native MMU translation differs')
    status=p.call(0x6f2fec,translated,thumb=False)
    expected=0 if valid_translation and bad_id is None else (13 if valid_translation else 11)
    require(status==expected,'Original graphics ID probe result differs')
    if not valid_translation:
        require(p.data(SGACTX,24)==b'\xa5'*24,'Null pointer altered graphics context')
    else:
        require(p.word(SGACTX)==SGA,'Original graphics probe did not store base')
        if bad_id is None:
            require([p.word(SGACTX+n) for n in (4,8,12,20)]==[0]*4,
                    'Graphics context not reset')
            require(p.word(SGACTX+16)==0xa5a5a5a5,'Unrelated context field changed')
        else:
            require(p.data(SGACTX+4,20)==b'\xa5'*20,'Failed ID probe reset context')
    register_controls=[]
    if expected==0:
        p.call(0x6f3804,translated,thumb=False)
        require(p.word(0xf204d8)==SGA,'Native hardware-base setter differs')
        for entry,name in ((0x6f3810,'clear_mask'),(0x6f3840,'set_mask')):
            for selector in (0,1,2):
                p.put(SGA+0x18,0xdeadbeef);p.put(SGA+0x60,0x5a5a3333)
                p.call(entry,selector,0xf0f0,thumb=False)
                expected_pair=[0xdeadbeef,0x5a5a3333]
                if selector in (0,1):
                    old=expected_pair[selector]
                    expected_pair[selector]=(old & ~0xf0f0) if name=='clear_mask' else (old | 0xf0f0)
                actual=[p.word(SGA+0x18),p.word(SGA+0x60)]
                require(actual==expected_pair,'Native SGA mask controls differ')
                register_controls.append({'operation':name,'selector':selector,
                                          'actual_register_pair':actual,'all_passed':True})
        p.put(SGA+0x14,0x1234);p.put(SGA+0x5c,0x5678)
        require(p.call(0x6f3870,0,thumb=False)==0x1234 and
                p.call(0x6f3870,1,thumb=False)==0x5678,'Native status selection differs')
        register_controls.append({'operation':'status_read','selectors':[0,1],
                                  'returned':[0x1234,0x5678],'all_passed':True})
    p.guard_ok(SGACTX,24)
    require(not p.fixtures,'Graphics probe used function fixture')
    return {'synthetic_L1_section_mapping':valid_translation,
            'translated_pointer':hex(translated),'mismatched_ID_index':bad_id,
            'synthetic_ID_words':ids,'probe_status':status,
            'native_register_controls':register_controls,'all_passed':True,
            'buffer_guards_intact':True,'function_fixtures':[],
            'actual_SGA_initialization_allocation_IRQ_or_pixels_executed':False}


def main():
    stock=NativeImage();image=RuntimeImage(stock)
    require(image.word(0x222148)==L1 and image.word(0x6f37f0)==SGACTX,
            'Exact firmware constants differ')
    usb_cases={'descriptors':[descriptors(stock,*args) for args in
                              [(0,64,16),(1,64,16),(1,512,64)]],
               'transmit':[transmit(stock,busy) for busy in (0,1)],
               'receive':[receive(stock,mode) for mode in (0,1)]}
    sga_cases=[graphics(stock)]+[graphics(stock,n) for n in range(8)]+[
        graphics(stock,valid_translation=False)]
    functions={hex(a):trace(image,a,2000) for a in
               (0x1bcf6c,0x1be63c,0x23c1c4,0x1bffc0,0x23c14c,0x1c00f2,0x221e46)}
    require(all(not f['unresolved_exits'] and not f['instruction_limit_reached']
                for f in functions.values()),'Incomplete bounded Thumb CFG')
    deps={Path(__file__).resolve(),ROOT/'evidence/firmware-analysis/main_02bd.bin'}
    for module in list(sys.modules.values()):
        filename=getattr(module,'__file__',None)
        if filename and Path(filename).resolve().parent==ROOT/'scripts' and filename.endswith('.py'):
            deps.add(Path(filename).resolve())
    output={'updated_utc':datetime.now(timezone.utc).isoformat(),
        'exact_target':{'HWID':1352,'software':'8.00','stock_sha256':EXPECTED},
        'source_sha256':{str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in sorted(deps)},
        'USB_cases':usb_cases,'SGA_cases':sga_cases,'bounded_Thumb_CFGs':functions,
        'all_passed':True,'device_io':False,'firmware_modified':False,
        'native_Android_Auto_running':False,'device_install_candidate':False,
        'stock_code_mappings_write_protected':True,
        'fixtures':'All unbacked data, stack, MMU page table, packet-size globals, mode flags, queue records and hardware registers are synthetic. Conditional code copies are mapped but actual boot flag is not observed. Kernel event publication is the only function fixture, once in accepted CSW enqueue. All SGA and descriptor/receive functions execute original bodies without function fixtures.',
        'scope':'USB device-mode descriptor builder (vendor and MSC),13-byte BOT CSW/queue/in-flight gate and receive register writes; native MMU section translation, SGA ID validation/base setter/register mask/status helpers. SGA full init/allocation/IRQ/drawing, USB controller side effects/FIFO/worker/IRQ/completion/speed negotiation and board ID/VBUS/host driver are not exercised. Not USB host/AOA or a real display/phone session.'}
    path=ROOT/'evidence/firmware-analysis/native-projection-io-emulation.json'
    path.write_text(json.dumps(output,indent=2)+'\n')
    print(json.dumps({'evidence':str(path.relative_to(ROOT)),'all_passed':True,
                      'USB_cases':7,'SGA_ID_translation_cases':10,
                      'SGA_register_controls':7,'source_dependencies':len(deps),'device_io':False}))


if __name__=='__main__':main()
