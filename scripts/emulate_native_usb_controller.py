#!/usr/bin/env python3
"""Probe native endpoint initialization, reset IRQ and device EP0 offline.

Indexed writes and FIFO bytes are recorded against synthetic RAM, not a full
USB controller model. FIFO input, IRQ publication and controller acknowledgement
are explicit boundaries. Stock ARM/Thumb code is unmodified and protected.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import sys

from unicorn import UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R4, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_CPSR
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from emulate_native_projection_io import Probe, USB, DEVICE, CONFIG, require

SETUP, EP0, SPEED, PACKETS, MODE = 0x2d1ff14,0x2d1ff20,0xf08fac,0xf08fb0,0xf08fd1
WORKSPACE, WORK_BYTES = 0x2d1ff00,0x200


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


class ControllerProbe(Probe):
    def __init__(self, stock):
        super().__init__(stock)
        self.index, self.register_writes, self.fifo_in, self.fifo_out = 0, [], [], []
        self.fifo_reads = 0
        self.uc.hook_add(UC_HOOK_MEM_WRITE,self.write_register,begin=USB,end=USB+0x100)

    def observe(self, uc, address, size, user):
        if address == 0x1bcc26:
            require(uc.reg_read(UC_ARM_REG_R4) == USB+0x20 and self.fifo_in,
                    'FIFO reader left explicit input fixture')
            # Stage data before the unmodified LDRB. This is a data fixture,
            # not a replacement for the reader function or instruction.
            uc.mem_write(USB+0x20,bytes((self.fifo_in.pop(0),)))
            self.fifo_reads += 1
        if address in (0x23c2e8,0x2fcf44):
            lr = uc.reg_read(UC_ARM_REG_LR)
            if address == 0x23c2e8:
                require(lr == 0x1bb2d3 and uc.reg_read(UC_ARM_REG_R0) == 60,
                        'Unexpected hardware interrupt acknowledgement caller')
                row = {'function':hex(address),'boundary':'controller_IRQ_acknowledgement_only',
                       'caller_LR':hex(lr),'argument':60}
            else:
                require(lr == 0x1bb269 and
                        [uc.reg_read(UC_ARM_REG_R0),uc.reg_read(UC_ARM_REG_R1)] == [0x12345678,0x2000],
                        'Unexpected kernel event publication')
                row = {'function':hex(address),'boundary':'kernel_event_publication_only',
                       'caller_LR':hex(lr),'arguments':[0x12345678,0x2000]}
            self.fixtures.append(row)
            self.visits[address] += 1
            uc.reg_write(UC_ARM_REG_R0,0)
            uc.reg_write(UC_ARM_REG_PC,lr)
            return
        super().observe(uc,address,size,user)

    def write_register(self, uc, access, address, size, value, user):
        if address == USB+0xe:
            require(size == 1,'Unexpected endpoint index width')
            self.index = value
        row = {'offset':hex(address-USB),'bytes':size,'value':value,'synthetic_endpoint_index':self.index}
        self.register_writes.append(row)
        if address == USB+0x20:
            require(size == 1,'Unexpected EP0 FIFO output width')
            self.fifo_out.append(value)

def prepare(p,mode=1):
    p.guarded(WORKSPACE,WORK_BYTES)
    p.uc.mem_write(WORKSPACE,bytes(WORK_BYTES))
    p.uc.mem_write(MODE,bytes((mode,)))
    p.uc.mem_write(SPEED,bytes(0x14))
    p.uc.mem_write(USB,bytes(0x100))


def indexed_fields(p,index):
    return {r['offset']:r['value'] for r in p.register_writes if r['synthetic_endpoint_index']==index
            and r['offset'] not in ('0xe','0x6','0x8','0xb')}


def endpoints(stock,speed):
    p = ControllerProbe(stock)
    prepare(p)
    p.uc.mem_write(SPEED,bytes((speed,)))
    p.call(0x1bb0d6)
    p.call(0x1bb176)
    require(not p.fixtures,'Endpoint initializer crossed unexpected function boundary')
    require(p.visits[0x307344] == 3,'Original ARM FIFO sizing helper not executed')
    require(p.visits[0x6e4724] == 3,'Original ARM CLZ helper body not executed')
    sizes = [p.word(PACKETS+n*4) for n in range(3)]
    require(sizes == ([64,512,512] if speed else [16,16,64]),'Native packet sizes differ')
    expected_fifo = [{1:16,2:32,3:36},{1:16,2:144,3:160}][speed]
    expected_max = [{1:64,2:16,3:16},{1:512,2:64,3:512}][speed]
    for n in (1,2,3):
        fields = indexed_fields(p,n)
        key = '0x14' if n==1 else '0x10'
        fifo_key = '0x66' if n==1 else '0x64'
        require(fields[key] == expected_max[n] and fields[fifo_key] == expected_fifo[n],
                'Endpoint register layout differs')
    require(not any(r['offset']=='0x60' for r in p.register_writes),
            'Literal10200060 actually accessed DEVCTL')
    p.guard_ok(WORKSPACE,WORK_BYTES)
    return {'synthetic_speed_flag':speed,'native_packet_size_words':sizes,
        'indexed_register_writes':p.register_writes,'all_passed':True,
        'original_ARM_FIFO_size_helper_calls':3,'function_fixtures':[],
        'original_ARM_CLZ_body_calls':3,
        'workspace_guards_intact':True,'DEVCTL_offset60_not_accessed':True,
        'indexed_register_side_effects_not_hardware_emulated':True}


def reset_irq(stock,mode,speed,suspend=False):
    p = ControllerProbe(stock)
    prepare(p,mode)
    p.uc.mem_write(USB+0xa,bytes((5 if suspend else 4,)))
    p.uc.mem_write(USB+1,bytes((0x10 if speed else 0,)))
    p.uc.mem_write(0xf08fbc,b'\x01\x77\x66\x55\x44')
    p.put(0xf08fd4,0x12345678)
    p.uc.mem_write(SPEED+2,b'\x00\x00')
    before_cpsr = p.uc.reg_read(UC_ARM_REG_CPSR)
    p.call(0x1bb22c)
    after_cpsr = p.uc.reg_read(UC_ARM_REG_CPSR)
    require((before_cpsr&0xc0)==(after_cpsr&0xc0),'Original IRQ mask save/restore differs')
    require(p.visits[0x21b6cc] == p.visits[0x21b6dc] == 1,'Original ARM IRQ-mask helpers bypassed')
    require(p.data(SPEED,1)==bytes((speed,)),'IRQ reset did not derive speed from POWER bit4')
    require(p.data(0xf08fbd,4)==bytes(4),'Native device state not reset')
    expected_pid = 0x2548 if mode else 3
    descriptor = p.data(DEVICE,18)
    require(struct.unpack_from('<H',descriptor,10)[0] == expected_pid,'Reset descriptor personality differs')
    require(p.visits[0x1bcf6c] == p.visits[0x1bb176] == p.visits[0x1bcb20] == 1,
            'Original reset/descriptor/endpoint chain not executed')
    expected_boundaries = (['kernel_event_publication_only'] if suspend else [])+['controller_IRQ_acknowledgement_only']
    require([f['boundary'] for f in p.fixtures] == expected_boundaries,'Unexpected IRQ fixtures')
    p.guard_ok(WORKSPACE,WORK_BYTES)
    configuration_bytes = int.from_bytes(p.data(CONFIG+2,2),'little')
    require(9<=configuration_bytes<=128,'Unexpected native configuration size')
    return {'synthetic_descriptor_mode':mode,'synthetic_POWER_HSMODE_bit':speed,
        'synthetic_suspend_and_reset':suspend,'device_descriptor_hex':descriptor.hex(),
        'configuration_hex':p.data(CONFIG,configuration_bytes).hex(),
        'configuration_capture_bytes':configuration_bytes,'indexed_register_writes':p.register_writes,
        'IRQ_mask_bits_restored':True,'original_ARM_IRQ_helpers_executed':True,
        'function_fixtures':p.fixtures,'workspace_guards_intact':True,'all_passed':True,
        'read_clear_interrupts_FIFO_endpoint_banking_or_physical_IRQ_not_emulated':True}


def setup(stock,name,packet,*,speed=1,expect_pending=None,expect_fifo=None,expect_stall=False):
    p = ControllerProbe(stock)
    prepare(p)
    p.uc.mem_write(SPEED,bytes((speed,)))
    p.call(0x1bb0d6)
    p.call(0x1bcf6c)
    p.register_writes.clear()
    require(len(packet)==8,'Only valid-width USB setup fixtures supported here')
    p.fifo_in = list(packet)
    p.uc.mem_write(USB+0x18,b'\x08')
    p.uc.mem_write(USB+0x12,b'\x01\x00')
    p.call(0x1bcc38)
    require(p.fifo_reads == 8 and not p.fifo_in and p.data(SETUP,8)==packet,
            'Original setup FIFO byte reader bypassed')
    require(p.visits[0x1bcc12] == 1 and not p.fixtures,'EP0 request crossed unexpected function boundary')
    if expect_pending is not None:
        require(p.data(EP0+1,2)==bytes((1,expect_pending)),'SET_ADDRESS pending state differs')
        require(p.data(USB,1)==b'\x00','Device address applied before completion')
        p.uc.mem_write(USB+0x12,b'\x02\x00')
        p.call(0x1bd120)
        require(p.data(USB,1)==bytes((expect_pending,)) and p.data(EP0+1,1)==b'\x00',
                'Original EP0 completion did not apply pending address')
    if expect_fifo is not None:
        require(bytes(p.fifo_out)==expect_fifo,'Native GET_DESCRIPTOR data differs')
    if expect_stall:
        require(int.from_bytes(p.data(USB+0x12,2),'little') & 0x20,'Unknown descriptor did not set stall')
    p.guard_ok(WORKSPACE,WORK_BYTES)
    require(not any(r['offset']=='0x60' for r in p.register_writes), 'EP0 used DEVCTL')
    return {'name':name,'setup_packet_hex':packet.hex(),'synthetic_speed_flag':speed,
        'FIFO_input_fixture_bytes':8,'original_FIFO_reader_executed':True,
        'FIFO_input_staged_before_original_LDRB':'0x1bcc26',
        'FIFO_output_hex':bytes(p.fifo_out).hex(),'indexed_register_writes':p.register_writes,
        'pending_address_applied_only_after_EP0_completion':expect_pending is not None,
        'unknown_descriptor_stall_case':expect_stall,'function_fixtures':[],
        'workspace_guards_intact':True,'all_passed':True,
        'USB_packet_ack_status_phase_or_actual_bus_transfer_verified':False}


def packet(bm,req,value,index,length):
    return struct.pack('<BBHHH',bm,req,value,index,length)


def fifo_size(stock,value,expected):
    p = ControllerProbe(stock)
    actual = p.call(0x1bb154,value)
    require(actual==expected and not p.fixtures and p.visits[0x6e4724]==1,
            'Native FIFO size validation differs')
    return {'input':value,'returned':actual,'original_ARM_CLZ_body_executed':True,
            'all_passed':True,'function_fixtures':[]}


def main():
    stock = NativeImage()
    image = RuntimeImage(stock)
    require(image.word(0x1bb310)==USB+0x60 and image.word(0x1bcf18)==USB+0x20,
            'Native controller constants differ')
    endpoint_cases = [endpoints(stock,s) for s in (0,1)]
    irq_cases = [reset_irq(stock,m,s) for m,s in ((0,0),(0,1),(1,0),(1,1))]+[
        reset_irq(stock,1,1,True)]
    reference = bytes.fromhex(irq_cases[3]['device_descriptor_hex'])
    setup_cases = [setup(stock,'SET_ADDRESS_'+str(addr),packet(0,5,addr,0,0),expect_pending=addr)
                   for addr in (1,42,127)]
    setup_cases += [setup(stock,'GET_DEVICE_DESCRIPTOR_'+str(n),packet(0x80,6,0x100,0,n),
                          expect_fifo=reference[:min(n,18)]) for n in (8,18,64)]
    setup_cases += [setup(stock,'unsupported_descriptor_type6_stalls',packet(0x80,6,0x600,0,18),expect_stall=True)]
    size_cases = [fifo_size(stock,n,result) for n,result in
                  ((0,0),(8,0),(16,1),(64,3),(512,6),(4096,9),(8192,0),(24,0))]
    deps = {Path(__file__).resolve(),ROOT/'evidence/firmware-analysis/main_02bd.bin'}
    for module in list(sys.modules.values()):
        filename = getattr(module,'__file__',None)
        if filename and Path(filename).resolve().parent==ROOT/'scripts' and filename.endswith('.py'):
            deps.add(Path(filename).resolve())
    output = {'updated_utc':datetime.now(timezone.utc).isoformat(),
        'exact_target':{'HWID':1352,'software':'8.00','stock_sha256':EXPECTED},
        'source_sha256':{str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in sorted(deps)},
        'endpoint_cases':endpoint_cases,'reset_IRQ_cases':irq_cases,'EP0_setup_cases':setup_cases,
        'FIFO_size_cases':size_cases,
        'all_passed':True,'stock_code_mappings_write_protected':True,
        'device_io':False,'firmware_modified':False,'device_install_candidate':False,
        'USB_host_AOA_VBUS_or_phone_session_verified':False,
        'verification_history':{
            'initial_full_speed_endpoint3_FIFO_offset_expectation_corrected_from48_to36':True,
            'FIFO_input_fixture_now_staged_at_original_LDRB_code_site':True,
            'memory_read_hook_attempt_did_not_supply_FIFO_bytes_and_was_not_a_passing_result':True,
            'complete_fresh_run_after_fixture_corrections':True},
        'scope':'Original packet/FIFO sizing and endpoint initialization; reset IRQ with original ARM '
            'interrupt-mask save/restore and runtime descriptors; byte-FIFO setup reader, GET_DESCRIPTOR '
            'and delayed SET_ADDRESS execute against synthetic registers/RAM. FIFO input is a data '
            'fixture. IRQ acknowledgement and optional kernel event publication are function fixtures. '
            'No true indexed banking, read-clear IRQ, FIFO bus behavior, status handshakes, physical '
            'controller, host enumeration, VBUS, phone or installed App.'}
    path = ROOT/'evidence/firmware-analysis/native-usb-controller-emulation.json'
    path.write_text(json.dumps(output,indent=2)+'\n')
    print(json.dumps({'evidence':str(path.relative_to(ROOT)),'all_passed':True,
        'endpoint_cases':len(endpoint_cases),'reset_IRQ_cases':len(irq_cases),'EP0_cases':len(setup_cases),
        'FIFO_size_cases':len(size_cases),
        'source_dependencies':len(deps)}))


if __name__=='__main__':
    main()
