#!/usr/bin/env python3
"""Exercise exact stock incoming AVDTP media dispatch with synthetic RAM.

There is no Bluetooth/device I/O. Only mutex/logging and (for non-media
controls) signalling/multiplex dispatch are intercepted. The LCID lookup,
media handler, and callback veneer execute the backed-up Thumb instructions.
"""
from datetime import datetime, timezone
import hashlib
import json
import struct

import unicorn
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import (UC_CPU_ARM_1176, UC_ARM_REG_R0, UC_ARM_REG_R1,
                               UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP,
                               UC_ARM_REG_LR, UC_ARM_REG_PC)
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_sdp_activation import trace

HANDLER = 0x50bbc0
LOOKUP = 0x525138
VENEER = 0x42758e
STATE = 0x3a88ef0
CHANNELS = 0x3a88f50
CONTEXT = 0x3a88eb8
CAPTURE = 0x10010
RETURN = 0x10000
PACKET_PAGE = 0x09101000
PEER = bytes.fromhex('010203040506')  # Synthetic, not the authorized device.


class MediaDispatch:
    """Attach stock dispatch to a new emulator or an existing loaded module."""
    def __init__(self, stock, emulator=None, callback=CAPTURE | 1):
        self.uc = emulator or Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.standalone = emulator is None
        if self.standalone:
            self.uc.ctl_set_cpu_model(UC_CPU_ARM_1176)
            self.uc.mem_map(0x02000000, 0x10000)
            self.uc.mem_map(RETURN, 0x1000)
            self.uc.mem_map(PACKET_PAGE, 0x1000, unicorn.UC_PROT_READ)
            self.uc.mem_map(0xf50000, 0x1000)
        for page in (0x50b000, 0x525000, 0x427000, 0x552000, 0x524000):
            self.uc.mem_map(page, 0x1000)
            self.uc.mem_write(page, stock.read(page, 0x1000))
        self.uc.mem_map(0x3a88000, 0x2000)
        self.hooks = {0x5523de: 'lock', 0x5523fc: 'unlock',
                      0x5525bc: 'log', 0x5247fc: 'signalling',
                      0x524398: 'multiplex'}
        for address in self.hooks:
            self.uc.mem_write(address, b'\x70\x47')
        if callback == CAPTURE | 1:
            self.uc.mem_write(CAPTURE, b'\x70\x47')
        self.callback = callback
        self.visited, self.events, self.calls = set(), [], []
        self.instruction_count = 0
        self.mutex_held = False
        self.uc.hook_add(UC_HOOK_CODE, self.observe)

    def configure(self, slot=0, channel_index=0, context_index=0,
                  state=8, channel_type=255, mismatch=False):
        if not 0 <= slot < 3 or not 0 <= channel_index < 12 or not 0 <= context_index < 2:
            raise ValueError('Synthetic indices exceed observed tables')
        self.uc.mem_write(CONTEXT, bytes(0x230))
        channel = CHANNELS+channel_index*8
        self.uc.mem_write(channel, struct.pack('<H', 0x1234))
        self.uc.mem_write(channel+4, bytes([channel_type]))
        self.uc.mem_write(channel+6, bytes([slot]))
        sep = STATE+slot*32
        self.uc.mem_write(sep, struct.pack('<I', self.callback))
        self.uc.mem_write(sep+0xf, bytes([(channel_index+1) % 12 if mismatch else channel_index]))
        self.uc.mem_write(sep+0x10, bytes([7]))
        self.uc.mem_write(sep+0x11, bytes([context_index]))
        self.uc.mem_write(sep+0x12, bytes([state]))
        self.uc.mem_write(CONTEXT+context_index*28+0x16, PEER)
        self.slot, self.channel_index = slot, channel_index
        self.visited, self.events, self.calls = set(), [], []
        self.instruction_count = 0
        self.mutex_held = False

    def observe(self, uc, address, size, data):
        # Instruction hooks are used for control-flow evidence only. They do
        # not establish complete memory-access traces or bounds safety.
        self.instruction_count += 1
        if address in (HANDLER, LOOKUP, VENEER): self.visited.add(address)
        if address in self.hooks:
            name = self.hooks[address]
            if name == 'lock':
                if self.mutex_held: raise ValueError('Mutex locked twice')
                self.mutex_held = True
            elif name == 'unlock':
                if not self.mutex_held: raise ValueError('Mutex unlocked twice')
                self.mutex_held = False
            self.events.append(name)
            uc.reg_write(UC_ARM_REG_R0, 0)
        if address == (self.callback & ~1):
            event, status, handle, payload = [uc.reg_read(r) for r in
                (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
            length = struct.unpack('<I', uc.mem_read(uc.reg_read(UC_ARM_REG_SP), 4))[0]
            if self.mutex_held: raise ValueError('Media callback invoked under stock mutex')
            if length > 4096: raise ValueError('Synthetic packet length exceeds test capacity')
            info = bytes(uc.mem_read(handle+4, 8))
            self.calls.append({'event':event, 'status':status,
                               'local_seid':info[0], 'remote_seid':info[1],
                               'synthetic_peer_hex':info[2:].hex(),
                               'payload_pointer':hex(payload), 'length':length,
                               'payload_hex':bytes(uc.mem_read(payload, length)).hex(),
                               'mutex_released_before_callback':True})
            if self.callback == CAPTURE | 1: uc.reg_write(UC_ARM_REG_R0, 0)
        if self.standalone and address == RETURN: uc.emu_stop()

    def run(self, packet, lcid=0x1234):
        if not self.standalone: raise ValueError('Use the loaded machine call interface for integration')
        if not 0 < len(packet) <= 4096: raise ValueError('Packet outside guarded page')
        source = PACKET_PAGE+4096-len(packet)
        self.uc.mem_write(source, packet)
        self.uc.reg_write(UC_ARM_REG_SP, 0x0200f000)
        self.uc.reg_write(UC_ARM_REG_LR, RETURN | 1)
        for register,value in [(UC_ARM_REG_R0,lcid),(UC_ARM_REG_R1,source),(UC_ARM_REG_R2,len(packet))]:
            self.uc.reg_write(register, value)
        self.uc.emu_start(HANDLER | 1, RETURN+2, timeout=1000000, count=3000)
        if self.uc.reg_read(UC_ARM_REG_PC) != RETURN or self.mutex_held:
            raise ValueError('Handler did not return cleanly and release mutex')
        return {'return_value':self.uc.reg_read(UC_ARM_REG_R0), 'callbacks':self.calls,
                'hook_events':self.events, 'stock_lcid_lookup_executed':LOOKUP in self.visited,
                'stock_bx_r7_veneer_executed':VENEER in self.visited,
                'instructions_executed':self.instruction_count}


def main():
    stock = NativeImage()
    if stock.read(VENEER,2) != b'\x38\x47': raise ValueError('Expected original BX R7 callback veneer')
    packet = bytes.fromhex('80600001000000010000000101')+bytes(range(32))
    scenarios = [
        ('first_streaming_endpoint',{},0x1234,0,0),
        ('third_endpoint_last_channel',{'slot':2,'channel_index':11,'context_index':1},0x1234,0,0),
        ('non_streaming_status_forwarded',{'state':1},0x1234,0,0x131),
        ('endpoint_channel_mismatch',{'mismatch':True},0x1234,0,None),
        ('unknown_channel',{},0x4567,0x2914,None),
        ('signalling_channel_control',{'channel_type':0},0x1234,0,None),
        ('multiplex_channel_control',{'channel_type':1},0x1234,0,None),
    ]
    cases=[]
    for name, setup, lcid, wanted_return, wanted_status in scenarios:
        machine=MediaDispatch(stock)
        machine.configure(**setup)
        result=machine.run(packet,lcid)
        if result['return_value'] != wanted_return or not result['stock_lcid_lookup_executed']:
            raise ValueError('Unexpected stock result: '+name)
        if wanted_status is None:
            if result['callbacks'] or result['stock_bx_r7_veneer_executed']:
                raise ValueError('Unexpected media callback: '+name)
        else:
            if len(result['callbacks']) != 1 or not result['stock_bx_r7_veneer_executed']:
                raise ValueError('Missing callback: '+name)
            call=result['callbacks'][0]
            if (call['event'],call['status'],call['local_seid'],call['remote_seid'],
                call['synthetic_peer_hex'],call['length'],call['payload_hex']) != (
                    0xf1,wanted_status,setup.get('slot',0)+1,7,PEER.hex(),len(packet),packet.hex()):
                raise ValueError('Callback ABI/payload mismatch: '+name)
        if name=='signalling_channel_control' and 'signalling' not in result['hook_events']:
            raise ValueError('Missing signalling control')
        if name=='multiplex_channel_control' and 'multiplex' not in result['hook_events']:
            raise ValueError('Missing multiplex control')
        cases.append({'name':name,'synthetic_setup':setup,**result,'passed':True})
    report={'updated_utc':datetime.now(timezone.utc).isoformat(),'stock_sha256':EXPECTED,
            'cpu_model':'ARM1176','unicorn_version':unicorn.__version__,
            'incoming_l2cap_handler':hex(HANDLER),'lcid_lookup':hex(LOOKUP),
            'callback_veneer':hex(VENEER),'callback_veneer_instruction':'bx r7',
            'handler_code_sha256':hashlib.sha256(stock.read(HANDLER,0x50be18-HANDLER)).hexdigest(),
            'channel_table':{'base':hex(CHANNELS),'slots':12,'stride':8,
                             'lcid_offset':0,'type_offset':4,'sep_index_offset':6,'direct_media_type':255},
            'local_sep':{'base':hex(STATE),'slots':3,'stride':32,'callback_offset':0,
                         'channel_index_offset':15,'remote_seid_offset':16,
                         'context_index_offset':17,'state_offset':18,'streaming_state':8},
            'context_table':{'base':hex(CONTEXT),'stride':28,'peer_offset':22},
            'callback_abi':{'r0':'event 0xf1','r1':'status 0 or 0x131',
                            'r2':'temporary handle: local SEID+4, remote SEID+5, peer+6..11',
                            'r3':'raw media packet pointer','stack_word_0':'packet byte count',
                            'handle_first_four_bytes_initialized_by_handler':False,
                            'packet_parsed_or_decoded_by_dispatch':False},
            'cases':cases,'all_passed':True,'device_io':False,
            'real_endpoint_registration_verified':False,'speaker_playback_verified':False,
            'handler_instructions':trace(stock,HANDLER,500),
            'lookup_instructions':trace(stock,LOOKUP,180),
            'limitations':'Synthetic endpoint/channel/context RAM. Mutex and logger controlled; signalling/multiplex controls are stubbed. Real LCID lookup and BX R7 run unchanged. Raw packets reach only a capture callback; this does not prove live endpoint registration, negotiation, Bluetooth reception, SBC decoding or speaker playback.'}
    output=ROOT/'evidence/firmware-analysis/avdtp-media-dispatch-emulation.json'
    output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'output':str(output),'cases':len(cases),'all_passed':True,'device_io':False}))


if __name__=='__main__': main()
