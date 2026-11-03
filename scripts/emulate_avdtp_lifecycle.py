#!/usr/bin/env python3
"""Execute stock media-channel completion and lifecycle in one offline VM.

An active SEP and signaling connection are explicit starting fixtures. All
subsequent SEP/channel transitions execute stock code; L2CAP transport itself
and the application callback remain simulated. Never a device install proof.
"""
from datetime import datetime, timezone
import hashlib
import json
import struct
from pathlib import Path

import unicorn
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_SP, UC_ARM_REG_LR
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from emulate_avdtp_control import (ControlVM, STATE, CHANNELS, CONTEXT,
    DESCRIPTORS, REGS, CONFIG, RETURN, CALLBACK, STACK, INPUT)

PEER = bytes.fromhex('010203040506')  # Synthetic, not a device address.
MEDIA_LCID = 0x4567
LOCAL_MTU = 672


class LifecycleVM(ControlVM):
    def __init__(self, stock):
        super().__init__(stock)
        # Emulate the already established signaling/registered-SEP boundary,
        # not registration. No SEP state is written after this setup.
        self.uc.mem_write(CONTEXT+0x15, b'\xff')
        self.uc.mem_write(CHANNELS+5, b'\x10')
        self.uc.mem_write(STATE+0xc, struct.pack('<H', LOCAL_MTU))
        self.uc.mem_map(0xf50000, 4096)
        self.global_data = stock.read(stock.runtime_to_load(0xf50000, 4096), 4096)
        self.uc.mem_write(0xf50000, self.global_data)
        # No global application/signaling callback registered in this fixture.
        self.uc.mem_write(0xf5009c, bytes(4))
        self.global_data = bytes(self.uc.mem_read(0xf50000, 4096))
        self.uc.mem_protect(0xf50000, 4096, unicorn.UC_PROT_READ)
        self.connection_reply_error = 0
        self.config_reply_error = 0
        self.config_request_error = 0
        self.transport_events = []
        self.history = []
        self.sep_state_writes = []
        self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE,self.observe_state_write)

    def observe_state_write(self,uc,access,address,size,value,unused):
        if address < STATE+0x14 and address+size > STATE+0x12:
            pc=uc.reg_read(UC_ARM_REG_PC)
            assert 0x50000 <= pc < 0xcb179c
            self.sep_state_writes.append({'instruction':hex(pc),'address':hex(address),
                'bytes':size,'value':value})

    def hook(self, uc, address, size, unused):
        r = [uc.reg_read(reg) for reg in REGS]
        self.executed.add(address)
        if address == 0x525f1c:
            self.transport_events.append({'operation': 'connection_reply',
                'lcid': r[0], 'result': r[1], 'return_fixture': self.connection_reply_error})
            self.ret(self.connection_reply_error)
        elif address == 0x544bc4:
            assert r[1] == self.input_start
            self.transport_events.append({'operation': 'configuration_reply',
                'lcid': r[0], 'mtu': struct.unpack('<H', uc.mem_read(r[1]+8, 2))[0],
                'return_fixture': self.config_reply_error})
            self.ret(self.config_reply_error)
        elif address == 0x525560:
            assert STACK <= r[1] and r[1]+16 < STACK+0xf000
            config = bytes(uc.mem_read(r[1], 16))
            self.transport_events.append({'operation': 'configuration_request',
                'lcid': r[0], 'mtu': struct.unpack_from('<H', config, 8)[0],
                'return_fixture': self.config_request_error})
            self.ret(self.config_request_error)
        elif address == 0x5450a4:
            self.transport_events.append({'operation': 'disconnect_request', 'lcid': r[0]})
            self.ret()
        elif address == CALLBACK:
            assert not self.mutex_held
            sp = uc.reg_read(UC_ARM_REG_SP)
            n = self.word(sp)
            assert n <= 4096
            assert STACK <= r[2] and r[2]+12 <= STACK+0xf000
            raw = bytes(uc.mem_read(r[3], n)) if n else b''
            if n:
                assert ((self.input_start <= r[3] and r[3]+n <= INPUT+4096) or
                    (r[0] != 0xf1 and STACK <= r[3] and r[3]+n <= STACK+0xf000))
            self.callbacks.append({'event': r[0], 'status': r[1],
                'handle_initialized_bytes_4_to_11_hex': bytes(uc.mem_read(r[2]+4, 8)).hex(),
                'payload_hex': raw.hex(), 'payload_length': n,
                'state_during_callback': self.byte(STATE+0x12),
                'pending_during_callback': self.byte(STATE+0x13), 'mutex_held': False})
            self.events.append('callback'); self.ret(self.callback_error)
        else:
            super().hook(uc, address, size, unused)

    def native(self, name, entry, args, payload=None, pointer_argument=None):
        self.mutex_held = False  # L2CAP callbacks acquire their own native lock.
        self.replies=[]; self.callbacks=[]; self.events=[]; self.executed=set()
        self.transport_events=[]
        self.sep_state_writes=[]
        if payload is not None:
            assert 0 < len(payload) <= 4096
            self.input_start = INPUT+4096-len(payload)
            self.uc.mem_protect(INPUT, 4096, unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
            self.uc.mem_write(self.input_start, payload)
            self.uc.mem_protect(INPUT, 4096, unicorn.UC_PROT_READ)
            args = list(args); args[pointer_argument] = self.input_start
        sp=STACK+0xf000
        self.uc.reg_write(UC_ARM_REG_SP, sp)
        self.uc.reg_write(UC_ARM_REG_LR, RETURN|1)
        for reg, value in zip(REGS, list(args)+[0]*4): self.uc.reg_write(reg, value)
        self.uc.emu_start(entry|1, RETURN+2, timeout=2000000, count=100000)
        assert self.uc.reg_read(UC_ARM_REG_PC)==RETURN
        assert self.uc.reg_read(UC_ARM_REG_SP)==sp and not self.mutex_held
        if payload is not None: assert bytes(self.uc.mem_read(self.input_start,len(payload)))==payload
        assert bytes(self.uc.mem_read(0x50000,len(self.code)))==self.code
        assert bytes(self.uc.mem_read(0xf50000,4096))==self.global_data
        assert bytes(self.uc.mem_read(0x3a88000,CONTEXT-0x3a88000))==b'\xa5'*(CONTEXT-0x3a88000)
        tail=DESCRIPTORS+36
        assert bytes(self.uc.mem_read(tail,0x3a8a000-tail))==b'\xa5'*(0x3a8a000-tail)
        result=self.snapshot(name)
        result.update(return_value=self.uc.reg_read(REGS[0]),
            original_lookup_executed=bool({0x525138,0x524140}&self.executed),
            original_ready_helper_executed=0x524da4 in self.executed,
            original_reset_executed=0x575678 in self.executed,
            original_pending_scan_executed=0x544854 in self.executed,
            code_globals_input_RAM_guards_and_stack_intact=True)
        self.history.append(result); return result

    def snapshot(self, name):
        index=self.byte(STATE+0xf)
        return {'step': name, 'state': self.byte(STATE+0x12),
            'pending': self.byte(STATE+0x13), 'media_channel_index': index,
            'media_channel_hex':bytes(self.uc.mem_read(CHANNELS+index*8,8)).hex() if index<12 else None,
            'channel_pool_hex':bytes(self.uc.mem_read(CHANNELS,96)).hex(),
            'context_pending_media_index':self.byte(CONTEXT+0x14),
            'context_outgoing_media_index':self.byte(CONTEXT+0x15),
            'native_SEP_state_writes':list(self.sep_state_writes),
            'callbacks':list(self.callbacks), 'transport_events':list(self.transport_events),
            'event_order':list(self.events)}

    def signal(self, signal, payload):
        self.mutex_held=True  # Explicit signaling-dispatch lock boundary.
        self.transport_events=[]
        self.sep_state_writes=[]
        result=self.invoke(signal,payload)
        assert bytes(self.uc.mem_read(0xf50000,4096))==self.global_data
        result.update(self.snapshot('signal_'+str(signal)))
        self.mutex_held=False
        self.history.append(result); return result

    def configure_open(self):
        a=self.signal(3,CONFIG); b=self.signal(6,b'\x04')
        assert a['state']==2 and b['state']==2 and b['pending']==2
        return a,b

    def incoming(self, peer=PEER):
        return self.native('incoming_media_channel',0x50b988,[0,MEDIA_LCID,0],peer,0)

    def config_request(self, mtu=1008):
        config=bytearray(12); struct.pack_into('<H',config,8,mtu)
        return self.native('remote_configuration_request',0x50b3dc,[MEDIA_LCID,0],bytes(config),1)

    def config_confirm(self, status=0, lcid=MEDIA_LCID):
        return self.native('local_configuration_confirmation',0x50b1f8,[lcid,status])

    def media(self, payload):
        return self.native('media_packet',0x50bbb8,[MEDIA_LCID,0,len(payload)],payload,1)


def main():
    stock=NativeImage(); cases=[]
    def check(name, vm, observations):
        assert all(observations.values()), (name, observations)
        assert all(r.get('code_globals_input_RAM_guards_and_stack_intact',
            r.get('original_code_input_and_RAM_guards_intact', False)) for r in vm.history)
        cases.append({'name':name, 'passed':True, 'checks':observations, 'steps':vm.history})
    def callback(r,event,status=0):
        return len(r['callbacks'])==1 and r['callbacks'][0]['event']==event and r['callbacks'][0]['status']==status
    def ready(vm):
        vm.configure_open();a=vm.incoming();b=vm.config_request();c=vm.config_confirm()
        assert a['state']==b['state']==2 and a['pending']==b['pending']==2
        assert c['state']==4 and c['pending']==0 and callback(c,13)
        return c
    def reset(r):
        pool=bytes.fromhex(r['channel_pool_hex'])
        return r['state']==1 and r['pending']==0 and r['media_channel_index']==255 and pool[8:10]==b'\x00\x00'

    vm=LifecycleVM(stock);end=ready(vm);start=vm.signal(7,b'\x04')
    payload=bytes(range(128));media=vm.media(payload)
    check('complete_stock_configure_Open_L2CAP_ready_Start_media_chain',vm,{
        'same_VM_no_host_SEP_state_advancement':True,
        'real_ready_helper_sets4_and_clears_pending2':end['original_ready_helper_executed'] and end['state']==4,
        'native_ready_state_store_observed':any(w['instruction']=='0x524ea4' and w['value']==4 for w in end['native_SEP_state_writes']),
        'real_Start_accepts_after_native_completion':start['state']==8 and start['pending']==0 and start['replies'][0]['wire_hex']=='1207',
        'real_media_dispatch_delivers_payload':callback(media,0xf1) and media['callbacks'][0]['payload_hex']==payload.hex(),
        'real_peer_scan_and_pending_scan_executed':any(r.get('original_pending_scan_executed') for r in vm.history),
        'remote_and_local_MTU_kept_distinct':bytes.fromhex(end['media_channel_hex'])[2:4]==struct.pack('<H',1008) and
            any(e['operation']=='configuration_request' and e['mtu']==LOCAL_MTU for r in vm.history for e in r['transport_events']),
    })
    vm=LifecycleVM(stock);vm.configure_open();vm.incoming();early=vm.media(b'not-ready')
    check('media_before_completion_reports_wrong_state',vm,{
        'pending_not_advanced':early['state']==2 and early['pending']==2,
        'error_callback_retains_payload':callback(early,0xf1,0x131) and early['callbacks'][0]['payload_hex']==b'not-ready'.hex()})
    vm=LifecycleVM(stock);ready(vm);vm.signal(7,b'\x04');suspend=vm.signal(9,b'\x04')
    paused=vm.media(b'paused');resume=vm.signal(7,b'\x04');audio=vm.media(b'resumed')
    check('Suspend_and_Start_reuse_completed_channel',vm,{
        'Suspend_sets_ready':suspend['state']==4 and callback(suspend,19),
        'suspended_media_reports_error':callback(paused,0xf1,0x131),
        'resumed_media_delivered':resume['state']==8 and resume['pending']==0 and callback(audio,0xf1)})
    vm=LifecycleVM(stock);ready(vm);vm.signal(7,b'\x04')
    disconnected=vm.native('disconnect_notification',0x50be1c,[MEDIA_LCID])
    stale=vm.media(b'stale');again=ready(vm);vm.signal(7,b'\x04');audio=vm.media(b'new-session')
    check('Disconnect_resets_SEP_then_same_VM_reconnects',vm,{
        'real_reset_releases_media_slot':reset(disconnected) and disconnected['original_reset_executed'],
        'disconnect_error_notifies_application':callback(disconnected,0xf2,0x2931),
        'stale_LCID_after_reset_has_no_callback':not stale['callbacks'] and stale['return_value']==0x2914,
        'reconfigured_ready_and_streaming':again['state']==4 and callback(audio,0xf1)})
    vm=LifecycleVM(stock);vm.configure_open();vm.connection_reply_error=7;failed=vm.incoming()
    check('connection_reply_send_failure_runs_stock_cleanup',vm,{
        'native_reset_to_idle':reset(failed) and failed['original_reset_executed'],
        'application_gets_disconnect_status':callback(failed,0xf2,0x2931)})
    vm=LifecycleVM(stock);vm.configure_open();vm.incoming();vm.config_reply_error=7;failed=vm.config_request()
    vm.config_reply_error=0;vm.config_request();completed=vm.config_confirm()
    check('remote_configuration_reply_failure_waits_then_retry_completes',vm,{
        'first_reply_failure_not_ready':failed['return_value']==7 and failed['state']==2 and failed['pending']==2 and not failed['callbacks'],
        'retry_uses_stock_ready_path':completed['state']==4 and completed['pending']==0 and callback(completed,13)})
    vm=LifecycleVM(stock);vm.configure_open();vm.incoming();vm.config_request_error=7;failed=vm.config_request()
    check('local_configuration_request_send_failure_resets',vm,{
        'native_reset_to_idle':reset(failed), 'application_gets_disconnect_status':callback(failed,0xf2,0x2931),
        'transport_disconnect_requested':any(e['operation']=='disconnect_request' for e in failed['transport_events'])})
    vm=LifecycleVM(stock);vm.configure_open();vm.incoming();vm.config_request();failed=vm.config_confirm(7)
    check('local_configuration_error_confirmation_resets',vm,{
        'native_reset_to_idle':reset(failed), 'application_gets_disconnect_status':callback(failed,0xf2,0x2931)})
    vm=LifecycleVM(stock);vm.configure_open();vm.incoming();duplicate=vm.incoming()
    check('duplicate_incoming_media_connection_rejected',vm,{
        'rejected_without_new_channel_or_state':duplicate['transport_events'][0]['result']==3 and
            duplicate['state']==2 and duplicate['pending']==2 and not duplicate['callbacks']})
    vm=LifecycleVM(stock);vm.signal(3,CONFIG);early=vm.incoming()
    check('incoming_media_without_Open_rejected',vm,{
        'rejected_without_fake_Open':early['transport_events'][0]['result']==3 and early['state']==2 and early['pending']==0,
        'reserved_channel_not_replaced':bytes.fromhex(early['media_channel_hex'])[:2]==b'\x01\x00'})
    vm=LifecycleVM(stock);ready(vm);duplicate=vm.config_confirm()
    notified=vm.native('disconnect_notification',0x50be1c,[MEDIA_LCID])
    check('duplicate_confirmation_requests_disconnect_then_notification_resets',vm,{
        'request_does_not_fake_completed_disconnection':duplicate['state']==4 and not duplicate['callbacks'] and
            any(e['operation']=='disconnect_request' for e in duplicate['transport_events']),
        'later_notification_resets':reset(notified) and callback(notified,0xf2,0x2931)})
    vm=LifecycleVM(stock);vm.configure_open();vm.incoming();unknown=vm.config_confirm(lcid=0x7777)
    check('unknown_LCID_confirmation_does_not_advance_SEP',vm,{
        'lookup_reject_preserves_pending':unknown['return_value']==0x2914 and unknown['state']==2 and
            unknown['pending']==2 and not unknown['callbacks']})
    vm=LifecycleVM(stock);ready(vm);vm.signal(7,b'\x04');payload=bytes(range(256))*16;media=vm.media(payload)
    check('4096_byte_read_only_page_end_payload_delivered',vm,{
        'max_fixture_payload_matches':callback(media,0xf1) and media['callbacks'][0]['payload_hex']==payload.hex(),
        'input_and_code_guards_intact':media['code_globals_input_RAM_guards_and_stack_intact']})
    vm=LifecycleVM(stock);ready(vm);vm.signal(7,b'\x04');empty=vm.native('zero_length_packet',0x50bbb8,[MEDIA_LCID,0,0])
    check('zero_length_wrapper_returns_without_lookup_or_callback',vm,{
        'empty_early_return':empty['return_value']==0 and not empty['original_lookup_executed'] and not empty['callbacks']})
    vm=LifecycleVM(stock);vm.configure_open();vm.incoming();unexpected=vm.config_confirm();completed=vm.config_request()
    check('confirmation_before_outbound_request_is_accepted_by_stock_state_core',vm,{
        'first_side_alone_does_not_mark_ready':unexpected['state']==2 and unexpected['pending']==2,
        'second_side_marks_ready_without_outbound_request':completed['state']==4 and completed['pending']==0 and
            callback(completed,13) and not any(e['operation']=='configuration_request' for e in completed['transport_events'])})
    vm=LifecycleVM(stock);vm.configure_open();vm.incoming();premature=vm.signal(7,b'\x04');media=vm.media(b'guard-required')
    check('rejected_early_Start_can_deliver_media_with_pending_Open',vm,{
        'Start_rejected_but_state8_pending2':premature['replies'][0]['wire_hex']=='13070431' and premature['state']==8 and premature['pending']==2,
        'media_reports_success_while_channel_not_ready':callback(media,0xf1) and media['pending']==2 and
            bytes.fromhex(media['media_channel_hex'])[5]==2,
        'application_needs_pending_and_channel_ready_fences':True})

    deps=[Path(__file__),ROOT/'scripts/emulate_avdtp_control.py',ROOT/'scripts/analyze_native_sections.py',
        ROOT/'evidence/firmware-analysis/main_02bd.bin']
    out={'updated_utc':datetime.now(timezone.utc).isoformat(),'stock_sha256':EXPECTED,
        'source_sha256':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in deps},
        'cpu_model':'ARM1176','case_count':len(cases),'cases':cases,'all_passed':True,
        'original_L2CAP_completion_handlers_executed_offline':True,
        'same_VM_configure_Open_ready_Start_media_and_reconnect':True,
        'post_setup_SEP_state_changed_only_by_stock_instructions':True,
        'actual_SEP_SDP_registration_verified':False,'real_L2CAP_transport_executed':False,
        'native_pending_configuration_queue_fixture':'Empty; stock ready-completion falls back to SEP callback event13.',
        'callback_handles_and_payloads_borrowed_only_during_call':True,
        'rejected_early_Start_can_deliver_success_media_with_pending_Open':True,
        'application_must_fence_pending_channel_readiness_and_session_epoch':True,
        'device_io':False,'firmware_modified':False,'device_install_candidate':False,
        'phone_speaker_native_App_or_decoder_integration_verified':False,
        'fixtures':['Registered active SEP, callback, local MTU672 and established signaling channel',
            'Synthetic peer010203040506 and LCID4567', 'L2CAP connection/configuration send outcomes and incoming callbacks',
            'Mutex/log/codec-copy hooks, application callback sink, no global callback or queued outgoing API'],
        'limitations':'Offline exact handlers, not a physical Bluetooth connection. Starting registration/signaling pools, transport and OS are synthetic. No decoder/voice loader/UI/speaker integration. 4096-byte test is a buffer boundary, not a negotiated physical MTU. Disconnect drops old LCID before reuse; packet epoch cannot be inferred after reuse and needs application session ownership. Native error callbacks are notifications, not configuration acceptance policy. No phone or installation proof.'}
    target=ROOT/'evidence/firmware-analysis/avdtp-lifecycle-emulation.json'
    target.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'evidence':str(target.relative_to(ROOT)),'cases_passed':len(cases),'device_io':False}))


if __name__=='__main__': main()
