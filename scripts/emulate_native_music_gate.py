#!/usr/bin/env python3
"""Execute compiled ARM gate and unmodified stock handlers, offline only.

The caller explicitly selects the gate entry; no native table is patched.
Registered endpoint, descriptors and connection are starting fixtures, not
registration proof. L2CAP send and callback remain simulated boundaries.
"""
from datetime import datetime, timezone
import hashlib
import itertools
import json
import struct
from pathlib import Path

import unicorn
from unicorn.arm_const import (UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
    UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
    UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11)
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from emulate_avdtp_control import (STATE, DESCRIPTORS, CHANNELS, CONTEXT,
    REGS, CONFIG, RETURN, CALLBACK, STACK, INPUT)
from emulate_avdtp_lifecycle import LifecycleVM, MEDIA_LCID

CAP_PAGE = 0x09002000
CAP = CAP_PAGE+4092
SAVED_REGS = [UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
    UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11]


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def signed(v):
    return v if v < 0x80000000 else v-0x100000000


class GateVM(LifecycleVM):
    def __init__(self, stock, build, *, caps=bytes.fromhex('3fff0235')):
        super().__init__(stock)
        self.build = build
        self.symbols = build['symbols']
        self.base = build['base']
        self.gate_code = (ROOT/build['flat']).read_bytes()
        size = (len(self.gate_code)+4095)&~4095
        self.uc.mem_map(self.base, size)
        self.uc.mem_write(self.base, self.gate_code)
        self.uc.mem_protect(self.base, size, unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
        self.bss = self.symbols['__bss_start']
        self.uc.mem_map(self.bss, 4096, unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
        self.uc.mem_write(self.bss, b'\xa5'*4096)
        self.uc.mem_write(self.symbols['music_gate_bindings'], bytes(12))
        self.uc.mem_map(CAP_PAGE, 4096)
        self.uc.mem_write(CAP_PAGE, b'\xa5'*4096)
        self.uc.mem_write(CAP, caps)
        self.cap_data = bytes(self.uc.mem_read(CAP_PAGE, 4096))
        self.uc.mem_protect(CAP_PAGE, 4096, unicorn.UC_PROT_READ)
        self.uc.mem_write(DESCRIPTORS, struct.pack('<I', CAP)+bytes([4,0,0,0,1,0,0,0]))
        self.entry_calls = []
        self.gate_calls = []

    def hook(self, uc, address, size, unused):
        if address in (0x574acc, 0x5756ac):
            self.entry_calls.append({'entry':hex(address),
                'args':[uc.reg_read(r) for r in REGS]+[self.word(uc.reg_read(UC_ARM_REG_SP))]})
        if address == 0x5524f6:
            dest, src, n = [uc.reg_read(reg) for reg in REGS[:3]]
            assert any(STATE+i*32+0x14 <= dest and dest+n <= STATE+i*32+0x18 for i in range(3))
            assert n <= 4 and self.input_start <= src and src+n <= INPUT+4096
            uc.mem_write(dest, bytes(uc.mem_read(src, n)))
            self.executed.add(address)
            self.ret(dest)
        else:
            super().hook(uc, address, size, unused)

    def pool(self):
        return bytes(self.uc.mem_read(CONTEXT, DESCRIPTORS+36-CONTEXT))

    def assert_guards(self):
        assert bytes(self.uc.mem_read(self.base, len(self.gate_code))) == self.gate_code
        assert bytes(self.uc.mem_read(0x50000, len(self.code))) == self.code
        assert bytes(self.uc.mem_read(0xf50000, 4096)) == self.global_data
        assert bytes(self.uc.mem_read(CAP_PAGE, 4096)) == self.cap_data
        assert bytes(self.uc.mem_read(self.bss+12, 4096-12)) == b'\xa5'*(4096-12)
        assert bytes(self.uc.mem_read(0x3a88000, CONTEXT-0x3a88000)) == b'\xa5'*(CONTEXT-0x3a88000)
        end = DESCRIPTORS+36
        assert bytes(self.uc.mem_read(end, 0x3a8a000-end)) == b'\xa5'*(0x3a8a000-end)

    def call(self, name, args, *, payload=None, payload_argument=None):
        self.mutex_held = True  # Explicit caller-held native dispatch lock.
        self.replies=[]; self.callbacks=[]; self.events=[]; self.executed=set()
        self.transport_events=[]; self.sep_state_writes=[]; self.entry_calls=[]
        args = list(args)
        if payload is not None:
            assert 0 < len(payload) <= 4096
            self.input_start = INPUT+4096-len(payload)
            self.uc.mem_protect(INPUT, 4096, unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
            self.uc.mem_write(self.input_start, payload)
            self.uc.mem_protect(INPUT, 4096, unicorn.UC_PROT_READ)
            args[payload_argument] = self.input_start
        sp = STACK+0xf000
        self.uc.mem_write(sp, struct.pack('<I', args[4] if len(args)>4 else 0))
        self.uc.reg_write(UC_ARM_REG_SP, sp)
        self.uc.reg_write(UC_ARM_REG_LR, RETURN|1)
        saved = [0x11220000+i*0x111 for i in range(len(SAVED_REGS))]
        for reg, value in zip(SAVED_REGS, saved):
            self.uc.reg_write(reg, value)
        for reg, value in zip(REGS, args+[0]*4):
            self.uc.reg_write(reg, value)
        before = self.pool()
        binding_before = bytes(self.uc.mem_read(self.bss,12))
        self.uc.emu_start(self.symbols[name], RETURN+2, timeout=2000000, count=100000)
        assert self.uc.reg_read(UC_ARM_REG_PC) == RETURN
        assert self.uc.reg_read(UC_ARM_REG_SP) == sp and self.mutex_held
        assert [self.uc.reg_read(r) for r in SAVED_REGS] == saved
        if payload is not None:
            assert bytes(self.uc.mem_read(self.input_start, len(payload))) == payload
        self.assert_guards()
        if name == 'music_configuration_gate':
            assert bytes(self.uc.mem_read(self.bss,12)) == binding_before
        result = self.snapshot(name)
        result.update(return_value=signed(self.uc.reg_read(REGS[0])),
            original_config_handler_executed=0x574acc in self.executed,
            original_reply_helper_executed=0x5756ac in self.executed,
            original_parser_executed=0x5a63e4 in self.executed,
            original_channel_reservation_executed=0x5a6228 in self.executed,
            stock_pool_unchanged=before == self.pool(),
            native_entry_ABI=list(self.entry_calls), replies=list(self.replies),
            compiled_gate_stock_code_inputs_capabilities_BSS_guards_stack_and_saved_registers_intact=True)
        self.mutex_held = False
        self.gate_calls.append(result)
        return result

    def claim(self, seid=1, callback=CALLBACK|1):
        return self.call('music_gate_claim', [seid, callback])

    def release(self, seid=1, callback=CALLBACK|1):
        return self.call('music_gate_release', [seid, callback])

    def gate(self, payload=CONFIG, *, signal=3, context=0, transaction=1, pointer=0, length=None):
        return self.call('music_configuration_gate', [context,signal,transaction,pointer,
            len(payload) if length is None and payload is not None else (length or 0)],
            payload=payload, payload_argument=3 if payload is not None else None)


def main():
    build = json.loads((ROOT/'staging/native-music-gate/manifest.json').read_text())
    for name, expected in build['source_sha256'].items():
        assert sha(ROOT/name) == expected, name
    assert sha(ROOT/build['flat']) == build['flat_sha256']
    assert sha(ROOT/build['elf']) == build['elf_sha256']
    stock=NativeImage(); cases=[]

    def fresh(**kw):
        vm=GateVM(stock,build,**kw)
        assert vm.claim()['return_value']==0
        return vm

    def check(name, vm, checks):
        assert all(checks.values()), (name, checks, vm.gate_calls[-1] if vm.gate_calls else None)
        vm.assert_guards()
        cases.append({'name':name, 'passed':True, 'checks':checks,
            'gate_calls':vm.gate_calls, 'stock_steps':vm.history})

    def rejected(name, payload, category, error, **kw):
        vm=fresh(**kw); r=vm.gate(payload)
        check(name, vm, {'exact_native_reject_wire':[x['wire_hex'] for x in r['replies']]==
            [bytes([0x13,3,category,error]).hex()],
            'stock_reply_helper_runs_before_any_accept':r['original_reply_helper_executed'] and
                not r['original_config_handler_executed'],
            'no_callbacks_channel_reservation_or_SEP_state_change':r['stock_pool_unchanged'] and
                not r['callbacks'] and not r['original_channel_reservation_executed'] and r['state']==1})

    # All supported SBC selections execute compiled policy AND stock parser,
    # response and allocator. Descriptors advertise a known explicit subset.
    for freq, mode, blocks, bands, allocation in itertools.product(
        [0x20,0x10], [8,4,2,1], [0x80,0x40,0x20,0x10], [8,4], [2,1]):
        body=bytes([4,8,1,0,7,6,0,0,freq|mode,blocks|bands|allocation,2,53])
        vm=fresh(); r=vm.gate(body)
        check('supported_%02x_%02x'%(body[8],body[9]),vm,{
            'compiled_then_original_accept':[x['wire_hex'] for x in r['replies']]==['1203'] and
                r['original_config_handler_executed'] and r['original_parser_executed'],
            'stock_allocator_and_callback_run':r['original_channel_reservation_executed'] and
                r['state']==2 and [x['event'] for x in r['callbacks']]==[9],
            'exact_five_argument_original_ABI':r['native_entry_ABI'][0]['args']==
                [0,3,1,vm.input_start,len(body)],
            'lock_released_only_for_callback':r['event_order']==['send','unlock','callback','lock']})
    matrix_count=len(cases)

    rejected('AAC_ID_rejected_before_stock_accept',bytes.fromhex('040801000706000221150235'),7,0x29)
    rejected('transport_only_rejected_before_stock_accept',bytes.fromhex('04080100'),7,0x29)
    rejected('missing_transport',bytes.fromhex('04080706000021150235'),1,0x29)
    rejected('truncated_TLV_header',CONFIG+b'\x07',7,0x11)
    rejected('truncated_codec',CONFIG[:-1],7,0x11)
    rejected('codec_length5',bytes.fromhex('0408010007050000211502'),7,0x11)
    rejected('duplicate_transport',CONFIG+bytes([1,0]),1,0x17)
    rejected('duplicate_codec',CONFIG+CONFIG[4:],7,0x17)
    rejected('nonempty_transport',bytes.fromhex('0408010100')+CONFIG[4:],1,0x23)
    rejected('unsupported_content_protection',CONFIG+bytes([4,0]),4,0x29)
    rejected('unknown_service',CONFIG+bytes([9,0]),9,0x17)
    rejected('reserved_local_SEID_bits',bytes([5])+CONFIG[1:],0,1)
    rejected('reserved_remote_SEID_bits',CONFIG[:1]+b'\x09'+CONFIG[2:],0,1)
    rejected('remote_SEID0',CONFIG[:1]+b'\x00'+CONFIG[2:],0,0x18)
    rejected('remote_SEID63',CONFIG[:1]+b'\xfc'+CONFIG[2:],0,0x18)
    rejected('ambiguous_frequency',CONFIG[:8]+b'\x31'+CONFIG[9:],7,0x29)
    rejected('32000_not_supported',CONFIG[:8]+b'\x41'+CONFIG[9:],7,0x29)
    rejected('zero_channel_mode',CONFIG[:8]+b'\x20'+CONFIG[9:],7,0x29)
    rejected('bitpool_min1',CONFIG[:10]+bytes([1,53]),7,0x29)
    rejected('bitpool_max54',CONFIG[:10]+bytes([2,54]),7,0x29)
    rejected('bitpool_reversed',CONFIG[:10]+bytes([30,20]),7,0x29)
    rejected('local_SEID0',b'\x00'+CONFIG[1:],0,0x12)
    rejected('local_SEID4',b'\x10'+CONFIG[1:],0,0x12)
    rejected('advertised_frequency_subset_enforced',CONFIG[:8]+b'\x11'+CONFIG[9:],7,0x29,
        caps=bytes.fromhex('2fff0235'))
    rejected('advertised_bitpool_subset_enforced',CONFIG,7,0x29,caps=bytes.fromhex('3fff141e'))

    vm=fresh(caps=bytes.fromhex('3fff141e')); r=vm.gate(CONFIG[:10]+bytes([20,30]))
    check('negotiated_bitpool_within_advertised_subset_accepted',vm,{
        'accept_and_codec_copied':r['replies'][0]['wire_hex']=='1203' and
            bytes(vm.uc.mem_read(STATE+0x14,4))==bytes.fromhex('2115141e')})
    vm=fresh(); r=vm.gate(bytes.fromhex('040807060000211502350100'),transaction=15)
    check('service_order_and_transaction15_preserved',vm,{
        'stock_accept_wire_f203':r['replies'][0]['wire_hex']=='f203',
        'original_ABI_transaction15':r['native_entry_ABI'][0]['args'][2]==15})
    vm=fresh(); r=vm.gate(bytes.fromhex('040706000021150235'),signal=5)
    check('claimed_Reconfigure_deliberately_unsupported',vm,{
        'native_reject13050729':r['replies'][0]['wire_hex']=='13050729',
        'no_stock_changes':r['stock_pool_unchanged'] and not r['original_config_handler_executed']})
    vm=fresh(); vm.send_error=0x2930; r=vm.gate(bytes.fromhex('04080100'))
    check('reject_send_failure_propagates_without_state_change',vm,{
        'error_propagated':r['return_value']==0x2930,
        'no_accept_or_mutation':r['stock_pool_unchanged'] and not r['original_config_handler_executed']})
    for name, options, expected in [
        ('invalid_context',{'context':2},-20), ('invalid_signal',{'signal':6},-20),
        ('transaction16',{'transaction':16},-20), ('null_payload',{'payload':None,'length':12},0),
        ('zero_length',{'length':0},0), ('length129',{'length':129},0),
        ('pointer_wrap',{'payload':None,'pointer':0xfffffff8,'length':12},0)]:
        vm=fresh(); r=vm.gate(**options)
        check(name,vm,{'correct_return':r['return_value']==expected,
            'stock_pool_unchanged':r['stock_pool_unchanged'],
            'no_stock_handler_or_callback':not r['original_config_handler_executed'] and not r['callbacks'],
            'invalid_input_reject_or_no_reply':([x['wire_hex'] for x in r['replies']]==['13030011'])
                if expected==0 else not r['replies']})
    for name, offset, value in [('invalid_channel_index',CONTEXT+0x13,b'\x0c'),
        ('signaling_not_ready',CHANNELS+5,b'\x02'),('wrong_context_owner',CHANNELS+6,b'\x01'),
        ('channel_wrong_type',CHANNELS+4,b'\x01'),('low_LCID',CHANNELS,b'\x01\x00')]:
        vm=fresh();vm.uc.mem_write(offset,value);r=vm.gate()
        check(name,vm,{'fail_closed_before_reply':r['return_value']==-20 and not r['replies'] and
            not r['original_config_handler_executed'] and r['stock_pool_unchanged']})

    vm=fresh();vm.uc.mem_write(STATE,struct.pack('<I',CALLBACK+0x101));r=vm.gate()
    check('changed_callback_owner_drops_without_foreign_callback',vm,{
        'stale_owner_error':r['return_value']==-22,'no_state_reply_or_callback':r['stock_pool_unchanged'] and
            not r['replies'] and not r['callbacks']})
    vm=fresh();vm.uc.mem_write(DESCRIPTORS+8,b'\x00');r=vm.gate()
    check('changed_descriptor_role_drops_claimed_configuration',vm,{
        'descriptor_error_no_stock_accept':r['return_value']==-22 and not r['replies'] and r['stock_pool_unchanged']})
    for name, offset, value in [('source_role',DESCRIPTORS+8,b'\x00'),
        ('wrong_codec',DESCRIPTORS+6,b'\x02'),('wrong_capability_length',DESCRIPTORS+4,b'\x03'),
        ('null_capability',DESCRIPTORS,bytes(4)),('nonidle',STATE+0x12,b'\x02'),
        ('pending',STATE+0x13,b'\x01'),('callback_mismatch',STATE,struct.pack('<I',CALLBACK+0x101))]:
        vm=GateVM(stock,build);vm.uc.mem_write(offset,value);r=vm.claim()
        check('claim_rejects_'+name,vm,{'no_claim_or_stock_changes':r['return_value']==-21 and
            r['stock_pool_unchanged'] and bytes(vm.uc.mem_read(vm.bss,12))==bytes(12)})
    vm=fresh();r=vm.claim();wrong=vm.release(callback=CALLBACK+0x101);released=vm.release();again=vm.release()
    check('double_claim_wrong_release_and_idle_release',vm,{
        'double_claim_busy':r['return_value']==-21,'wrong_release_rejected':wrong['return_value']==-20,
        'idle_release_clears_only_binding':released['return_value']==0 and released['stock_pool_unchanged'] and
            bytes(vm.uc.mem_read(vm.bss,12))==bytes(12),'second_release_rejected':again['return_value']==-20})

    # Preserve normal behavior of an unclaimed registered SEP; both runs
    # execute stock handler with matching pools and compare exact outcomes.
    vm=fresh();vm.uc.mem_write(STATE+32,struct.pack('<I',CALLBACK|1))
    vm.uc.mem_write(STATE+32+0x12,b'\x01')
    baseline=GateVM(stock,build);baseline.uc.mem_write(STATE+32,struct.pack('<I',CALLBACK|1))
    baseline.uc.mem_write(STATE+32+0x12,b'\x01')
    payload=bytes.fromhex('080c0100')
    a=vm.gate(payload);b=baseline.signal(3,payload)
    check('unclaimed_second_SEP_preserves_normal_stock_behavior',vm,{
        'same_pool_wire_and_callback':vm.pool()==baseline.pool() and a['replies']==b['replies'] and
            a['callbacks']==b['callbacks'],
        'original_accept_still_executes':a['original_config_handler_executed'] and a['replies'][0]['wire_hex']=='1203'})
    vm=GateVM(stock,build);r=vm.gate(bytes.fromhex('040801000706000221150235'))
    check('unclaimed_codec_keeps_stock_policy_not_global_replacement',vm,{
        'legacy_codec_core_accept':r['original_config_handler_executed'] and r['replies'][0]['wire_hex']=='1203'})
    vm=GateVM(stock,build);baseline=GateVM(stock,build)
    for actor in [vm,baseline]:
        actor.configure_open();actor.incoming();actor.config_request();actor.config_confirm()
    payload=bytes.fromhex('040706000021150235')
    a=vm.gate(payload,signal=5);b=baseline.signal(5,payload)
    check('unclaimed_Reconfigure_preserves_stock_accept_and_callback21',vm,{
        'same_pool_wire_and_callback':vm.pool()==baseline.pool() and a['replies']==b['replies'] and
            a['callbacks']==b['callbacks'],
        'stock_Reconfigure_accept':a['replies'][0]['wire_hex']=='1205' and a['callbacks'][0]['event']==21})
    vm=fresh();vm.send_error=0x2930;r=vm.gate()
    check('stock_accept_send_failure_leaves_configured_state_not_rolled_back',vm,{
        'original_partial_state_retained':r['state']==2 and not r['stock_pool_unchanged'] and
            r['original_config_handler_executed'] and not r['callbacks'],
        'stock_return_zero_does_not_prove_reply_delivery':r['return_value']==0 and
            r['replies'][0]['wire_hex']=='1203'})
    vm=fresh();vm.uc.mem_write(STATE+0x13,b'\x01');r=vm.gate()
    check('supported_configuration_still_obeys_original_busy_check',vm,{
        'native_busy_reject':r['original_config_handler_executed'] and r['replies'][0]['wire_hex']=='13030013' and
            r['stock_pool_unchanged'] and not r['callbacks']})
    vm=fresh();r=vm.gate(bytes.fromhex('04080100'),transaction=15)
    check('native_reject_transaction15_exact_five_argument_ABI',vm,{
        'native_reply_f3030729':r['replies'][0]['wire_hex']=='f3030729',
        'reply_helper_exact_args':r['native_entry_ABI']==[{'entry':'0x5756ac','args':[0,15,3,7,0x29]}]})

    # One VM: compiled wrapper -> stock channel completion -> media -> reset.
    vm=fresh();config=vm.gate();busy=vm.release();op=vm.signal(6,b'\x04')
    incoming=vm.incoming();request=vm.config_request();ready=vm.config_confirm()
    start=vm.signal(7,b'\x04');media=vm.media(b'candidate-no-decoder-fixture')
    disconnected=vm.native('disconnect_notification',0x50be1c,[MEDIA_LCID]);release=vm.release()
    check('compiled_preaccept_wrapper_full_stock_lifecycle_then_idle_release',vm,{
        'config_accept_before_callback':config['replies'][0]['wire_hex']=='1203' and config['state']==2,
        'busy_release_preserves_claim':busy['return_value']==-21,
        'real_completion_not_host_state_advancement':op['pending']==2 and incoming['state']==request['state']==2 and
            ready['state']==4 and ready['original_ready_helper_executed'],
        'stock_stream_callback':start['state']==8 and start['pending']==0 and
            media['callbacks'][0]['event']==0xf1 and media['callbacks'][0]['status']==0,
        'real_disconnect_before_idle_release':disconnected['original_reset_executed'] and disconnected['state']==1 and
            release['return_value']==0 and bytes(vm.uc.mem_read(vm.bss,12))==bytes(12)})
    for seid in [0,4]:
        vm=GateVM(stock,build);r=vm.claim(seid)
        check('invalid_claim_SEID_'+str(seid),vm,{'invalid_argument':r['return_value']==-20 and r['stock_pool_unchanged']})
    vm=GateVM(stock,build);r=vm.claim(callback=0)
    check('null_claim_callback',vm,{'invalid_argument':r['return_value']==-20})

    deps=[Path(__file__),ROOT/'scripts/emulate_avdtp_control.py',ROOT/'scripts/emulate_avdtp_lifecycle.py',
        ROOT/'scripts/analyze_native_sections.py',ROOT/'evidence/firmware-analysis/main_02bd.bin',
        ROOT/'staging/native-music-gate/manifest.json',ROOT/build['flat'],ROOT/build['elf']]
    proof={'updated_utc':datetime.now(timezone.utc).isoformat(), 'stock_sha256':EXPECTED,
        'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in deps},
        'build_source_sha256':build['source_sha256'], 'compiled_code_bytes':build['flat_bytes'],
        'binding_bytes':12, 'cpu_model':'ARM1176', 'valid_SBC_matrix':matrix_count,
        'case_count':len(cases),'cases':cases,'all_passed':True,
        'original_config_and_reject_helpers_executed_without_instruction_changes':True,
        'compiled_wrapper_invoked_by_fixture_not_installed_dispatcher':True,
        'claimed_Reconfigure_deliberately_unsupported':True,
        'original_accept_send_failure_can_leave_state2_without_callback_and_return0':True,
        'recovery_and_transport_delivery_not_proven_by_stock_handler_return':True,
        'registered_SEP_and_signaling_connection_starting_fixtures':True,
        'real_SEP_SDP_registration_or_pointer_allocator_verified':False,
        'real_mutex_scheduling_module_pin_unload_or_media_hook_verified':False,
        'phone_speaker_DAC_native_App_or_UI_verified':False,
        'device_io':False,'firmware_modified':False,'device_install_candidate':False,
        'limitations':'Gate entry chosen by emulator caller, never an installed native hook. Descriptor/capability/callback allocation and lifetime, real mutex ownership, same-thread snapshot and module pinning are caller obligations. Numeric pointer checks do not prove a backing allocation. Basic malformed envelope checks also run for unclaimed input; only normal unclaimed endpoint behavior was compared. Claimed Reconfigure rejected as an explicit unsupported subset. No actual SEP/SDP activation, decoder/RTP/media gate binding or device/UI test.'}
    target=ROOT/'evidence/firmware-analysis/native-music-gate-emulation.json'
    target.write_text(json.dumps(proof,indent=2)+'\n')
    print(json.dumps({'evidence':str(target.relative_to(ROOT)),'case_count':len(cases),
        'valid_SBC_matrix':matrix_count,'code_bytes':build['flat_bytes'],'device_io':False}))


if __name__=='__main__':
    main()
