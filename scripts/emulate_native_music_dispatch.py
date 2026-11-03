#!/usr/bin/env python3
"""Exercise native L2CAP->AVDTP dispatch with a declared offline patch fixture.

Only four table words and two explicit instruction sites change in a VM copy.
The component's address is synthetic; this is not a device-installable image.
All backup/previous component artifacts remain untouched.
"""
from datetime import datetime,timezone
import hashlib,json,struct
from pathlib import Path
import unicorn
from unicorn.arm_const import UC_ARM_REG_PC,UC_ARM_REG_SP,UC_ARM_REG_R4
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from emulate_avdtp_control import STATE,CONTEXT,REGS,CONFIG,CALLBACK,STACK
from emulate_avdtp_lifecycle import MEDIA_LCID
from emulate_native_music_endpoint import EndpointVM,HEAP

TABLE=0xba6f6c
SIGNAL_LCID=0x1234
class InvalidDispatchTarget(Exception):pass
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()


class DispatchVM(EndpointVM):
    def __init__(self,stock,build,variant):
        super().__init__(stock,build)
        assert variant in ['stock','table_only','table_and_bounds']
        self.variant=variant;self.original_code=self.code;self.patch_plan=[]
        self.dispatch_entries=[];self.invalid_branch=None
        replacements=[]
        if variant!='stock':
            for signal,name in [(2,'music_endpoint_capabilities'),(3,'music_configuration_gate'),
                (4,'music_endpoint_capabilities'),(5,'music_configuration_gate')]:
                replacements.append((TABLE+(signal-1)*4,struct.pack('<I',self.symbols[name]),
                    'ARM_entry_for_signal_'+str(signal)))
        if variant=='table_and_bounds':
            assert stock.read(0x5249f8,4)==bytes.fromhex('0206120e')
            assert stock.read(0x5248fc,2)==bytes.fromhex('0b28')
            replacements += [(0x5249f8,bytes.fromhex('0200c046'),'retain_full_handler_body_length_movs_r2_r0_Thumbv6_NOP'),
                (0x5248fc,bytes.fromhex('0a28'),'bound_accepted_signals_to_actual10_entry_table')]
        image=bytearray(self.code)
        for address,replacement,purpose in replacements:
            before=stock.read(address,len(replacement))
            self.uc.mem_write(address,replacement)  # Construction-time API writes, never guest self-patching.
            image[address-0x50000:address-0x50000+len(replacement)]=replacement
            self.patch_plan.append({'address':hex(address),'original':before.hex(),
                'replacement':replacement.hex(),'purpose':purpose})
        self.code=bytes(image)
        # Original ControlVM already mapped all MAIN RX; restore/check the page
        # protections and retain an explicit expected variant image.
        self.uc.mem_protect(0x50000,(len(self.code)+4095)&~4095,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
        assert bytes(self.uc.mem_read(0x50000,len(self.code)))==self.code
        self.boot();self.signaling_fixture();assert self.prepare()['return_value']==1
        assert self.publish()['return_value']==0

    def hook(self,uc,address,size,unused):
        if address==CALLBACK:
            r=[uc.reg_read(reg) for reg in REGS];n=self.word(uc.reg_read(UC_ARM_REG_SP))
            if HEAP+4096-32<=r[3] and r[3]+n<=HEAP+4096:
                assert not self.mutex_held and STACK<=r[2] and r[2]+12<=STACK+0xf000
                assert r[3]+n<=HEAP+4096-32+self.allocations[-1]
                self.callbacks.append({'event':r[0],'status':r[1],
                    'handle_initialized_bytes_4_to_11_hex':bytes(uc.mem_read(r[2]+4,8)).hex(),
                    'payload_hex':bytes(uc.mem_read(r[3],n)).hex(),'payload_length':n,
                    'payload_backing':'native_signaling_reassembly_heap',
                    'state_during_callback':self.byte(STATE+0x12),'pending_during_callback':self.byte(STATE+0x13),
                    'mutex_held':False})
                self.events.append('callback');self.executed.add(address);self.ret(self.callback_error);return
        if address==0x427588:
            target=uc.reg_read(UC_ARM_REG_R4)
            if not (0x50000<=target&~1<0xcb179c or self.base<=target&~1<self.base+len(self.endpoint_code) or
                0x10000<=target&~1<0x11000):
                self.invalid_branch={'veneer':hex(address),'target':hex(target),'PC_before_branch':hex(uc.reg_read(UC_ARM_REG_PC))}
                raise InvalidDispatchTarget(str(self.invalid_branch))
        if address in [self.symbols['music_endpoint_capabilities'],self.symbols['music_configuration_gate']]:
            self.dispatch_entries.append({'entry':hex(address),
                'args':[uc.reg_read(r) for r in REGS]+[self.word(uc.reg_read(UC_ARM_REG_SP))]})
        super().hook(uc,address,size,unused)

    def wire(self,payload):
        self.dispatch_entries=[]
        r=self.invoke('original_L2CAP_received_signaling',0x50bbb8,[SIGNAL_LCID,0,len(payload)],
            thumb=True,payload=payload,pointer_arg=1)
        r.update(wire_input=payload.hex(),native_compiled_dispatch_entries=list(self.dispatch_entries),
            original_L2CAP_handler_executed=0x50bbc0 in self.executed,
            original_signaling_parser_dispatcher_executed=0x5247fc in self.executed,
            original_indirect_BX_veneer_executed=0x427588 in self.executed,
            exact_variant_code_and_declared_patch_only_intact=True)
        return r


def main():
    build=json.loads((ROOT/'staging/native-music-endpoint/manifest.json').read_text())
    for path,h in build['source_sha256'].items():assert sha(ROOT/path)==h,path
    stock=NativeImage();cases=[]
    def fresh(variant='table_and_bounds'):return DispatchVM(stock,build,variant)
    def check(name,vm,checks,extra=None):
        assert all(checks.values()),(name,checks,vm.calls[-1])
        vm.guards()
        cases.append({'name':name,'passed':True,'variant':vm.variant,'checks':checks,
            'patch_plan':vm.patch_plan,'calls':vm.calls,'stock_lifecycle':vm.history,
            'extra':extra or {}})

    baseline=fresh('stock');a=baseline.wire(bytes.fromhex('100204'))
    vm=fresh();b=vm.wire(bytes.fromhex('100204'))
    check('native_received_capability_routes_through_bound_ARM_entry',vm,{
        'original_receive_dispatch_and_BX_all_execute':b['original_L2CAP_handler_executed'] and
            b['original_signaling_parser_dispatcher_executed'] and b['original_indirect_BX_veneer_executed'],
        'stock_offer_contains_HeaderCompression':a['replies'][0]['wire_hex']=='120201000603800000070600003fff0235',
        'bound_entry_offer_supported_subset_only':b['replies'][0]['wire_hex']=='12020100070600003fff0235' and
            b['native_compiled_dispatch_entries'][0]['args'][:3]==[0,2,1],
        'five_argument_body_length_is1':b['native_compiled_dispatch_entries'][0]['args'][-1]==1,
        'no_Python_per_message_entry_selection':True}, {'unmodified_dispatch_control':a})
    bad=bytes.fromhex('1003')+bytes.fromhex('040801000706000221150235')
    baseline=fresh('stock');a=baseline.wire(bad);vm=fresh();b=vm.wire(bad)
    check('native_received_AAC_ID_rejects_before_original_config_accept',vm,{
        'baseline_core_accept':a['state']==2 and a['replies'][0]['wire_hex']=='1203',
        'patched_table_reject':b['state']==1 and b['replies'][0]['wire_hex']=='13030729' and not b['callbacks'],
        'actual_native_gate_entry':len(b['native_compiled_dispatch_entries'])==1 and b['native_compiled_dispatch_entries'][0]['args'][-1]==12},
        {'unmodified_dispatch_control':a})
    vm=fresh();configured=vm.wire(b'\x10\x03'+CONFIG);op=vm.wire(bytes.fromhex('100604'))
    vm.incoming();vm.config_request();ready=vm.config_confirm();started=vm.wire(bytes.fromhex('100704'))
    media=vm.media(b'native-table-bound-no-decoder-fixture');paused=vm.wire(bytes.fromhex('100904'))
    resumed=vm.wire(bytes.fromhex('100704'));reset=vm.native('disconnect_notification',0x50be1c,[MEDIA_LCID])
    again=vm.wire(b'\x20\x03'+CONFIG)
    check('native_wire_config_Open_Start_suspend_reconnect_same_VM',vm,{
        'wire_config_accept':configured['replies'][0]['wire_hex']=='1203' and configured['state']==2,
        'wire_Open_then_original_completion':op['pending']==2 and ready['original_ready_helper_executed'] and ready['state']==4,
        'wire_Start_and_media':started['replies'][0]['wire_hex']=='1207' and media['callbacks'][0]['status']==0,
        'wire_pause_resume_stock_handlers':paused['state']==4 and resumed['state']==8,
        'disconnect_then_transaction2_config':reset['original_reset_executed'] and again['replies'][0]['wire_hex']=='2203'})

    # Actual stock command dispatcher truncates fifth argument to8bits. A
    # table-only hook therefore accepts a valid prefix with256 trailing bytes.
    oversized=b'\x10\x03'+CONFIG+bytes(256)
    baseline=fresh('table_only');a=baseline.wire(oversized);vm=fresh();b=vm.wire(oversized)
    check('full_length_patch_fences_native_uint8_prefix_acceptance',vm,{
        'table_only_native_length_wrap':a['native_compiled_dispatch_entries'][0]['args'][-1]==12 and
            a['state']==2 and a['replies'][0]['wire_hex']=='1203',
        'patched_length_retains268':b['native_compiled_dispatch_entries'][0]['args'][-1]==268,
        'no_accept_or_endpoint_change':b['state']==1 and b['replies'][0]['wire_hex']=='13030011' and not b['callbacks']},
        {'table_only_control':a})
    oversized=bytes.fromhex('100204')+bytes(256)
    baseline=fresh('table_only');a=baseline.wire(oversized);vm=fresh();b=vm.wire(oversized)
    check('full_length_patch_fences_capability_uint8_prefix_acceptance',vm,{
        'table_only_length1_accept':a['native_compiled_dispatch_entries'][0]['args'][-1]==1 and a['replies'][0]['wire_hex'].startswith('1202'),
        'full257_rejected':b['native_compiled_dispatch_entries'][0]['args'][-1]==257 and b['replies'][0]['wire_hex']=='130211'})
    for name,wire in [('transport_only',bytes.fromhex('100304080100')),('duplicate_codec',b'\x10\x03'+CONFIG+CONFIG[4:]),
        ('truncated_codec',b'\x10\x03'+CONFIG[:-1]),('owned_Reconfigure',bytes.fromhex('1005040706000021150235'))]:
        vm=fresh();r=vm.wire(wire)
        check('wire_'+name+'_rejected',vm,{'no_accept_callback':r['replies'][0]['wire_hex'].startswith('130') and
            r['state']==1 and not r['callbacks'] and len(r['native_compiled_dispatch_entries'])==1})
    vm=fresh();start=vm.wire(b'\x14\x02\x03'+CONFIG[:5]);end=vm.wire(b'\x1c'+CONFIG[5:])
    check('stock_two_fragment_reassembly_invokes_bound_configuration_gate',vm,{
        'start_buffers_without_gate':not start['native_compiled_dispatch_entries'] and not start['replies'],
        'end_reassembles12_body_then_accepts':end['native_compiled_dispatch_entries'][0]['args'][-1]==12 and
            end['state']==2 and end['replies'][0]['wire_hex']=='1203',
        'original_reassembly_buffer_released':vm.word(CONTEXT+8)==0})
    vm=fresh();first=vm.wire(b'\x14\x02\x03'+CONFIG[:5]);end=vm.wire(b'\x2c'+CONFIG[5:])
    check('fragment_transaction_mismatch_rejected_by_original_parser',vm,{
        'no_handler_or_accept':not end['native_compiled_dispatch_entries'] and
            end['replies'][0]['wire_hex']=='23030001' and end['state']==1 and not end['callbacks']})
    vm=fresh();r=vm.wire(bytes.fromhex('f00204'))
    check('wire_transaction15_capability_preserved',vm,{
        'f202_supported_offer':r['replies'][0]['wire_hex']=='f2020100070600003fff0235' and
            r['native_compiled_dispatch_entries'][0]['args'][2]==15})
    vm=fresh();vm.wire(b'\x10\x03'+CONFIG);r=vm.wire(bytes.fromhex('100404'))
    check('wire_GetConfiguration_uses_owned_entry_then_stock_selected_codec',vm,{
        'selected_codec_reply':r['replies'][0]['wire_hex']=='120401000706000021150235' and
            r['native_compiled_dispatch_entries'][0]['args'][1]==4})
    # Signal11 passes stock range check despite only10 pointers. Stop before
    # the invalid BX; never map or execute the ASCII value as code.
    baseline=fresh('stock')
    try:baseline.wire(bytes.fromhex('100b04'))
    except InvalidDispatchTarget:pass
    else:raise AssertionError('Expected stock range/table mismatch was not reached')
    assert baseline.invalid_branch and baseline.invalid_branch['target']=='0x5046485b'
    vm=fresh();r=vm.wire(bytes.fromhex('100b04'))
    check('range_patch_rejects_signal11_before_ASCII_table_overread',vm,{
        'baseline_stopped_before_invalid_BX':baseline.invalid_branch is not None,
        'patched_never_reads_outside_table':not r['original_indirect_BX_veneer_executed'] and not r['native_compiled_dispatch_entries'],
        'stock_unknown_signal_reply_and_no_callback':r['replies'][0]['wire_hex']=='1000' and not r['callbacks'] and r['state']==1},
        {'stock_invalid_branch':baseline.invalid_branch,'stock_table_entries':10})
    for signal in [0,12,63]:
        vm=fresh();r=vm.wire(bytes([0x10,signal,4]))
        check('unsupported_wire_signal_'+str(signal),vm,{'bounded_stock_unknown_signal_reply':r['replies'][0]['wire_hex']=='1000' and
            not r['native_compiled_dispatch_entries'] and not r['original_indirect_BX_veneer_executed'] and r['state']==1})
    vm=fresh();r=vm.wire(b'\x10')
    check('one_byte_packet_dropped_before_handler_payload_read',vm,{
        'original_short_packet_guard':not r['replies'] and not r['native_compiled_dispatch_entries'] and r['state']==1})

    # There is no safe code gap at CB179C: startup relocates this484-byte
    # image span to high exception-vector memory. Do not place the component.
    vector=next(r for r in stock.copies if r['runtime_start']==0xffff0000)
    assert vector['load_start']==0xcb179c and vector['size']==484
    deps=[Path(__file__),ROOT/'scripts/emulate_native_music_endpoint.py',ROOT/'scripts/emulate_native_music_gate.py',
        ROOT/'scripts/emulate_avdtp_lifecycle.py',ROOT/'scripts/emulate_avdtp_control.py',ROOT/'scripts/analyze_native_sections.py',
        ROOT/'evidence/firmware-analysis/main_02bd.bin',ROOT/'staging/native-music-endpoint/manifest.json',
        ROOT/build['flat'],ROOT/build['elf'],ROOT/'sources/music-policy-reference/bluez-avdtp.c',
        ROOT/'sources/music-policy-reference/avdtp-message-reference.json']
    stage=ROOT/'staging/native-music-dispatch';stage.mkdir(parents=True,exist_ok=True)
    plan={'stock_sha256':EXPECTED,'native_command_dispatcher':hex(0x5247fc),'table':hex(TABLE),
        'patches':vm.patch_plan,'patch_fields_bytes':22,
        'component_manifest':'staging/native-music-endpoint/manifest.json',
        'component_link_address_is_synthetic':True,'device_install_candidate':False,
        'unsafe_to_apply_as_live_flash_image':'No actual component allocation/bootstrap, accepted firmware/loader, stable lifetime or device-ready media pipeline proved. This is a VM construction recipe only.',
        'unknown_signal_reply_captured_at_stock_send_boundary':'1000; outgoing type/signal format versus modern GeneralReject remains unresolved. Stock send implementation and actual phone behavior not validated here.',
        'vector_load_span_not_free_insertion_gap':vector}
    (stage/'patch-plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    deps.append(stage/'patch-plan.json')
    proof={'updated_utc':datetime.now(timezone.utc).isoformat(),'stock_sha256':EXPECTED,
        'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in deps},'build_source_sha256':build['source_sha256'],
        'all_passed':True,'case_count':len(cases),'cases':cases,'cpu_model':'ARM1176',
        'native_L2CAP_wire_parser_fragment_reassembly_and_indirect_dispatch_executed':True,
        'bound_entries_selected_by_native_table_not_per_message_Python':True,
        'fixture_modifications':'Four dispatcher data words16bytes plus full-length4byte and range2byte instruction replacements in VM copy only; all other MAIN bytes preserved.',
        'component_link_address_is_synthetic_no_device_allocation':True,
        'original_uint8_body_length_truncation_and_signal11_table_mismatch_reproduced_offline':True,
        'stock_unknown_reply_1000_captured_modern_reject_format_unresolved':True,
        'media_policy_decoder_callback_still_unbound':True,
        'all_legacy_handlers_large_body_regression_not_verified':True,
        'vector_load_span_not_free_insertion_gap':vector,
        'device_io':False,'backup_firmware_modified':False,'device_firmware_modified':False,
        'VM_firmware_copy_modified':True,'device_install_candidate':False,
        'accepted_loader_real_scheduling_UI_phone_or_speaker_verified':False,
        'limitations':'Explicit offline dispatch-table/instruction variant, not live hook or installable firmware. Component remains linked at synthetic08E00000 with simulated persistent storage/kernel/PSM/signaling transport. Native parser selects handlers from fixed patched table; L2CAP sends/application callbacks remain fixtures. Length and range differences proved on backed-up code only, not device crash/security claims. Unknown signal response1000 captured before stock send implementation, modern GeneralReject/actual phone behavior unresolved. Full-length change has not covered every legacy handler on large inputs. Media policy/decoder callback unbound. No firmware acceptance/real allocation/App/menu/decoder/DAC or phone proof.'}
    target=ROOT/'evidence/firmware-analysis/native-music-dispatch-emulation.json'
    target.write_text(json.dumps(proof,indent=2)+'\n')
    print(json.dumps({'evidence':str(target.relative_to(ROOT)),'cases':len(cases),
        'patch_fields_bytes':22,'device_IO':False,'device_install_candidate':False}))


if __name__=='__main__':main()
