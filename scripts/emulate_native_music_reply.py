#!/usr/bin/env python3
"""Wire-driven GeneralReject experiment through original L2CAP TX queue."""
from datetime import datetime,timezone
import json,struct
from pathlib import Path
import unicorn
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from emulate_avdtp_control import STATE,CONFIG
from emulate_native_l2cap_send import SendVM,sha,ENTITY,FREE,HEAD,TAIL,TX


class ReplyVM(SendVM):
    def __init__(self,stock,build,reply):
        super().__init__(stock,build)
        self.reply_build=reply;self.reply_base=reply['base']
        self.reply_code=(ROOT/reply['flat']).read_bytes()
        self.uc.mem_map(self.reply_base,4096)
        self.uc.mem_write(self.reply_base,self.reply_code)
        self.uc.mem_protect(self.reply_base,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC)
        expected=bytearray(self.code)
        for row in reply['additional_patches']:
            a=int(row['address'],16);before=bytes.fromhex(row['original']);after=bytes.fromhex(row['replacement'])
            assert bytes(self.uc.mem_read(a,len(before)))==before
            self.uc.mem_write(a,after);expected[a-0x50000:a-0x50000+len(after)]=after
            self.patch_plan.append(row)
        self.code=bytes(expected);self.guards()

    def guards(self):
        super().guards()
        if hasattr(self,'reply_code'):
            assert bytes(self.uc.mem_read(self.reply_base,len(self.reply_code)))==self.reply_code


def main():
    stock=NativeImage();build=json.loads((ROOT/'staging/native-music-endpoint/manifest.json').read_text())
    reply=json.loads((ROOT/'staging/native-music-reply/manifest.json').read_text())
    for path,h in {**build['source_sha256'],**reply['source_sha256']}.items():assert sha(ROOT/path)==h,path
    assert sha(ROOT/reply['flat'])==reply['flat_sha256']
    cases=[]
    def fresh():return ReplyVM(stock,build,reply)
    def baseline():return SendVM(stock,build)
    def check(name,vm,result,checks,extra=None):
        assert all(checks.values()),(name,checks,result)
        vm.guards();cases.append({'name':name,'passed':True,'checks':checks,'result':result,'extra':extra or {}})
    for signal in [0,11,12,13,63]:
        for transaction in range(16):
            vm=fresh();original_seps=bytes(vm.uc.mem_read(STATE,96))
            r=vm.wire(bytes([transaction<<4,signal]));expected=bytes([(transaction<<4)|1,signal]).hex()
            check('unknown_'+str(signal)+'_transaction_'+str(transaction)+'_native_general_reject',vm,r,{
                'type1_original_signal_two_byte_body':r['TX_queue'][0]['wire_hex']==expected,
                'actual_native_L2CAP_send_allocation_copy_queue':all(r[k] for k in
                    ['actual_native_L2CAP_send_executed','actual_native_allocator_executed',
                     'actual_native_queue_link_executed','actual_native_scheduler_wrapper_executed']),
                'native_written_payload2':r['native_sends'][0]['native_written_payload_bytes']==2,
                'no_endpoint_callback_or_SEP_state_change':not r['callbacks'] and r['state']==1 and
                    bytes(vm.uc.mem_read(STATE,96))==original_seps,
                'native_mutex_restored':not vm.mutex_held and not vm.l2_held})
    for signal in range(1,11):
        for error in [0,1]:
            a=baseline();before=a.invoke('stock_reply',0x5756ac,[0,15,signal,4,error],thumb=True,held=True)
            vm=fresh();r=vm.invoke('patched_reply',0x5756ac,[0,15,signal,4,error],thumb=True,held=True)
            check('known_signal_'+str(signal)+'_error_'+str(error)+'_relocated_original_reply_identical',vm,r,{
                'original_payload_and_category_error_unchanged':vm.queue()==a.queue(),
                'original_reply_body_after_relocated_prologue_executed':0x5756bc in vm.executed and 0x5756fc in vm.executed,
                'callee_saved_registers_SP_guards':r['compiled_stock_code_initialized_data_input_BSS_heap_core_SDP_guards_SP_saved_registers_intact'],
                'native_core_pools_unchanged':r['stock_pools_unchanged']}, {'stock_reply':before,'stock_TX_queue':a.queue()})
    for name,wire,expected in [
        ('owned_caps','100204','12020100070600003fff0235'),
        ('AAC_preaccept_reject','1003040801000706000221150235','13030729'),
        ('valid_config_accept','1003040801000706000021150235','1203'),
        ('short_known_config_reject','100304','13030011')]:
        a=baseline();br=a.wire(bytes.fromhex(wire));vm=fresh();r=vm.wire(bytes.fromhex(wire))
        check(name+'_wire_dispatch_unchanged',vm,r,{
            'same_native_queued_wire':r['TX_queue'][0]['wire_hex']==br['TX_queue'][0]['wire_hex']==expected,
            'same_state_pending_callback':(r['state'],r['pending'],r['callbacks'])==(br['state'],br['pending'],br['callbacks'])})
    vm=fresh();history=[]
    for packet in [bytes.fromhex('100c'),bytes.fromhex('100204'),bytes.fromhex('1003')+CONFIG,bytes.fromhex('100404')]:
        history.append(vm.wire(packet))
    check('unknown_then_capabilities_configuration_and_GetConfiguration_same_VM',vm,history[-1],{
        'native_queue_retains_all_four_independent_copies':[r['wire_hex'] for r in vm.queue()]==
            ['110c','12020100070600003fff0235','1203','120401000706000021150235'],
        'unknown_context_signal_does_not_block_following_config':history[2]['state']==2 and
            history[2]['callbacks'][0]['event']==9,
        'normal_negotiated_codec_reply_unchanged':history[-1]['state']==2}, {'wire_history':history})
    for name,args in [('channel12',[12,1,12,0,1]),('transaction16',[0,16,12,0,1]),('signal64',[0,1,64,0,1])]:
        vm=fresh();r=vm.invoke('invalid_unknown_envelope',reply['symbols']['music_reply_dispatch'],args,held=True)
        check(name+'_unknown_wrapper_rejects_before_lookup_send',vm,r,{
            'return_minus41':r['return_value']==-41,'no_native_send_or_queue':not vm.native_sends and not vm.queue(),
            'no_core_or_SDP_change':r['stock_pools_unchanged'] and r['SDP_records_unchanged']})
    vm=fresh();first=vm.wire(bytes([0x14,2,3])+CONFIG[:5]);second=vm.wire(bytes([0x2c])+CONFIG[5:])
    check('fragment_transaction_mismatch_known_signal_reject_retained',vm,second,{
        'no_reply_for_first_fragment':not first['TX_queue'],
        'known_error1_reply_retains_category_and_error':second['TX_queue'][0]['wire_hex']=='23030001',
        'no_configuration_callback':not second['callbacks'] and second['state']==1})
    vm=fresh();r=vm.wire(bytes.fromhex('10'))
    check('one_byte_input_original_drop_retained',vm,r,{'no_native_send_or_queue':not r['native_sends'] and not r['TX_queue']})
    vm=fresh();vm.l2_lock_error=-1;r=vm.wire(bytes.fromhex('100c'))
    check('unknown_reply_native_lock_failure_not_delivery',vm,r,{
        'no_queue_no_event':not r['TX_queue'] and not r['OS_event_submissions'],
        'native_output_zero':r['native_sends'][0]['native_written_payload_bytes']==0,
        'native_allocator_not_entered':not r['actual_native_allocator_executed'],
        'mutex_restored':not vm.mutex_held and not vm.l2_held})
    vm=fresh();vm.uc.mem_write(ENTITY+0x1e,b'\x04');vm.entities_expected=bytes(vm.uc.mem_read(ENTITY,880))
    r=vm.wire(bytes.fromhex('100c'))
    check('unknown_reply_native_channel_not_ready_no_queue',vm,r,{
        'no_queue_no_event':not r['TX_queue'] and not r['OS_event_submissions'],
        'native_output_zero':r['native_sends'][0]['native_written_payload_bytes']==0,
        'no_allocator':not r['actual_native_allocator_executed']})
    deps=[Path(__file__),ROOT/'scripts/emulate_native_l2cap_send.py',ROOT/'scripts/emulate_native_music_dispatch.py',
        ROOT/'scripts/emulate_native_music_endpoint.py',ROOT/'scripts/emulate_avdtp_lifecycle.py',
        ROOT/'scripts/emulate_avdtp_control.py',ROOT/'scripts/analyze_native_sections.py']
    proof={'updated_utc':datetime.now(timezone.utc).isoformat(),'MAIN_sha256':EXPECTED,
        'case_count':len(cases),'all_passed':True,'cases':cases,
        'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in deps},
        'build_source_sha256':reply['source_sha256'],'component_manifest_sha256':sha(ROOT/'staging/native-music-reply/manifest.json'),
        'endpoint_manifest_sha256':sha(ROOT/'staging/native-music-endpoint/manifest.json'),
        'bluez_reference_manifest_sha256':sha(ROOT/'sources/music-policy-reference/avdtp-message-reference.json'),
        'additional_patch_plan':reply['additional_patches'],'all_VM_patch_plan':vm.patch_plan,
        'all_VM_patch_fields_bytes':sum(len(bytes.fromhex(p['replacement'])) for p in vm.patch_plan),
        'additional_patch_fields_bytes':18,'reply_component_bytes':reply['flat_bytes'],
        'original_normal_MAIN_other_bytes_preserved':True,'VM_firmware_copy_modified':True,
        'native_send_and_native_queue_execute':True,'GeneralReject_type1_original_signal_verified_offline':True,
        'known_reply_original_body_and_relocated_prologue_verified':True,
        'device_io':False,'firmware_modified_on_device':False,'device_install_candidate':False,
        'actual_radio_phone_speaker_or_accepted_loader_verified':False,
        'media_policy_decoder_callback_still_unbound':True,
        'original_inbound_GeneralReject_processing_not_fixed_or_tested':True,
        'limitations':'Explicit VM-only synthetic08A00000 reply shim plus earlier08E00000 endpoint component/22-byte dispatch recipe. New18-byte patch sites preserve unknown signal and four register arguments/SP at helper wrapper, aggregate40 bytes at8 sites. Native L2CAP allocator/copy/queue/scheduler wrapper execute under explicit channel/kernel/credit fixtures; OS event delivery and radio remain intercepted. Original16-byte prologue is relocated and known1..10 accept/reject paths delegated; full original stack/legacy handler/concurrency regression not proved. No actual allocation/bootstrap/acceptedloader/App/menu/PCM/DAC/device install or phone test.'}
    path=ROOT/'evidence/firmware-analysis/native-music-reply-emulation.json'
    path.write_text(json.dumps(proof,indent=2)+'\n')
    print(json.dumps({'evidence':str(path.relative_to(ROOT)),'case_count':len(cases),
        'all_passed':True,'additional_patch_fields_bytes':18,'aggregate_patch_fields_bytes':proof['all_VM_patch_fields_bytes']}))


if __name__=='__main__':main()
