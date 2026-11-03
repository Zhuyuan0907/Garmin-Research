#!/usr/bin/env python3
"""NEW immutable FILE-ONLY review; no emulator imports or guest execution.

This reads exact HWID1352/SW8.00 MAIN and frozen historical inputs. It never
executes old analyzers, builds, guests or publishers and writes only NEW files.
"""
import hashlib
import json
from pathlib import Path
import struct
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'scripts'))
from analyze_native_sections import NativeImage
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_GRP_JUMP
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path):
    return json.loads((ROOT / path).read_text())


def main():
    targets = [OUT / 'native-receiver-to-compiled-ingress-contract.json',
               OUT / 'native-receiver-exact-source-fragments.json']
    if any(p.exists() for p in targets):
        raise RuntimeError('Terminal sources/outputs are immutable; use a NEW version')
    image = NativeImage()
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    dependencies = [Path(__file__).relative_to(ROOT).as_posix(),
        'scripts/analyze_native_sections.py', 'evidence/firmware-analysis/main_02bd.bin',
        'evidence/firmware-analysis/avdtp-media-dispatch-emulation.json',
        'evidence/firmware-analysis/avdtp-control-emulation.json',
        'evidence/firmware-analysis/avdtp-lifecycle-emulation.json',
        'evidence/firmware-analysis/native-music-endpoint-emulation.json',
        'evidence/firmware-analysis/native-music-loaded-emulation.json',
        'evidence/firmware-analysis/native-music-continuous-emulation.json',
        'staging/native-music-endpoint/manifest.json',
        'staging/native-music-loaded/manifest.json',
        'staging/native-music-continuous/manifest.json',
        'native/music-endpoint/endpoint.c', 'native/music-endpoint/endpoint.h',
        'native/avdtp-gate/gate.c', 'native/avdtp-gate/gate.h',
        'native/avdtp-policy/policy.c', 'native/avdtp-policy/policy.h',
        'native/music-continuous/entry.c', 'native/music-continuous/runtime.c',
        'native/music-continuous/stream.c', 'native/sbc-prototype/app_component_entry.c',
        'staging/native-music-continuous/music_patch_imports.h',
        'staging/native-player-sbc-sync/build-v3/source-snapshot/04-mixer_source_sbc_v1.c',
        'staging/native-player-sbc-sync/build-v3/source-snapshot/03-audio_session_driver_v4.c',
        'staging/native-player-sbc-sync/static-review/sbc-pipeline-build-v3-peer-review.json',
        'staging/native-player-sbc-sync/static-review/sbc-pipeline-build-v3-static-seal.json']
    before = {p: sha(ROOT / p) for p in dependencies}
    checks = []
    def check(name, value):
        if not value:
            raise AssertionError(name)
        checks.append({'name': name, 'passed': True})
    # Direct branches are traversed, calls are recorded without executing them.
    # The bounds exclude literal pools/diagnostic ASCII. Indirect jumps stop.
    ranges = [
        ('original_L2CAP_PSM25_initializer', 0x4ccc3c, 0x4ccd36),
        ('original_L2CAP_descriptor_init', 0x50c138, 0x50c150),
        ('original_L2CAP_registration', 0x50c150, 0x50c2be),
        ('original_nonempty_receive_wrapper_and_media_dispatch', 0x50bbb8, 0x50bd26),
        ('original_LCID_lookup', 0x525138, 0x525176),
        ('original_Discover', 0x5747b4, 0x574852),
        ('original_Configure', 0x574acc, 0x574daa),
        ('original_Start_Suspend', 0x5752cc, 0x57546e),
        ('original_disconnect_media_callback', 0x543e0c, 0x543eb0),
        ('original_SEP_reset_preserving_callback', 0x575678, 0x5756a6),
        ('original_SDP_enable', 0x607f9c, 0x608030),
        ('original_DLL_outer_entry', 0x3b331a, 0x3b3336),
        ('original_DLL_export_registration', 0x2356bc, 0x235714),
        ('original_BX_R4_veneer', 0x427588, 0x42758a),
        ('original_BX_R7_veneer', 0x42758e, 0x427590)]
    fragments = []
    by_address = {}
    for name, start, end in ranges:
        pending, seen, edges, stops = [start], {}, [], []
        while pending:
            a = pending.pop()
            if a in seen:
                continue
            if not start <= a < end:
                stops.append({'address': hex(a), 'reason': 'outside declared function bound'})
                continue
            ins = next(md.disasm(image.read(a, min(4, end-a)), a, count=1), None)
            if ins is None:
                raise AssertionError(f'Undecodable reachable instruction {a:x}')
            row = {'address': hex(a), 'bytes': bytes(ins.bytes).hex(),
                   'mode': 'Thumb', 'mnemonic': ins.mnemonic, 'operands': ins.op_str}
            if ins.mnemonic == 'ldr' and len(ins.operands) == 2:
                mem = ins.operands[1]
                if mem.type == ARM_OP_MEM and mem.mem.base == ARM_REG_PC:
                    lit = ((a+4)&~3)+mem.mem.disp
                    row['literal_address'] = hex(lit)
                    row['literal_bytes'] = image.read(lit,4).hex()
                    row['literal_value'] = hex(image.word(lit))
            seen[a] = row
            by_address[a] = ins
            nxt = a + ins.size
            if ins.mnemonic in ('bl','blx'):
                if ins.operands and ins.operands[0].type == ARM_OP_IMM:
                    edges.append({'from':hex(a),'to':hex(ins.operands[0].imm),
                                  'kind':'recorded original call; callee not executed'})
                pending.append(nxt)
            elif ins.mnemonic in ('bx','bxj') or (ins.mnemonic == 'pop' and 'pc' in ins.op_str):
                stops.append({'address':hex(a),'reason':'original return/indirect branch'})
            elif ins.group(CS_GRP_JUMP):
                if ins.operands and ins.operands[-1].type == ARM_OP_IMM:
                    target = ins.operands[-1].imm
                    edges.append({'from':hex(a),'to':hex(target),'kind':'branch'})
                    pending.append(target)
                    if ins.mnemonic != 'b':
                        pending.append(nxt)
                else:
                    stops.append({'address':hex(a),'reason':'indirect control flow boundary'})
            elif (ins.mnemonic in ('mov','add') and ins.op_str.startswith('pc,')):
                stops.append({'address':hex(a),'reason':'computed PC; not guessed'})
            else:
                pending.append(nxt)
        fragments.append({'name':name,'entry':hex(start),'declared_end_exclusive':hex(end),
            'declared_bytes_sha256':hashlib.sha256(image.read(start,end-start)).hexdigest(),
            'reachable_instruction_count':len(seen),
            'instructions':[seen[a] for a in sorted(seen)],'edges':edges,'boundaries':stops})
    exact = [
        (0x4cccd4,'movs','r0, #0x19'), (0x4cccd8,'bl','#0x50c138'),
        (0x4cccf4,'ldr','r0, [pc, #0xdc]'), (0x4cccf6,'str','r0, [sp, #0x20]'),
        (0x4cccf8,'mov','r0, sp'), (0x4cccfa,'bl','#0x50c150'),
        (0x50c27e,'movs','r2, #0x34'), (0x50c282,'blx','#0x39129c'),
        (0x50bbb8,'cmp','r2, #0'), (0x50bbba,'bne','#0x50bbc0'),
        (0x50bbf4,'bl','#0x525138'), (0x50bc08,'ldrb','r1, [r0, #4]'),
        (0x50bc1a,'cmp','r1, #0xff'), (0x50bc26,'ldrb','r7, [r4, #0xf]'),
        (0x50bc28,'cmp','r7, r3'), (0x50bc5c,'ldr','r7, [r0, r2]'),
        (0x50bc60,'bl','#0x5523fc'), (0x50bc82,'ldrb','r0, [r4, #0x12]'),
        (0x50bc84,'cmp','r0, #8'), (0x50bc8c,'movs','r0, #0xf1'),
        (0x50bc8e,'add','r2, sp, #0xc'), (0x50bc90,'str','r6, [sp]'),
        (0x50bc92,'bl','#0x42758e'), (0x50bcba,'bl','#0x42758e'),
        (0x50bcc0,'bl','#0x5523de'), (0x42758e,'bx','r7'),
        (0x525158,'cmp','r0, #0xc'), (0x5747d4,'ldrb','r7, [r4, #0x12]'),
        (0x5747d8,'beq','#0x57480e'), (0x574d12,'bl','#0x5756ac'),
        (0x574d54,'bl','#0x5523fc'), (0x574d84,'bl','#0x427588'),
        (0x5752e4,'movs','r0, #8'), (0x5752e8,'movs','r0, #0x11'),
        (0x575364,'bl','#0x5756ac'), (0x57536a,'beq','#0x575386'),
        (0x5753ae,'strb','r3, [r1, #0x12]'), (0x575416,'ldr','r7, [r2, r0]'),
        (0x57541a,'bl','#0x5523fc'), (0x57543c,'bl','#0x42758e'),
        (0x543e32,'ldr','r4, [r5, r4]'), (0x543e68,'bl','#0x5523fc'),
        (0x543e8a,'bl','#0x427588'), (0x575684,'strb','r1, [r4, #0x12]'),
        (0x608004,'strh','r0, [r1, #4]'), (0x608008,'bl','#0x5523fc'),
        (0x3b3332,'blx','r1'), (0x235700,'str','r5, [r6, r3]')]
    for a,m,o in exact:
        i = by_address.get(a)
        check(f'exact original {a:08x}: {m} {o}', i is not None and (i.mnemonic,i.op_str)==(m,o))
    check('native PSM descriptor callback points to Thumb nonempty media wrapper',image.word(0x4ccdd4)==0x50bbb9)
    for a,v in [(0x50bd9c,0x3a88f50),(0x50bda0,0x3a88ef0),(0x50bda4,0x3a88eb8)]:
        check(f'exact native pool literal {a:x}',image.word(a)==v)
    media = read_json('evidence/firmware-analysis/avdtp-media-dispatch-emulation.json')
    ctrl = read_json('evidence/firmware-analysis/avdtp-control-emulation.json')
    life = read_json('evidence/firmware-analysis/avdtp-lifecycle-emulation.json')
    endpoint = read_json('evidence/firmware-analysis/native-music-endpoint-emulation.json')
    loaded = read_json('evidence/firmware-analysis/native-music-loaded-emulation.json')
    check('old media proof explicitly excludes endpoint registration',media['all_passed'] and media['real_endpoint_registration_verified'] is False)
    check('old control proof preserves actual reject-Start state/callback false positive',ctrl['rejected_Start_can_transition_and_callback_after_successful_reject_send'])
    check('old lifecycle proof preserves pending-Open successful media false positive',life['rejected_early_Start_can_deliver_success_media_with_pending_Open'])
    check('compiled provider previously created descriptors; original registration API not recovered',endpoint['SEP_descriptors_created_by_compiled_provider_not_registered_SEP_starting_fixture'] and endpoint['original_endpoint_registration_API_recovered'] is False)
    check('historical loaded entry installed sites itself; physical acceptance explicitly false',loaded['guest_installs_MAIN_sites_no_host_dispatch_rewiring'] and loaded['real_package_acceptance_verified'] is False)
    provider=(ROOT/'native/music-endpoint/endpoint.c').read_text()
    entry=(ROOT/'native/music-continuous/entry.c').read_text()
    source=(ROOT/'staging/native-player-sbc-sync/build-v3/source-snapshot/04-mixer_source_sbc_v1.c').read_text()
    check('compiled provider explicitly custom rather than recovered native API','Custom endpoint provider, not a recovered original registration API' in provider)
    check('compiled provider publishes callback and capability before state1',provider.index('*(volatile uint32_t *)s=callback;')<provider.index('*(volatile uint32_t *)d=(uint32_t)music_endpoint_sbc_caps;')<provider.index('s[0x12]=1;'))
    check('compiled SDP publication unnests AVDTP and DB lock',provider.index('if(unlock()<0)return -38;')<provider.index('int result=((sdp_operation)0x00607f9du)'))
    check('old loaded entry executes original bootstrap before own registration',entry.index('int result=native_app_component_entry(loader);')<entry.index('music_component_state.bootstrap_result='))
    check('old frozen SBC source declared broad cold initialization', '0x277e21u' in source and 'i<18u' in source and '0x269f6du' in source)
    literal_inventory = {}
    for v in [0x3a88eb8,0x3a88ef0,0x3a88f50,0x3a89028,0x3a89058]:
        needle=struct.pack('<I',v);off=0;rows=[]
        while True:
            off=image.data.find(needle,off)
            if off<0:break
            rows.append(hex(off+0x50000));off+=1
        literal_inventory[hex(v)]=rows
    source_rows=[]
    needles={'native/music-endpoint/endpoint.c':['int music_endpoint_prepare','*(volatile uint32_t *)s=callback','s[0x12]=1','int music_endpoint_publish','int result=((sdp_operation)'],
        'native/music-continuous/entry.c':['int native_music_callback','int native_music_start','int result=dispatch_install','music_endpoint_prepare','music_endpoint_publish','int native_music_component_entry'],
        'native/music-continuous/runtime.c':['int __wrap_media_coordinator_init','uint32_t music_runtime_status','int music_runtime_boot','int music_runtime_start_gate'],
        'native/music-continuous/stream.c':['static int snapshot','int music_stream_configuration_gate','static int configure','int music_stream_callback','else if(event==17u','Publish session/copy before waking'],
        'native/sbc-prototype/app_component_entry.c':['int native_app_component_entry','while (at<end)','original_tts_entry(loader)'],
        'staging/native-player-sbc-sync/build-v3/source-snapshot/04-mixer_source_sbc_v1.c':['static int initialize_source','0x277e21u','i<18u']}
    for path,ns in needles.items():
        lines=(ROOT/path).read_text().splitlines()
        for needle in ns:
            matches=[{'line':i+1,'source':s} for i,s in enumerate(lines) if needle in s]
            check(f'frozen source anchor {path}: {needle}',bool(matches))
            source_rows.append({'path':path,'needle':needle,'matches':matches})
    contract={
      'schema':'native-receiver-to-compiled-ingress-static-contract/v1',
      'created_utc':datetime.now(timezone.utc).isoformat(), 'HWID':1352,'software':'8.00',
      'all_passed':True,'scope':'NEW file-only exact original instruction/source review; no new executed guest',
      'MAIN_sha256':sha(ROOT/'evidence/firmware-analysis/main_02bd.bin'),
      'checks':checks,'source_sha256':before,
      'native_L2CAP_registration':{
        'original_initializer':'0x4CCC3C','descriptor_init':'0x50C138','register':'0x50C150',
        'PSM':25,'descriptor_bytes':52,'callback_descriptor_offset':'0x20',
        'callback_pointer':'0x50BBB9','zero_length_wrapper':'0x50BBB8',
        'original_registration_copy':'0x50C282 -> ARM memcpy 0x39129C, length52',
        'scope':'Static exact-source only. Prior proofs controlled kernel/PSM transport; new native PSM registration not executed here.',
        'application_SEP_callback_registration':False},
      'application_SEP_publication':{
        'recovered_original_registration_API':False,
        'compiled_provider':'native/music-endpoint/endpoint.c:music_endpoint_prepare',
        'earlier_executed_proof':'evidence/firmware-analysis/native-music-endpoint-emulation.json',
        'mechanism':['Original 5523DE mutex','Find genuinely unowned idle SEP and descriptor','Compiled stores callback/MTU/flags/capability descriptor','Compiled state1 last','Claim ownership before AV unlock','Separate compiled music_endpoint_publish verifies identity, AV unlock then original607F9C SDP90007'],
        'host_function_pointer_seeding_is_registration':False,
        'original_pool_literal_inventory_is_exhaustive_API_absence_proof':False,
        'uncertain_failures':'Provider unlock -38 retains installed endpoint/ownership. SDP2504 can mean enabled record with DB unlock failure; never rollback or unload based on return alone.',
        'not_yet_integrated_into_new_Stage1_image':True},
      'media_dispatch':{
        'native_chain':['0x50BBB8 nonempty wrapper','0x50BBC0','0x525138 LCID lookup12slots','0x50BC5C cached SEP callback in r7','0x50BC60 original mutex unlock','0x50BC92/BA BL 42758E','0x42758E BX r7','0x50BCC0 original mutex relock'],
        'caller_ABI':{'r0':'LCID','r1':'borrowed packet pointer','r2':'length'},
        'callback_ABI':{'r0':'eventF1','r1':'0 streaming / 0x131 error','r2':'borrowed stack12-byte handle; bytes0..3 uninitialized','r3':'borrowed packet','stack_word0':'length'},
        'handle_defined_bytes':{'4':'local SEID 1..3','5':'remote SEID','6..11':'peer copied from context+0x16'},
        'raw_channel':'typeFF + matching channelindex, no SBC decode by dispatcher',
        'success_state_check':'state8 after original unlock; insufficient validated remoteStart/admission evidence',
        'callback_return_is_transport_acceptance_or_playback':False,
        'borrowed_storage_rule':'Copy validated packet and only defined handle bytes into module-owned slot before full callback return; retain neither original pointer.'},
      'callback_lifetime':{
        'media_target_cached_before_unlock':'50BC5C -> 50BC60',
        'disconnect_target_cached_before_unlock':'543E32 -> 543E68 -> 427588',
        'Start_target_cached_before_unlock':'575416 -> 57541A -> 42758E',
        'clearing_SEP_callback_is_quiescence':False,
        'required':'Keep code/capabilities/TCBs/stacks resident, close admission before mutation, preserve generation-tagged typed callback leases through return, wait for native dispatch and deferred consumers to quiesce before any replacement/unload.',
        'late_not_yet_entered_cached_callbacks':'Application callback-entry refcount alone cannot account for native cached target before it enters. Resident module or proven native dispatcher barrier required.'},
      'generation_and_remoteStart':{
        'rejected_Start_false_positive_original_sequence':['575364 reply','57536A reply-return0 branches575386','5753AE writes state8','57543C event17 callback'],
        'configuration_reply_precedes_callback':['574D12 reply','574D54 unlock','574D84 callback'],
        'state8_or_event17_alone_opens_remoteStart':False,
        'required_identity':['monotonic no-wrap configuration/session generation','local and remoteSEID','peer identity','actual callback identity','context/channelindex/LCID/flags/type','validated negotiated codec+MTU','accepted Start for the same generation with no pendingOpen'],
        'copy_protocol':['Close by default','Acquire producer/callback lease','Snapshot matching native/application generation under declared synchronization','Bounded copy to owned reserved slot','Recheck same generation and admission after copy','Commit metadata before native POST Source0x80000','Source drains copied slots only for matching epoch','Recheck before decode and after wholepacket speculative gather before FIFO publication'],
        'revocation':['Suspend','Close','Abort','disconnect','Stop','profile/provider replacement','newconfiguration','failedpublication','generationoverflow'],
        'LCID_reuse_derives_generation':False,
        'new_receiver_gate_implementation_or_execution_proven_here':False},
      'loaded_module_publication_order':{
        'historical_loaded_entry':['original DLL BLX3B3332','native_app_component_entry clears relinked BSS','originalTTSbootstrap registers40 exports via2356BC','native_music_start','dispatch_install guest-owned sites','compiled endpoint_prepare','compiled endpoint_publish'],
        'new_required_order':['Single guarded resident loaded entry; never re-clear active module on voice reload','Preserve original40 exports/runtime and check exact image/boot readiness','Complete Stage1 decoder/copiedqueue/guard/profile and actual SourceTCB+stack owner READY','Install validated preaccept Configure/Start and typed5-argument ingress target while admissionclosed','Only then compiled prepare/publish candidate','First admitted external packet wakes Source0x80000; Source owns decode/register/native start/fullsync','Open PLAY only after original initializer fully returns and typed ownership is valid'],
        'Stage1_READY_does_not_require_first_packet_PCM_registration':True,
        'SDP_readiness_checks_not_complete_radio_or_mutex_health':True,
        'main_write_MMU_cache_physical_package_acceptance_still_unproved':True},
      'cold_warm_and_channel8':{
        'frozen_SBC_cold_inputs':'original277E21 + all18 calls269F6D + channel8 profile277D27 were explicitly provided guest boot calls',
        'cold_inputs_are_warm_module_boot':False,
        'warm_requirement':'Inspect and reuse initialized native channel mapping, globalqueue, profile and mixer/Source identities. Never rerun whole18-channel/global initialization on an active system just to make this module ready.',
        'channel8_existing_activity':'Must prove exclusive admission and existing source/list/mixer ownership before registration/profile changes; transient AV/audio mutex is not durable channel8 exclusive capability.',
        'new_Stage1_cold_or_warm_full_device_readiness_proven':False,
        'capacity_preemption':'Source capacity POST may preempt a Mixer still holding its frame/borrow. Model producer and mixer leases separately and prove FIFO slot lifetime; event wake/full Source return is not complete Mixer quiescence.'},
      'next_ROOT_actions':['Integrate actual compiled provider only after guarded Stage1 readiness; preserve original L2CAP versus SEP distinction','Execute NEW guest native receive-dispatch into typed five-arg copy-only ingress with original POST/WAIT Source0x80000 and capacity path','Serialize before/after native SEP/context/channel/state, cached-target callback lifetime, queueepochs/leases, wholeRW and finalRX plus fullreturn snapshots','Add negative rejectedStart/pendingOpen/staleLCID/generationchange/Stop/profile/queuefull/latecallback/capacitypreemption cases','Keep all prototypes resident and goal active; no nativephone/App/speaker/deviceinstallation completion claim'],
      'guest_executed':False,'device_IO':False,'canonical_writes':False,
      'native_phone_App_speaker_verified':False,'native_heap_or_exclusive_Stop_DONE_verified':False,
      'goal_complete':False,'overall_progress_percent':33,'App_progress_percent':20}
    source_output={'schema':'native-receiver-exact-source-fragments/v1',
        'MAIN_sha256':contract['MAIN_sha256'],'fragments':fragments,
        'pool_literal_inventory':literal_inventory,'frozen_source_anchors':source_rows,
        'scope':'Reachable bounded original instructions only; no blind ASCII/literal decoding, no VM, no complete API absence conclusion.'}
    for p in dependencies:
        check(f'input preserved {p}',sha(ROOT/p)==before[p])
    for path, data in zip(targets,[contract,source_output]):
        path.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'all_passed':True,'static_checks':len(checks),
        'bounded_functions':len(fragments),'original_instructions':sum(f['reachable_instruction_count'] for f in fragments),
        'output_sha256':{p.relative_to(ROOT).as_posix():sha(p) for p in targets},
        'source_sha256':sha(Path(__file__)),'guest_executed':False},ensure_ascii=False))


if __name__ == '__main__':
    main()
