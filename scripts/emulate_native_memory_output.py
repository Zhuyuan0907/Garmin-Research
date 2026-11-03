#!/usr/bin/env python3
"""Owned compiled PCM -> original kind10 source/mixer lifecycle, offline.

Original actor selects/reads/stops/cleans; tests explicitly supply pool
admission/post-selector/release boundaries. Single-actor/exclusive-channel
contracts, inherited hardware/handle/message fixtures and no installed hooks
are material scope limits. This does not redirect SBC/worker output yet.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import struct

from unicorn import UC_PROT_READ, UC_PROT_EXEC
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from emulate_native_memory_completion import (CompletionAudio, DELETE_AFTER_NOTICE,
                                              DELETE_STACK, REMOVE_SOURCE)
from emulate_native_memory_audio import POOL10, POOL11, INSTANCE_COUNT, INSTANCE_BYTES
from emulate_native_audio_registration import require, sha, MIX_DESCRIPTOR
from emulate_native_audio_messages import POST_SELECT, WAIT
from emulate_native_memory_notice import check_manifest
from emulate_native_sbc import INPUT_PAGE, OUTPUT_PAGE, PAGE_BYTES, RETURN

CALLBACK_STACK = 0x0990c000
CONTROL_FIELDS = ('initialized', 'channel', 'generation', 'active_ticket', 'installed',
                  'native_calls', 'reader_in_flight', 'reads', 'bytes_read', 'releases',
                  'full', 'last_native_result')
SLOT_FIELDS = ('ticket', 'state', 'bytes', 'instance', 'reads', 'in_flight')


class OwnedOutput(CompletionAudio):
    def __init__(self, stock, companion, output):
        super().__init__(stock, companion)
        self.output = output
        self.allowed_channels.add(self.channel)
        code_bytes = (output['flat_binary_bytes']+4095)&~4095
        self.uc.mem_map(output['load_base'], code_bytes)
        self.uc.mem_write(output['load_base'], (ROOT/output['flat_binary']).read_bytes())
        self.uc.mem_protect(output['load_base'], code_bytes, UC_PROT_READ | UC_PROT_EXEC)
        self.state_start = output['symbols']['__output_state_start']['address']
        self.state_end = output['symbols']['__output_state_end']['address']
        self.uc.mem_map(self.state_start, PAGE_BYTES)
        self.uc.mem_write(self.state_start, b'\xa5'*PAGE_BYTES)
        self.uc.mem_write(self.state_start, bytes(self.state_end-self.state_start))
        self.buffers = output['pcm_pages']
        for page in self.buffers:
            self.uc.mem_map(page, PAGE_BYTES)
            # No valid PCM exists before submit; unused bytes are canaries.
            self.uc.mem_write(page, b'\xa5'*PAGE_BYTES)
        self.buffer_expected = {}
        self.symbols.update({k:v for k,v in output['symbols'].items() if k.startswith('memory_output_')})
        self.control = output['symbols']['memory_output_control']['address']
        self.slot_base = output['symbols']['memory_output_slots']['address']

    def out(self, name, args=()):
        return self.external('memory_output_'+name, args)

    def state(self):
        return dict(zip(CONTROL_FIELDS, struct.unpack('<11Ii', self.uc.mem_read(self.control, 48))))

    def slots(self):
        return [dict(zip(SLOT_FIELDS, struct.unpack('<6I', self.uc.mem_read(self.slot_base+i*24, 24))))
                for i in range(4)]

    def submit(self, payload):
        pointer = INPUT_PAGE+PAGE_BYTES-len(payload)
        self.uc.mem_write(INPUT_PAGE, b'\xa5'*PAGE_BYTES)
        self.uc.mem_write(pointer, payload)
        ticket = self.out('submit', (pointer, len(payload)))
        if ticket > 0:
            index = ticket & 3
            self.buffer_expected[index] = payload
            require(bytes(self.uc.mem_read(self.buffers[index], len(payload))) == payload,
                    'Compiled submit did not copy PCM to owned storage')
            self.uc.mem_write(pointer, bytes(len(payload)))
        return ticket

    def register_owned(self, ticket):
        before = self.next_handle
        require(self.out('register', (ticket,)) == 0 and self.next_handle == before+1,
                'Compiled original registration failed or used unexpected nodes')
        handle = 0xd0000000+before
        entry = self.handles[handle]
        require(self.word(entry['pointer']+4) == 0 and self.word(entry['pointer']+8) == 0,
                'Adapter passed a private token as a native client identifier')
        return handle

    def select_owned(self, ticket):
        require(self.out('selection_guard', (ticket,)) == 0, 'Native pool admission failed')
        require(self.call('queue_start', (self.record+0x1a8,)) == 0, 'Original queue start failed')
        require(self.run_worker(((13, 0),), True) == POST_SELECT,
                'Original actor missed post-selector boundary')
        original = bytes(self.uc.mem_read(self.record+0xf4, 68))
        require(self.out('after_selection', (ticket,)) == 0 and
                self.out('after_selection', (ticket,)) == 0, 'Compiled attach/repeated attach failed')
        expected = bytearray(original)
        struct.pack_into('<I', expected, 20, self.symbols['memory_output_read']['address'])
        require(bytes(self.uc.mem_read(self.record+0xf4, 68)) == expected,
                'Post-selector attachment changed another method')
        require(self.run_worker() == WAIT, 'Post-selector actor did not return to wait')
        return self.slots()[ticket & 3]['instance']

    def verify(self):
        super().verify()
        require(not self.state()['native_calls'] and not self.state()['reader_in_flight'],
                'Owned output retained a native/reader call')
        require(bytes(self.uc.mem_read(self.state_end, self.state_start+4096-self.state_end)) ==
                b'\xa5'*(self.state_start+4096-self.state_end), 'Output crossed metadata guard')
        require(bytes(self.uc.mem_read(self.output['load_base'], self.output['flat_binary_bytes'])) ==
                (ROOT/self.output['flat_binary']).read_bytes(), 'Output modified protected code')
        for index, payload in self.buffer_expected.items():
            require(bytes(self.uc.mem_read(self.buffers[index], len(payload))) == payload,
                    'Published immutable PCM changed before reuse')


def fifo_route(stock, companion, output):
    m = OwnedOutput(stock, companion, output)
    require(m.out('configure', (m.channel,)) == 0, 'Output configure failed')
    tts = m.tts_snapshot()
    payloads = [bytes((j*(29+i*2)+i+7)&255 for j in range(n))
                for i,n in enumerate((384, 600, 4096, 512))]
    tickets = [m.submit(p) for p in payloads]
    require(all(t > 0 for t in tickets) and len(set(tickets)) == 4,
            'Owned slots did not issue private distinct tickets')
    require(m.submit(b'\x11\x22'*64) == -24 and m.state()['full'] == 1,
            'Full owned buffer queue was overwritten')
    cases = []
    for ticket, payload in zip(tickets, payloads):
        handle = m.register_owned(ticket)
        require(m.out('release', (ticket,)) == -25, 'Queued borrowed PCM released before selection')
        instance = m.select_owned(ticket)
        m.activate_fixture()
        actual = bytearray()
        supplied_consumer = False
        for part in range((len(payload)+255)//256):
            if len(payload) == 4096 and part == 7:
                # The small mixer has no real DMA consumer in this fixture.
                # First prove original backpressure, then explicitly consume
                #each committed chunk to continue the maximum-size buffer.
                require(len(actual) == 1792 and m.actor_pull() == b'' and
                        m.out('release', (ticket,)) == -25,
                        'Undrained mixer did not retain/stall the owned source')
                m.put(MIX_DESCRIPTOR+12, m.word(MIX_DESCRIPTOR+16))
                supplied_consumer = True
            actual.extend(m.actor_pull())
            if supplied_consumer: m.put(MIX_DESCRIPTOR+12, m.word(MIX_DESCRIPTOR+16))
        require(bytes(actual) == payload and m.actor_pull() == b'', 'Owned PCM/EOF differs from original')
        require(m.out('release', (ticket,)) == -25, 'EOF allowed early buffer recycle')
        m.run_worker(((15, 0),))
        require(m.out('release', (ticket,)) == -25, 'Stop without provider cleanup allowed recycle')
        m.run_worker(((19, 0),))
        require(m.out('release', (ticket,)) == -25, 'Provider cleanup without node remove allowed recycle')
        m.remove_first()
        require(m.handles[handle]['freed'] and m.out('release', (ticket,)) == 0,
                'Complete serialized original lifecycle did not release owned buffer')
        require(m.out('release', (ticket,)) == -28, 'Stale release was accepted')
        cases.append({'ticket': ticket, 'native_instance': instance, 'pcm_bytes': len(payload),
                      'pcm_sha256': sha(bytes(actual)), 'reference_byte_identical': True})
    # Reuse storage with a different private generation; an old ticket cannot
    #release/discard/register the newly copied buffer at the same address.
    extra = b'\x2a\x51'*128
    new_ticket = m.submit(extra)
    require(new_ticket > 0 and (new_ticket & 3) == (tickets[0] & 3) and new_ticket != tickets[0],
            'Freed slot did not retain monotonic private generation')
    require(m.out('discard', (tickets[0],)) == -28 and
            m.out('register', (tickets[0],)) == -28, 'Old token matched reused storage')
    require(m.out('discard', (new_ticket,)) == 0, 'Private unregistered discard failed')
    require(m.state()['releases'] == 4 and m.state()['bytes_read'] == sum(map(len,payloads)) and
            m.tts_snapshot() == tts and all(s['state'] == 0 for s in m.slots()),
            'Owned lifecycle changed navigation PCM or leaked owned slots')
    require(m.worker_entries == 1 and not m.notice_packets, 'Actor restarted or NULL metadata emitted notice')
    m.verify()
    return {'name': 'four_owned_buffers_through_original_serialized_actor',
            'cases': cases, 'queued_private_blocks': 4, 'pcm_bytes': sum(map(len,payloads)),
            'caller_input_destroyed_after_submit': True,
            'native_registration_uses_null_metadata_not_private_tokens': True,
            'only_one_native_source_published_at_a_time': True,
            'original_select13_read18_stop15_cleanup19_and_node_remove_executed': True,
            'max_buffer_original_mixer_stalls_at1792_without_consumer': True,
            'mixer_consumer_index_advance_explicitly_supplied_after_stall': True,
            'actual_dma_or_capacity_wakeup_verified': False,
            'release_rejected_at_queue_eof_stop_and_cleanup_before_node_removal': True,
            'private_generation_stale_tokens_rejected_after_reuse': True,
            'source_instances': [c['native_instance'] for c in cases],
            'tts_context_entire_ring_unchanged': True, 'passed': True}


def parameter_and_method_guards(stock, companion, output):
    m = OwnedOutput(stock, companion, output)
    require(m.submit(b'\x01\x02'*32) == -28, 'Submit before configure was accepted')
    require(m.out('configure', (18,)) == -20 and m.out('configure', (m.channel,)) == 0,
            'Configure channel guard failed')
    before = bytes(m.uc.mem_read(m.control, 48))+bytes(m.uc.mem_read(m.slot_base, 96))
    for pointer, count in ((0, 2), (INPUT_PAGE, 0), (INPUT_PAGE, 3), (INPUT_PAGE, 4098),
                           (m.buffers[0], 2), (0xfffffff0, 32)):
        require(m.out('submit', (pointer, count)) == -20, 'Invalid PCM range was accepted')
        require(bytes(m.uc.mem_read(m.control, 48))+bytes(m.uc.mem_read(m.slot_base, 96)) == before,
                'Invalid PCM submission changed ownership state')
    ticket = m.submit(b'\x44\x33'*64)
    require(m.out('configure', (m.channel,)) == -25, 'Configure discarded a READY buffer')
    handle = m.register_owned(ticket)
    require(m.out('discard', (ticket,)) == -25 and m.out('after_selection', (ticket,)) == -27,
            'Published PCM discarded or unprepared source wrapped')
    m.select_owned(ticket)
    methods = bytes(m.uc.mem_read(m.record+0xf4,68))
    m.put(m.record+0x10c, 0x48f0a5)
    changed = bytes(m.uc.mem_read(m.record+0xf4,68))
    require(m.out('after_selection', (ticket,)) == -27 and
            bytes(m.uc.mem_read(m.record+0xf4,68)) == changed, 'Unrelated format was overwritten')
    m.uc.mem_write(m.record+0xf4,methods)
    m.activate_fixture(); m.stop_cleanup(); m.remove_first()
    require(m.handles[handle]['freed'] and m.out('release', (ticket,)) == 0, 'Guard source cleanup failed')
    m.put(m.control+8, 0x1fffffff)
    require(m.submit(b'\x01\x02'*32) == -30 and all(s['state']==0 for s in m.slots()),
            'Private generation silently wrapped')
    m.verify()
    return {'name': 'parameters_token_generation_and_unrelated_method_guards',
            'invalid_pcm_pointer_count_overlap_and_wrap_rejected': True,
            'live_reconfigure_published_discard_unprepared_attach_rejected': True,
            'unrelated_format_rejected_without_changing_descriptor': True,
            'private_positive_token_generation_overflow_rejected': True, 'passed': True}


def allocation_failure(stock, companion, output):
    m = OwnedOutput(stock, companion, output)
    m.out('configure', (m.channel,)); payload=b'\x6a\x3b'*128
    ticket = m.submit(payload)
    m.fail_next_allocation = True
    require(m.out('register', (ticket,)) == 5 and m.state()['last_native_result'] == 5 and
            not m.state()['active_ticket'] and m.slots()[ticket & 3]['state'] == 2 and
            m.half(m.record+0x1c0) == 0 and not m.factory_results,
            'Original node allocation failure lost PCM or published native source')
    handle = m.register_owned(ticket); m.select_owned(ticket); m.activate_fixture()
    require(m.actor_pull() == payload, 'Retry after allocation failure changed copied PCM')
    m.stop_cleanup(); m.remove_first(); require(m.out('release',(ticket,)) == 0, 'Retry release failed')
    require(m.handles[handle]['freed'], 'Retry node not freed')
    m.verify()
    return {'name': 'original_node_allocation_failure_keeps_ready_owned_pcm',
            'original_registration_failure_code': 5, 'no_native_node_provider_on_failure': True,
            'same_private_ticket_and_immutable_pcm_retry_passed': True, 'passed': True}


def exhausted_pool(stock, companion, output):
    m = OwnedOutput(stock, companion, output)
    m.out('configure', (m.channel,))
    pcm = b'\x19\x72'*64
    for channel in range(5):
        p = m.pcm_page(channel,pcm)
        source = m.register_memory(10,channel,p,len(pcm))
        require(source['constructor_return']==0 and source['instance']==channel,
                'Original kind10 occupancy fixture did not fill pool')
    adjacent = m.register_memory(11,6,m.pcm_page(6,pcm),len(pcm))
    require(adjacent['constructor_return']==0 and adjacent['instance']==0,
            'Original adjacent kind11 fixture did not prepare')
    pools = bytes(m.uc.mem_read(POOL10,2*INSTANCE_COUNT*INSTANCE_BYTES))
    ticket = m.submit(pcm); handle = m.register_owned(ticket)
    factories = len(m.factory_results)
    require(m.out('selection_guard',(ticket,)) == -33 and len(m.factory_results)==factories and
            bytes(m.uc.mem_read(POOL10,2*INSTANCE_COUNT*INSTANCE_BYTES)) == pools,
            'Full pool admission ran dangerous constructor or changed adjacent pool')
    m.remove_first(); require(m.out('release',(ticket,)) == 0 and m.handles[handle]['freed'],
                              'Never-selected source did not release after list removal')
    m.verify()
    return {'name': 'full_native_kind10_pool_rejects_selection_before_constructor',
            'original_kind10_providers_prepared': 5, 'original_kind11_adjacent_provider_prepared': True,
            'pool_bytes_unchanged_and_no_new_factory_invocation': True,
            'guard_is_admission_not_global_cross_actor_reservation': True,
            'real_allocator_race_or_pool_reservation_proved': False, 'passed': True}


def early_remove(stock, companion, output):
    m = OwnedOutput(stock, companion, output)
    m.out('configure',(m.channel,)); ticket=m.submit(b'\x5a\x31'*64)
    handle=m.register_owned(ticket); m.select_owned(ticket); m.activate_fixture(); m.stop_cleanup()
    m.stop_address=DELETE_AFTER_NOTICE
    m.uc.reg_write(UC_ARM_REG_R0,m.record+0x1a8); m.uc.reg_write(UC_ARM_REG_R1,0)
    m.uc.reg_write(UC_ARM_REG_SP,DELETE_STACK); m.uc.reg_write(UC_ARM_REG_LR,RETURN)
    m.uc.emu_start(REMOVE_SOURCE | 1,RETURN,timeout=1000000,count=100000)
    require(m.uc.reg_read(UC_ARM_REG_PC)==DELETE_AFTER_NOTICE and
            not m.handles[handle]['freed'] and m.half(m.record+0x1c0)==1 and
            m.error_notifications[-1]['event']==23, 'Original early-remove boundary changed')
    paused=m.uc.context_save()
    require(m.out('release',(ticket,)) == -25 and m.slots()[ticket & 3]['state']==4,
            'Report23 before original remove return allowed reuse')
    m.stop_address=None; m.uc.context_restore(paused)
    m.uc.emu_start(DELETE_AFTER_NOTICE | 1,RETURN,timeout=1000000,count=100000)
    require(m.uc.reg_read(UC_ARM_REG_PC)==RETURN and m.handles[handle]['freed'] and
            m.out('release',(ticket,)) == 0, 'Remove completion did not release pinned PCM')
    m.verify()
    return {'name': 'original_remove_in_flight_keeps_owned_pcm_pinned',
            'original_report23_called_before_remove_return': True,
            'null_metadata_filters_notice_transport': True,
            'compiled_release_rejects_count1_before_node_free': True,
            'separate_stacks_python_restore_then_complete_remove_release': True,
            'actual_os_preemption_or_callback_quiescence_proved': False, 'passed': True}


def entered_reader(stock, companion, output):
    m=OwnedOutput(stock,companion,output)
    m.out('configure',(m.channel,)); pcm=b'\x2a\x53'*128
    ticket=m.submit(pcm); handle=m.register_owned(ticket); instance=m.select_owned(ticket)
    # Explicit read with mixer inactive; pause after compiled in-flight entry,
    #before original read. This is a defensive entered-callback control,
    #not the serialized actor protocol used by the route test.
    m.stop_address=0x48edf8
    destination=OUTPUT_PAGE+PAGE_BYTES-256
    m.uc.mem_write(OUTPUT_PAGE,b'\xa5'*PAGE_BYTES)
    for reg,val in ((UC_ARM_REG_R0,instance),(UC_ARM_REG_R1,destination),
                    (UC_ARM_REG_R2,256),(UC_ARM_REG_SP,CALLBACK_STACK),(UC_ARM_REG_LR,RETURN)):
        m.uc.reg_write(reg,val)
    m.uc.emu_start(m.symbols['memory_output_read']['address'],RETURN,timeout=1000000,count=100000)
    require(m.uc.reg_read(UC_ARM_REG_PC)==0x48edf8 and m.state()['reader_in_flight']==1,
            'Compiled reader missed in-flight boundary')
    paused=m.uc.context_save()
    # Original cleanup and list remove on another stack leave all native
    #release checks clear; entered-call count must still pin the owned data.
    m.external('source_cleanup',(m.record,)); m.remove_first()
    require(m.handles[handle]['freed'] and m.half(m.record+0x1c0)==0 and
            not m.byte(m.record+2) and not m.byte(m.mixer+0x84), 'Cleanup fixture did not clear native state')
    require(m.out('release',(ticket,)) == -25 and m.state()['reader_in_flight']==1,
            'Entered native reader did not prevent buffer recycle')
    m.stop_address=None; m.uc.context_restore(paused)
    m.uc.emu_start(0x48edf9,RETURN,timeout=1000000,count=100000)
    require(m.uc.reg_read(UC_ARM_REG_PC)==RETURN and m.state()['reader_in_flight']==0,
            'Original reader/compiled wrapper did not return')
    count=m.uc.reg_read(UC_ARM_REG_R0)
    require(count in (0,256) and bytes(m.uc.mem_read(destination,count))==pcm[:count] and
            bytes(m.uc.mem_read(OUTPUT_PAGE,PAGE_BYTES-256))==b'\xa5'*(PAGE_BYTES-256),
            'Original interrupted reader copied outside valid retained PCM/output')
    require(m.out('release',(ticket,)) == 0, 'Returned reader did not allow final release')
    m.verify()
    return {'name': 'entered_reader_pins_pcm_even_after_controlled_native_cleanup_remove',
            'original_reader_pause_address':'0x48edf8', 'original_read_bytes_after_cleanup':count,
            'compiled_counter_blocks_release_after_all_native_state_checks_clear':True,
            'release_only_after_reader_and_wrapper_return':True,
            'explicit_callback_separate_stacks_python_restore_control':True,
            'not_yet_entered_callback_exclusion_or_real_os_quiescence_proved':False,'passed':True}


def main():
    stock=NativeImage()
    companion_path=ROOT/'staging/native-media-consumer/manifest.json'
    output_path=ROOT/'staging/native-memory-output/manifest.json'
    companion,output=map(check_manifest,(companion_path,output_path))
    route=fifo_route(stock,companion,output)
    controls=[parameter_and_method_guards(stock,companion,output),
              allocation_failure(stock,companion,output),exhausted_pool(stock,companion,output),
              early_remove(stock,companion,output),entered_reader(stock,companion,output)]
    dependencies=(ROOT/'scripts/emulate_native_memory_completion.py',
                  ROOT/'scripts/emulate_native_memory_audio.py',
                  ROOT/'scripts/emulate_native_memory_notice.py',
                  ROOT/'scripts/emulate_native_pcm_initialization.py',
                  ROOT/'scripts/emulate_native_audio_messages.py',
                  ROOT/'scripts/emulate_native_audio_registration.py',
                  ROOT/'scripts/emulate_native_pcm_flow_control.py',
                  ROOT/'scripts/emulate_native_sbc.py',ROOT/'scripts/emulate_native_sbc_pcm.py',
                  ROOT/'scripts/analyze_native_sections.py',ROOT/'scripts/analyze_sdp_activation.py',
                  companion_path,output_path)
    result={'updated_utc':datetime.now(timezone.utc).isoformat(),'stock_sha256':EXPECTED,
            'script_sha256':sha(Path(__file__).read_bytes()),
            'dependency_sha256':{str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in dependencies},
            'output_elf_sha256':output['elf_sha256'],'output_flat_binary_bytes':output['flat_binary_bytes'],
            'consumer_companion_elf_sha256':companion['elf_sha256'],
            'route':route,'controls':controls,'all_passed':True,
            'compiled_pcm_copy_registration_reader_and_release_executed':True,
            'private_ticket_not_native_client_id':True,
            'native_pool_guard_not_cross_actor_reservation':True,
            'source_serialization_and_exclusive_channel_list_are_caller_contracts':True,
            'post_selection_and_lifecycle_hook_installed':False,
            'not_yet_entered_callback_exclusion_real_os_quiescence_unload_proved':False,
            'sbc_decoder_queue_worker_output_redirected_or_called':False,
            'existing_consumer_init_runs_in_inherited_fixture':True,
            'existing_consumer_audio_pipeline_called_or_changed':False,
            'raw_notice_observer_or_main_client_exercised':False,
            'device_io':False,'device_install_candidate':False,
            'limitations':'Offline standalone owned finite mono16k PCM source prototype. Four guarded static4096-byte buffers use private monotonic positive tickets and copy before original registration, which uses NULL metadata. Only one source is published at a time. Original mixer actor13/18/15/19 and original source-list removal execute, but admission/post-selector/release are explicit test calls at serialized boundaries, not installed production hooks or automatic playback. Maximum buffer stalls after1792bytes in the2048-byte mixer without consumption; test explicitly advances its read index after proving that stall, not real DMA/hardware consumption or capacity wakeup. Pool inspection avoids full-pool construction only under supplied exclusive allocation boundary; no cross-actor reservation. Release checks native source/method/prepared/pool/mixer/list states and entered-reader counts; they supplement the required one-actor/exclusive-channel contract and do not exclude not-yet-entered callbacks or permit real module unload. Early remove and entered callback controls use separate stacks/Python context restoration; entered-reader cleanup is defensive controlled interleaving, not normal actor ordering/actual OS preemption. Inherited wait/message/handle/mutex/priority/start and activation/mixer/scratch remain fixtures, no actual hardware14/drain/navigation/speaker/resampling. Consumer init is inherited setup only; decoder/FIR/queue/worker output is not redirected or called and no journal/main client is exercised. Actual task/hook installation, capacity wakeup/auto-advance/stop-restart, accepted VPM/SEP/SDP/UI/phone and Google Maps remain incomplete. No device I/O or install candidate.'}
    path=ROOT/'evidence/firmware-analysis/native-memory-output-emulation.json'
    path.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'output':str(path),'compiled_output_bytes':output['flat_binary_bytes'],
                      'pcm_bytes':route['pcm_bytes'],'controls':len(controls),
                      'all_passed':True,'device_io':False}))


if __name__=='__main__':
    main()
