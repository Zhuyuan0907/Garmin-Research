#!/usr/bin/env python3
"""Original audio actor capacity-event response, with a virtual consumer.

Controller posts kernel event0x200; the original actor looks up its channel,
checks output space and posts its own read18. No controller read message is
used. Event arrival and consumption are explicit fixtures, not a real timer,
DMA or hardware IRQ.
"""
from datetime import datetime, timezone
import json
from pathlib import Path

from analyze_native_sections import NativeImage, ROOT, EXPECTED
from emulate_native_mixer_start import NativeStart
from emulate_native_audio_registration import MIX_DESCRIPTOR, require, sha
from emulate_native_memory_notice import check_manifest
from emulate_native_sbc import Reference
from emulate_native_voice_media import packet
from emulate_native_voice_convert import reference_pcm


def capacity_control(stock, companion, output, reference, tables):
    m = NativeStart(stock, companion, output, ring_bytes=6144)
    frames = reference.encode(dict(frequency=0, mode=0, subbands=1, blocks=3,
                                   allocation=0, bitpool=31), frames=15)
    wanted, _ = reference_pcm(reference, frames, 16000, 1, tables)
    tts = m.tts_snapshot()
    m.deliver(packet(frames, 0))
    m.yield_all()
    ticket = m.pipe('owned_media_next')
    require(ticket > 0, 'Maximum packet did not publish owned PCM')
    m.buffer_expected[ticket & 3] = wanted
    m.register_owned(ticket)
    m.select_native(ticket)
    actual = m.start_native()
    require(actual == wanted and len(actual) == 3840 and not m.byte(m.mixer+0x7e),
            'Expected a full source copy stalled before EOF probe')
    reads, sends = len(m.native_chunks), len(m.message_sends)
    before_visits = m.registration_visits[0x2fa0b4]
    # This lower-priority target does not preempt the controller. The post
    #routine preserves r0(target), unlike a preempting call that resumes a
    #parked wait with r0(events). Verify the actual mailbox/ready state.
    post_result = m.kernel_call('_post', (m.mixer_tcb, 0x200))
    require(post_result == m.mixer_tcb and m.word(m.mixer_tcb+4) == 0x200 and
            m.byte(m.mixer_tcb+22) == 1 and m.current() == m.controller,
            'Kernel capacity event did not make the original actor ready')
    m.yield_all()
    require(m.registration_visits[0x2fa0b4] == before_visits+1 and
            len(m.native_chunks) == reads and len(m.message_sends) == sends and not m.byte(m.mixer+0x7e),
            'Capacity event bypassed the original source block-space check')
    require(m.pipe('owned_media_release', (ticket,)) == -25, 'Capacity-blocked source released early')

    # This index advancement is a virtual consumer, not hardware DMA.
    m.put(MIX_DESCRIPTOR+12, m.word(MIX_DESCRIPTOR+16))
    before_visits = m.registration_visits[0x2fa0b4]
    post_result = m.kernel_call('_post', (m.mixer_tcb, 0x200))
    require(post_result == m.mixer_tcb and m.word(m.mixer_tcb+4) == 0x200 and
            m.byte(m.mixer_tcb+22) == 1 and m.current() == m.controller,
            'Kernel rearm event did not make the original actor ready')
    m.yield_all()
    require(m.registration_visits[0x2fa0b4] == before_visits+1 and
            m.native_chunks[reads:] == [b''] and m.byte(m.mixer+0x7e) == 1,
            'Original capacity response did not post and consume its EOF read')
    require(len(m.message_sends) == sends+1 and m.message_sends[-1][0] == 18 and
            m.message_origins[-1] == {'current': m.mixer_tcb, 'kind': 18},
            'Controller supplied a read message instead of original actor capacity response')
    m.finish_native(ticket)
    require(m.tts_snapshot() == tts, 'Capacity event changed navigation TTS context/ring')
    require(m.pipe('media_worker_shutdown') == 0, 'Decoder shutdown failed')
    m.yield_all()
    m.verify_start()
    require(m.byte(m.worker_tcb+22) == 0x80, 'Original decoder self-exit was incomplete')
    return {'case': 'native_event0x200_checks_space_then_self_posts_read18',
            'frames': 15, 'pcm_bytes': len(actual), 'pcm_sha256': sha(actual),
            'virtual_output_ring_bytes': 6144, 'source_block_bytes': 4096,
            'explicit_kernel_event_posts': 2,
            'nonpreempting_post_preserves_target_r0_and_readies_mailbox': True,
            'native_channel_lookup_calls': 2,
            'no_space_event_does_not_enqueue_or_read': True,
            'space_available_event_self_posts_original_read18': True,
            'controller_read18_messages': 0,
            'self_posted_rearm_read18_messages': 1,
            'original_message_count': len(m.message_sends),
            'native_actor_entries': m.native_actor_entries,
            'copy_order_scratch_ring_stack_fifo_guards_and_reference_identical': True,
            'tts_context_and_full_ring_unchanged': True,
            'event_arrival_and_consumer_position_are_explicit_fixtures': True,
            'original_timer_expiry_dma_irq_clock_drain_or_auto_source_transition_verified': False,
            'passed': True}


def main():
    stock, reference = NativeImage(), Reference()
    companion, output = map(check_manifest, (ROOT/'staging/native-media-consumer/manifest.json',
                                            ROOT/'staging/native-owned-media/manifest.json'))
    cv = json.loads((ROOT/'staging/native-pcm-converter/manifest.json').read_text())
    tables = json.loads((ROOT/cv['coefficient_table']).read_text())['tables']
    controls = [capacity_control(stock, companion, output, reference, tables)]
    prior_path = ROOT/'evidence/firmware-analysis/native-mixer-start-emulation.json'
    prior = json.loads(prior_path.read_text())
    paths = [ROOT/p for p in prior['dependency_sha256']]
    paths.extend((ROOT/'scripts/emulate_native_mixer_start.py', prior_path))
    result = {'updated_utc': datetime.now(timezone.utc).isoformat(), 'stock_sha256': EXPECTED,
              'script_sha256': sha(Path(__file__).read_bytes()),
              'dependency_sha256': {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in paths},
              'owned_elf_sha256': output['elf_sha256'], 'controls': controls, 'all_passed': True,
              'compiled_components_changed': False, 'device_io': False, 'device_install_candidate': False,
              'original_actor_event0x200_capacity_gate_and_self_read_message_executed': True,
              'real_capacity_irq_timer_expiry_hardware_output_or_complete_automatic_lifecycle_verified': False,
              'limitations': 'Offline original kernel decoder/audio tasks plus native START14/STOP15 and FIFO. Controller explicitly posts two0x200 kernel events; original actor obtains its channel through original current-task lookup0x2FA0B4, rejects a read when virtual output free space2304<=source block4096, then self-posts read18 after explicit virtual consumer index advancement. Controller never sends read18 in this case. Original post/get/wait executes and source reaches EOF. This is native event response, not proof of original timer expiry, event source, DMA, IRQ, clock or physical speaker output. Source attachment/stop/cleanup/remove/release still controller supplied; output descriptor/no-resampler matching16k rate, heap/locks/generic mutex/priority/hardware hints remain fixtures. No cross-channel pool reservation/list ownership/future callback exclusion, installed module/UI/SEP/phone/navigation concurrency or safe unload. No device I/O.'}
    p = ROOT/'evidence/firmware-analysis/native-mixer-capacity-emulation.json'
    p.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'output': str(p), 'all_passed': True, 'device_io': False}), flush=True)


if __name__ == '__main__':
    main()
