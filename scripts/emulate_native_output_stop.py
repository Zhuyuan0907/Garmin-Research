#!/usr/bin/env python3
"""Stock public stop through output/central tasks, retaining the source node.

This deliberately ends with owned PCM and its native queue node pinned. Stock
STOP/cleanup is not source deletion, and is not permission to recycle PCM.
The peripheral and heap boundaries are inherited offline fixtures.
"""
from datetime import datetime, timezone
import json
from pathlib import Path

from analyze_native_sections import NativeImage, ROOT, EXPECTED
from emulate_native_output_manager import NativeDriver
from emulate_native_source_controller import CENTRAL_GLOBAL, SOURCE_STATES
from emulate_native_memory_audio import POOL10, INSTANCE_BYTES
from emulate_native_audio_registration import require, sha
from emulate_native_memory_notice import check_manifest
from emulate_native_sbc import Reference
from emulate_native_voice_media import packet


def snapshot(m, ticket, stage):
    return {'stage': stage, 'source_state': m.byte(SOURCE_STATES+m.channel),
        'driver_state': m.half(m.driver_record), 'live_gain': m.half(m.driver_record+2),
        'prepared': m.byte(m.record+2), 'mixer_active': m.byte(m.mixer+0x84),
        'scratch_handle': m.word(m.mixer+0xb0), 'queue_nodes': m.half(m.record+0x1c0),
        'owned_release_result': m.pipe('owned_media_release', (ticket,)),
        'driver_requests': [p['opcode'] for p in m.driver_requests],
        'central_messages': [p[0] for p in m.aux_tasks[m.word(CENTRAL_GLOBAL)]['receives']]}


def main():
    previous = ROOT/'evidence/firmware-analysis/native-output-manager-emulation.json'
    prior = json.loads(previous.read_text())
    require(prior['all_passed'] and prior['script_sha256'] ==
            sha((ROOT/'scripts/emulate_native_output_manager.py').read_bytes()),
            'Original output baseline evidence is stale or failed')
    for name, digest in prior['dependency_sha256'].items():
        require(sha((ROOT/name).read_bytes()) == digest, 'Original output dependency is stale')
    stock, reference = NativeImage(), Reference()
    companion, output = map(check_manifest, (ROOT/'staging/native-media-consumer/manifest.json',
                                            ROOT/'staging/native-owned-media/manifest.json'))
    m = NativeDriver(stock, companion, output)
    frames = reference.encode(dict(frequency=0, mode=0, subbands=1, blocks=3,
                                    allocation=0, bitpool=31), frames=2)
    wanted = b''.join(reference.decode_stream(frames))
    tts = m.tts_snapshot()
    m.deliver(packet(frames, 0))
    m.yield_all()
    ticket = m.pipe('owned_media_next')
    require(ticket > 0 and m.slots()[ticket & 3]['bytes'] == len(wanted), 'Owned source absent')
    m.buffer_expected[ticket & 3] = wanted
    node = m.register_owned(ticket)
    m.select_native(ticket)
    require(b''.join(m.native_chunks) == wanted, 'Original writer PCM differs from reference')
    stages = [snapshot(m, ticket, 'playing')]
    require(stages[-1]['source_state'] == 4 and stages[-1]['driver_state'] == 3 and
            stages[-1]['owned_release_result'] == -25, 'Source not active/pinned before stop')
    require(m.kernel_call('stock_public_stop', (m.channel, 1)) == 0, 'Original public stop failed')
    m.yield_all()
    stages.append(snapshot(m, ticket, 'stop_requested'))
    require(stages[-1]['source_state'] == 5 and stages[-1]['driver_state'] == 6 and
            stages[-1]['prepared'] == stages[-1]['mixer_active'] == 1 and
            stages[-1]['queue_nodes'] == 1 and stages[-1]['owned_release_result'] == -25,
            'Stop request incorrectly treated as completed retirement')
    for i in range(4):
        m.frame()
        stages.append(snapshot(m, ticket, f'virtual_frame_{i+1}'))
        require(stages[-1]['owned_release_result'] == -25, 'Stop recycled still-queued owned PCM')
        if stages[-1]['driver_state'] == 0:
            break
    final = stages[-1]
    require(final['source_state'] == 1 and final['driver_state'] == 0 and
            not final['prepared'] and not final['mixer_active'] and not final['scratch_handle'] and
            final['queue_nodes'] == 1 and not m.original_node_removals and
            not m.handles[node]['freed'] and not m.handles[node]['locks'] and
            final['driver_requests'] == [1, 0, 4, 3] and
            final['central_messages'] == [11, 12, 1, 3, 7],
            'Public stop completion/source retention/native FIFO differs')
    instance = m.slots()[ticket & 3]['instance']
    provider = POOL10+instance*INSTANCE_BYTES
    require(instance < 5 and not m.byte(provider+12) and not m.byte(provider+28) and
            bytes(m.uc.mem_read(m.record+0xf4, 68)) == bytes(68) and
            all(h['freed'] and not h['locks'] for h in m.output_handles.values()) and
            m.tts_snapshot() == tts, 'Stop left driver/provider resources or changed TTS state')
    # Shut down only the decoder. The queued source and owned PCM remain
    #intentionally held; this is not an unload/restart/cancellation adapter.
    require(m.pipe('media_worker_shutdown') == 0, 'Decoder shutdown failed')
    m.yield_all()
    m.verify_central()
    for a in (0x36af74, 0x1d8f2c, 0x436d44, 0x1d8c98, 0x3b9dfc):
        require(bytes(m.uc.mem_read(a, 4)) == stock.read(a, 4), 'Claimed stock stop entry altered')
    paths = [ROOT/p for p in prior['dependency_sha256']]
    paths.extend((ROOT/'scripts/emulate_native_output_manager.py', previous))
    result = {'updated_utc': datetime.now(timezone.utc).isoformat(), 'stock_sha256': EXPECTED,
        'script_sha256': sha(Path(__file__).read_bytes()),
        'dependency_sha256': {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in paths},
        'owned_elf_sha256': output['elf_sha256'], 'stages': stages,
        'source_pcm_bytes': len(wanted), 'source_pcm_sha256': sha(wanted),
        'frame_calls': m.frame_calls, 'driver_events': m.output_events,
        'original_public_stop_executes': True,
        'stop_is_asynchronous_then_original_frame_stop_and_central_completion_cleanup': True,
        'provider_scratch_and_driver_ring_retired_but_source_node_and_owned_pcm_retained': True,
        'owned_release_refused_after_stop_completion': True,
        'restart_or_complete_source_cancellation_verified': False,
        'controller_direct_stop15_cleanup19_remove_or_consumer_advance': False,
        'tts_context_and_entire_ring_unchanged': True, 'all_passed': True,
        'compiled_components_changed': False, 'device_io': False, 'device_install_candidate': False,
        'limitations': 'Bounded mono16k two-frame source, stop before first virtual peripheral consumption. Source EOF has already been published by original writer; no long stream, pending producer cancellation, actual speaker mute/fade quality or native restart proved. Public stop executes stock central opcode3/driver state6, native frame helper retires scratch, next frame releases driver ring and central opcode7 cleans provider/methods. Queue node and owned PCM deliberately retained; release returns-25. Existing compiled selection guard requires QUEUED, while stopped source remains ACTIVE; production restart/reselection/cancel policy needs work. Initial physical inventory, peripheral ARM bridge/frame events, heap and arbitration/power remain fixtures. First reads occur before late reader attachment with pinned PCM. Native transport/guard checks execute, but no future-callback exclusion/cross-channel reservation/loading/App UI/SEP/phone/speaker/navigation/safe unload/Google Maps. Tasks/module/queue node/owned PCM retained. No device I/O.'}
    path = ROOT/'evidence/firmware-analysis/native-output-stop-emulation.json'
    path.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'output': str(path), 'all_passed': True, 'retained_queue_nodes': 1,
                      'owned_release_result': final['owned_release_result'], 'device_io': False}))


if __name__ == '__main__':
    main()
