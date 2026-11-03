#!/usr/bin/env python3
"""Check the current music/App checkpoint; older AA audits remain historical."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
def read(name):return json.loads((ROOT/name).read_text())
def sha(name):return hashlib.sha256((ROOT/name).read_bytes()).hexdigest()


def main():
    state=read('evidence/deep-research-state.json')
    task=read('evidence/task-state.json')
    findings=read('reports/findings.json')
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    proof_name='evidence/firmware-analysis/avdtp-capabilities-emulation.json'
    proof=read(proof_name)
    for name,want in proof['source_sha256'].items():
        assert sha(name)==want,name
    native=state['native_app_music'];caps=native['static_findings']['avdtp_capabilities']
    cases={c['name']:c for c in proof['cases']}
    melody=read(state['audio']['latest_physical_test_evidence'])
    music=read(state['audio']['phone_bridge_evidence'])
    mic=read(state['microphone_amplifier']['historical_attempt_evidence'])
    # Validate preserved executable evidence and its dependencies, without
    # relabelling old synthetic experiments as operations in the attended turn.
    retained={}
    for name in ['evidence/firmware-analysis/native-loaded-playback-emulation.json',
                 'evidence/firmware-analysis/native-voice-metadata-emulation.json']:
        obj=read(name)
        dependencies=obj.get('dependency_sha256',obj.get('source_sha256',{}))
        assert dependencies,name
        for path,want in dependencies.items():assert sha(path)==want,path
        retained[name]={'sha256':sha(name),'dependencies_checked':len(dependencies),
                        'offline_device_io':obj['device_io']}
    progress=findings['research_progress']
    checks={
      'exact_native_source_dependencies_and_evidence':proof['stock_sha256']==
          '10ab7e1f864f3e9b39806b7d3b7c7eb11ba597fdd8cfc0796e281f509c5a54a8' and
          caps['evidence_sha256']==sha(proof_name),
      '13_capability_reply_cases_code_stack_heap_guards':proof['all_passed'] and
          len(cases)==proof['case_count']==caps['case_count']==13 and
          all(c['passed'] and c['stack_restored'] and c['code_images_and_guard_canaries_intact']
              and c['reply'][0]['wire_hex']==c['expected_wire_hex'] for c in cases.values()),
      'SDP_only_does_not_supply_endpoint':cases['inactive_endpoint']['reply']==
          cases['SDP_enabled_endpoint_still_inactive']['reply']==[{'channel':4660,'wire_hex':'130212'}],
      'SBC_capabilities_stock_serializer_runs':cases['SBC_capabilities_first_endpoint']['stock_serializer_executed'] and
          cases['SBC_capabilities_third_endpoint']['stock_serializer_executed'],
      'codec_passthrough_not_claimed_decoder_support':proof['codec_ID_and_codec_info_are_serialized_not_decoded_or_validated'] and
          cases['codec_ID_passthrough_does_not_prove_decoder']['reply'][0]['wire_hex'].endswith('0002ffff0235'),
      'native_registration_installation_and_direct_music_still_open':not proof['local_SEP_registration_verified'] and
          not proof['device_io'] and not proof['firmware_modified'] and not proof['device_install_candidate'] and
          not native['native_app_running'] and not native['direct_phone_music_verified'],
      'actual_attended_melody_and_music_confirmed':melody['heard_on_device'] and melody['incoming_answered'] and
          melody['host_cind_restored'] and music['heard_on_device'] and
          music['phone_speaker_observation']=='有持續聽到手機音樂' and
          not music['user_confirmation']['full_duration_limit_continuous_audio_verified'],
      'microphone_cancelled_without_claimed_success':state['microphone_amplifier']['status']=='cancelled_by_user' and
          not state['microphone_amplifier']['requested'] and not state['microphone_amplifier']['next_actions'] and
          mic['microphone_followup_cancelled_by_user'] and
          not mic['microphone_result']['phone_microphone_to_Garmin_verified'] and
          all('microphone' not in x.lower() and '麥克風' not in x for x in state['next_actions']),
      'current_priority_and_original_remaining_scopes':state['ordered_priorities'][1].startswith('原生音訊') and
          'GarminOS' in state['ordered_priorities'][2] and state['native_android_auto']['requested'] and
          state['google_maps']['research_deferred_by_user'],
      'canonical_task_findings_match':findings['deep_research']==state and
          all(task[k]==state[k] for k in ['ordered_priorities','microphone_amplifier','current_priority',
              'latest_user_instruction','native_android_auto','last_goal_turn','next_actions']),
      'progress_time_and_current_plan_visible':progress['estimate_percent']==31 and
          len(progress['completed'])==18 and progress['ordered_priorities']==state['ordered_priorities'] and
          progress['includes_deferred_Google_Maps'] and not progress['goal_completed'] and
          all(x in report for x in ['目前主線：原生藍牙音樂與 GarminOS 播放器 App',
              '後續研究：GarminOS 內建 Android Auto 接收端','麥克風／遠端擴音已依使用者指示取消',
              '13 個案例通過','research-priorities','research-progress','report-updated-time','research-updated-time']),
      'no_private_device_IDs_in_report':not re.search(r'\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b',report) and
          'REDACTED_PRIVATE_ID' not in report,
      'physical_attended_IO_separate_from_offline_native_proof':state['last_goal_turn']['device_io'] and
          not state['last_goal_turn']['device_files_written'] and
          all(not p['offline_device_io'] for p in retained.values()),
      'goal_remains_active_no_achieve':state['goal_status']=='active' and not state['goal_complete'] and
          state['required_work_remaining'] and state['latest_user_instruction']['goal_completion_forbidden_by_user'],
    }
    assert all(checks.values()),[name for name,ok in checks.items() if not ok]
    name='evidence/firmware-analysis/native-music-priority-checkpoint-audit.json'
    (ROOT/name).write_text(json.dumps({'updated_utc':datetime.now(timezone.utc).isoformat(),
       'all_passed':True,'scope_checks':checks,'state_sha256':sha('evidence/deep-research-state.json'),
       'report_sha256':sha('reports/nuvi2565RT.html'),'capabilities_evidence_sha256':sha(proof_name),
       'retained_offline_proofs':retained,'actual_attended_audio_round_device_io':True,
       'new_native_capability_emulation_device_io':False,'device_files_written':False,
       'audit_script_sha256':sha(str(Path(__file__).relative_to(ROOT))),
       'goal_status':'active','full_goal_complete':False},indent=2)+'\n')
    print(json.dumps({'audit':name,'all_passed':True,'scope_checks':len(checks),
        'retained_dependencies':sum(x['dependencies_checked'] for x in retained.values())}))


if __name__=='__main__':main()
