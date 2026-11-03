#!/usr/bin/env python3
"""Publish finite music contract reviews without touching target code/devices."""
import copy
from datetime import datetime, timezone
import gzip
import html
import json
import os
import re
from zoneinfo import ZoneInfo

from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, replace, service, sha

FILES = ['evidence/deep-research-state.json', 'evidence/task-state.json', 'reports/findings.json',
         'reports/nuvi2565RT.html', 'evidence/report-web-latest.json']
INTERFACE = 'staging/native-music-control-stop-interface-readonly-20261007-v1/'
SBC = 'staging/native-music-SBC-capability-contract-readonly-20261007-v1/'
ANDROID = 'staging/native-music-android-AVDTP-contract-readonly-20261007-v1/'
FIELD = 'latest_native_music_contract_checkpoint'
PINS = {
    INTERFACE + 'proof.json': '0e9221ce12081633da3132db88a4536059ff78d0891c5df17c31413f0271de7f',
    INTERFACE + 'comparison.json': 'c3c77791bec2b7267d17f17f10b21d2260c7581f07c7b87c2a42792426d38521',
    INTERFACE + 'sealed-files.json': '96eb4dd0f59740300b7e3bb1924102b9f22f257702396e32a61ffbb3c2ea4543',
    INTERFACE + 'actual-terminal-closure.json': '924cd2a2b91716d485ee1453763bb178d7654781920da5ca1e1b21de25c75e00',
    SBC + 'proof.json': 'c57c83b9018bb99b17670b3fcc3c9a5dbe0c374ddea660b5398624955a498515',
    SBC + 'capability-contract-ledger.json': 'f7fe74e42ce250bfe39caac9eafd3b2f8e641e0db6d7d3a4ba7c0be3c36a2548',
    SBC + 'sealed-files.json': '489e1c64de068097c6ec547b6f21b74cc6fabc4ec86e5c70c9dcfe99848677d7',
    ANDROID + 'proof.json': 'ea84f34ca63154f77782dd4393e6a239adeacc51826346aa5e7414ed3ef40ea7',
    ANDROID + 'android-capability-choice-ledger.json': '48b7aaa32fb84a97521e9faedf9ca95f0ef8ffad6afafb693d0af1de3b258b5b',
    ANDROID + 'sealed-files.json': '13000c8475276ca10be5535814490a9fda267558624e9562a031937a16f6b586',
    ANDROID + 'actual-postcheck-tool-receipt.json': '3da31ee6f458ec22b44a2a9bead2536fb844528fbed20e097506ab829e059113',
}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def pinned(path, pin):
    p = ROOT / path
    require(p.stat().st_size <= 40000, 'Bounded evidence: ' + path)
    raw = p.read_bytes()
    require(sha(raw) == pin, 'Exact closed evidence: ' + path)
    return json.loads(raw)


def main():
    evidence = {p: pinned(p, pin) for p, pin in PINS.items()}
    interface = evidence[INTERFACE + 'proof.json']
    sbc = evidence[SBC + 'proof.json']
    android = evidence[ANDROID + 'proof.json']
    comparison = evidence[INTERFACE + 'comparison.json']
    codec = evidence[SBC + 'capability-contract-ledger.json']
    choice = evidence[ANDROID + 'android-capability-choice-ledger.json']
    require(interface['STOP'] and interface['all_assigned_checks_passed']
            and interface['no_native_implementation'] and not interface['guest_emulator_runs'], 'Closed typed FILE review')
    table = comparison['table_comparison']
    require(table['public_model_bytes'] == 36 and table['old_model_bytes'] == 40
            and table['public_abi_scalar']['name'] == 'abi_version' and table['public_abi_scalar']['offset'] == 0
            and sum(r['matching_public_role'] is not None for r in table['old_function_roles']) == 6
            and not table['cast_compatible'], 'Explicit symbol bindings, not table cast')
    require(comparison['coordinator_field_comparison']['all_fields_equal']
            and comparison['coordinator_field_comparison']['model_bytes'] == 60
            and not comparison['coordinator_field_comparison']['semantics_equivalent'], 'Same view storage, different lifecycle')
    require(sbc['STOP'] and sbc['all_assigned_checks_passed'] and sbc['checks_passed'] == 38
            and sbc['fresh_source_files'] == 8 and sbc['fresh_source_bytes'] == 43671
            and not sbc['target_import_compile_test_guest'], 'Closed codec FILE/scalar review')
    numeric = codec['numeric_summary']
    require(numeric['conservative_15_frame_output_bound_bytes'] == 3840
            and numeric['gather_capacity_bytes'] == 4096 and numeric['arithmetic_only'], 'Arithmetic bound, no execution')
    require(android['STOP'] and android['all_assigned_metadata_checks_passed']
            and choice['sdp_template']['AVDTP_version_uint16'] == 0x100
            and choice['public_Android']['identifiers'] == {'AVDT_SIG_GETCAP': 2, 'AVDT_SIG_GETCONFIG': 4, 'AVDT_SIG_GET_ALLCAP': 12}
            and not choice['conditional_inference']['all_capabilities_12_proven_required_for_this_Pixel_or_this_device'],
            'Version-conditional Android inference, corrected signal names')

    before = {p: (ROOT / p).read_bytes() for p in FILES}
    state, task, public = [json.loads(before[p]) for p in FILES[:3]]
    web = json.loads(before[FILES[4]])
    require(state == public['deep_research'] and state['navigation_repair'] == task['navigation_repair']
            == public['navigation_repair'], 'Prior canonical equality')
    require(all(d['current_goal_priority'] == 'bluetooth_music' and d['goal_status'] == 'active'
                and not d['goal_complete'] for d in (state, task, public, web)), 'Music priority active')
    require(state['navigation_repair']['status'] == 'stopped_by_user' and task['user_away']
            and not state['audio']['audible_tests_allowed'] and not web['current_physical_test_requested'],
            'No navigation work or physical test requested')
    old_native, old_audio, old_nav = [copy.deepcopy(state[k]) for k in ('native_app_music', 'audio', 'navigation_repair')]
    progress = public['research_progress']
    old_estimates = [progress['estimate_percent'], [p['estimate_percent'] for p in progress['phases']]]
    before_service = service()
    require(http(web['url'])[0] == before[FILES[3]], 'Prior exact HTTP')
    now = datetime.now(timezone.utc)
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    stamp = local.isoformat(timespec='seconds')
    checkpoint = {
        'updated_utc': now.isoformat(), 'proof_pins': PINS, 'scope': 'finite saved C/H/docs/JSON and public AOSP source review',
        'public_control_table_model': {'ARM32_source_only': True, 'version_word': True, 'function_pointers': 8, 'bytes': 36},
        'old_adapter_table_model': {'function_pointers': 10, 'bytes': 40},
        'common_named_typed_symbols': 6, 'direct_table_cast_compatible': False,
        'coordinator_view_model': {'bytes': 60, 'fields': 15, 'storage_equal': True, 'lifecycle_equivalent': False},
        'compiler_or_device_ABI_verified_this_turn': False,
        'registration_ticket_is_durable_native_token': False,
        'required_identity_binding': 'persistent native anchor/node-generation token mapped to controller generation, session epoch, ownership cookie and Source actor',
        'typed_started_cleanup_APIs_exist': True,
        'production_started_whole_cleanup_or_wake_service_hooks_verified': False,
        'guard_sync': {'base_C_included': False, 'base_header_line': 5, 'source_body_is_separate_copy': True,
                       'base_C_not_directly_manifest_pinned_proves_missing_implementation': False},
        'SBC': {'capability_bytes': '3f ff 02 35', 'advertised_rates': [44100, 48000],
                'bitpool_range': [2, 53], 'validator_fields_agree': True,
                'converter_supports_advertised_subset': True, 'converter_16k_32k_inputs_also_advertised': False,
                'outer_parser': 'complete nonfragmented RTPv2 packets, 1..15 SBC frames, codec/MTU limits',
                'numeric_summary': copy.deepcopy(numeric),
                'fresh_inner_parser_CRC_or_actual_phone_traffic_verified': False,
                'nsg_config_begin_first_byte_precondition_proves_actual_null_caller': False},
        'original_SDP_template': {'AVDTP_version': '1.0', 'A2DP_version': '1.0', 'live_advertisement_verified': False},
        'Android_inference': copy.deepcopy(choice['conditional_inference']),
        'AOSP_primary_sources': copy.deepcopy(choice['public_Android']['sources']),
        'errata': {
            'signal4_name_corrected_to_GetConfiguration': True, 'GetAllCapabilities_signal': 12,
            'GetAll_delegated_to_stock_claim_withdrawn': True,
            'interface_value_macro_label': 'UMC_ABI_VERSION1 is an inherited label error, not a C identifier; only abi_version at offset0 is used',
            'original_sealed_reviews_preserved': True},
        'FILE_scopes': {'interface': {'fresh_files': 3, 'fresh_bytes': 17119, 'historical_captures_reused': 10},
                        'SBC': {'fresh_files': 8, 'fresh_bytes': 43671, 'FILE_scalar_checks': 38},
                        'root': copy.deepcopy(choice['root_accounting_scope'])},
        'native_compile_execution_guest_original_ASM_MAIN_binary_RAM_source_changes': False,
        'device_BT_DBUS_audio_or_interrupted_guest_retry': False,
        'native_ownership_STOP_DONE_App_direct_phone_speaker_or_install_verified': False,
        'native_install_ready': False, 'full_goal_complete': False,
    }
    next_actions = [
        '下一段先對照同一映像的named controller symbols及provider型別，形成逐symbol接線與持久native來源token對應；不直接cast舊函式表，也不把FIFO ticket當永久來源身分。',
        '依保存的SDP／端點文件核對實際啟用與GetCapabilities／SetConfiguration入口；原廠範本AVDTP1.0只是條件證據，不能拿未核signal12當手機失敗原因，也不能只改宣告版本。',
        '音樂為優先；導航／麥克風取消、Android Auto／Google Maps延後。真實A2DP端點、原機來源／喇叭與菜單仍未完成；使用者會通知可實測時間，現在不要求接線、不自動來電或播放。',
    ]
    state.update(updated_utc=now.isoformat(), next_actions=copy.deepcopy(next_actions))
    state[FIELD] = copy.deepcopy(checkpoint)
    native = state['native_app_music']
    native[FIELD] = copy.deepcopy(checkpoint)
    native['remaining_work'] = copy.deepcopy(next_actions[:2]) + [
        '實際Source READY／每次service／完整停止返回、永久元件保留、原機直接手機播放及菜單尚未證明，沒有可安裝原生整合包。']
    work = state['offline_24h_work_order']
    work[FIELD] = copy.deepcopy(checkpoint)
    work['current_offline_line_status']['native_music'] = (
        'SBC capability/validator subset consistent; table cast rejected by typed ARM32 source comparison; persistent identity providers and physical endpoint activation open')
    turn = {'classification': 'native_music_typed_binding_codec_protocol_FILE_progress', 'validated_utc': now.isoformat(),
            'goal_status': 'active', 'full_goal_complete': False, 'required_work_remaining': True,
            'device_files_written': False,
            'reason': 'Concrete table-order/identity-domain mismatch changes binding plan; codec field alignment and Android version condition narrow negotiation hypotheses; no target execution.'}
    state['last_goal_turn'] = copy.deepcopy(turn)
    for key in ('updated_utc', 'next_actions', 'offline_24h_work_order', FIELD, 'last_goal_turn'):
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state), offline_24h_work_order=copy.deepcopy(work),
                  last_goal_turn=copy.deepcopy(turn))
    public[FIELD] = copy.deepcopy(checkpoint)
    progress.update(research_updated_utc=now.isoformat(), next=next_actions[0])
    for phase in progress['phases']:
        if phase['name'] in ('原生音訊與元件原型', '原生 App 入口與功能整合'):
            phase['next'] = next_actions[0] if 'App' in phase['name'] else next_actions[1]

    report = before[FILES[3]].decode()
    aosp_url = choice['public_Android']['sources'][0]['url']
    card = ('<section class="card" id="bluetooth-music-current-checkpoint-v1"><h2>藍牙音樂：格式一致，控制器介面需要顯式接線</h2>'
            f'<p>更新：<time datetime="{stamp}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>（台灣時間）</p>'
            '<p>這輪完成兩條程式介面／格式核對，以及Android協商條件研究。手機直接連Garmin播放與原生菜單App仍未完成，沒有可安裝整合包。'
            '先前Pixel→Pi→Garmin的60秒有聲是8kHz單聲道通話中繼。</p><ul>'
            '<li><strong>找到具體介面差異：</strong>ARM32源碼模型中，新public表是版本欄＋8個函式指標（36B），舊adapter是10個指標（40B），順序也不同。'
            '6個共用symbol可按完整型別逐項綁定；相同大小的60B來源view仍有不同釋放／生命週期，不能直接轉型。這不是編譯或實機ABI驗證。</li>'
            '<li><strong>來源身分：</strong>新版registration_ticket是初始化稽核值，FIFO槽位可回收。開始／清理回報需要永久native來源身分，'
            '再對應控制器generation、session epoch及ownership cookie；這條provider與每次喚醒service接線仍待完成。</li>'
            '<li><strong>SBC格式：</strong>自製端點的44.1／48kHz、channel modes、bitpool2–53宣告與設定驗證器一致，落在轉換器支援範圍。'
            '外層只接受完整未分片的1–15幀封包；3840B保守輸出界線小於4096B gather。38項FILE／算術核對通過，未重跑解碼器或接收真手機封包。</li>'
            '<li><strong>協定查詢：</strong>更正先前文字：signal4是GetConfiguration；GetAllCapabilities是12，真dispatch12本輪未核。'
            '原廠韌體內的範本宣告AVDTP1.0，並非目前實機公告狀態。AOSP只有對方與本地版本都至少1.3才選全部能力查詢。'
            f'<a href="{html.escape(aosp_url, quote=True)}">Android原始碼</a>。因此，若仍使用1.0範本並遵循此分支，會選一般能力查詢；這是條件推論，不是Pixel實測。</li></ul>'
            '<p><strong>下一段：</strong>核對同一映像的named symbols、永久來源token及真正端點／一般能力與設定入口，再做原機播放與菜單。'
            '這輪沒有native編譯／執行、修改候選或操作裝置；App工程估計維持40%。</p>'
            '<p>導航／麥克風已取消，Android Auto／Google Maps延後。語音恢復2.10已確認。現在不需接線或配對，等使用者通知可實測時間。</p></section>')
    report, count = re.subn(r'<section class="card" id="bluetooth-music-current-checkpoint-v1">.*?</section>',
                           lambda _: card, report, count=1, flags=re.S)
    require(count == 1, 'Current card')
    frontier = ('<p id="offline-frontier-latest-v1">最新：SBC格式宣告與設定驗證一致；新舊控制器表與來源ticket生命週期不同，'
                '改採具型別symbol／永久來源身分的接線方案。Android能力查詢需依實際公告版本判斷，原機直連／App仍未完成。</p>')
    report, count = re.subn(r'<p id="offline-frontier-latest-v1">.*?</p>', lambda _: frontier, report, count=1, flags=re.S)
    require(count == 1, 'Current frontier')
    report, count = re.subn(r'<p><strong>下一步：</strong>以保存的C介面.*?</p>',
                           lambda _: '<p><strong>下一步：</strong>' + html.escape(next_actions[0]) + '</p>', report, count=1, flags=re.S)
    require(count == 1, 'Current next action')
    for name in ('report-updated-time', 'research-updated-time'):
        report, count = re.subn(r'<time id="' + name + r'" datetime="[^"]+">[^<]+</time>',
                               lambda _: f'<time id="{name}" datetime="{stamp}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>',
                               report, count=1)
        require(count == 1, 'Current timestamp: ' + name)
    expected = copy.deepcopy(old_native)
    expected[FIELD] = copy.deepcopy(checkpoint)
    expected['remaining_work'] = copy.deepcopy(native['remaining_work'])
    require(native == expected and state['audio'] == old_audio and state['navigation_repair'] == old_nav, 'History retained')
    require(old_estimates == [progress['estimate_percent'], [p['estimate_percent'] for p in progress['phases']]], 'Estimates retained')
    out = ROOT / 'staging' / ('native-music-contract-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(mode=0o700)
    for path, raw in before.items():
        with (out / (path.replace('/', '__') + '.gz')).open('xb') as stream:
            stream.write(gzip.compress(raw, mtime=0))
            stream.flush()
            os.fsync(stream.fileno())
    for path, value in zip(FILES[:4], (state, task, public, report)):
        replace(path, value)
    served, response = http(web['url'])
    require(served == report.encode() and service() == before_service, 'Fresh HTTP exact; same report service')
    web.update(updated_utc=now.isoformat(), HTTP_status=response['status'], local_report_sha256=sha(served),
               served_report_sha256=sha(served), report_bytes=len(served), service_not_restarted=True,
               offline_24h_work_order=copy.deepcopy(work), last_goal_turn=copy.deepcopy(turn))
    web[FIELD] = copy.deepcopy(checkpoint)
    web['progress_display_verified'].update(report_updated_time=stamp, research_updated_time=stamp,
                                           typed_symbol_not_table_cast_visible=True,
                                           capability_signal_name_erratum_visible=True,
                                           Android_version_inference_not_Pixel_test_visible=True)
    replace(FILES[4], web)
    fresh = [json.loads((ROOT / path).read_bytes()) for path in (FILES[0], FILES[1], FILES[2], FILES[4])]
    require(fresh[0] == fresh[2]['deep_research'] and fresh[0]['navigation_repair'] == fresh[1]['navigation_repair']
            == fresh[2]['navigation_repair'], 'Fresh canonical equality')
    require(all(d[FIELD] == checkpoint and d['goal_status'] == 'active' and not d['goal_complete'] for d in fresh),
            'Music goal active and incomplete')
    create(out / 'fresh-readback.json', {'all_passed': True, 'updated_at_Taiwan': stamp, 'checkpoint': checkpoint,
                                      'report_url': web['url'], 'report_sha256': sha(served), 'service': before_service,
                                      'device_IO': False, 'goal_complete': False})
    print(json.dumps({'all_passed': True, 'snapshot': str(out.relative_to(ROOT)), 'updated_at_Taiwan': stamp,
                      'report_url': web['url'], 'service': before_service, 'device_IO': False}))


if __name__ == '__main__':
    main()
