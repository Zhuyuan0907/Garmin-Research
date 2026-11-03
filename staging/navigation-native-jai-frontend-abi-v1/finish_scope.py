#!/usr/bin/env python3
"""Seal the finite ABI result without opening MAIN, DB, IMG, or devices."""
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path('/root/garmin')
HERE = Path(__file__).resolve().parent


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(name, value):
    with (HERE / name).open('x') as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
        f.write('\n')


def trace_receipt(name, terminal, exit_code):
    p = HERE / name
    raw = p.read_bytes()
    lines = raw.decode().splitlines()
    db_name = '/root/garmin/staging/navigation-native-jai-full-db-adapter-prototype-v1/TWNJAI-offline-prototype.sqlite'
    source_names = {db_name, str(HERE / 'JAI-runtime-code-64KiB.bin')}
    sources = {}
    for name in source_names:
        open_lines = [l for l in lines if ('openat(' in l and name in l)]
        reads = [l for l in lines if re.search(r'\b(?:read|pread64)\(', l) and '<' + name + '>' in l]
        read_values = [int(re.search(r'= (\d+)\s*$', l).group(1)) for l in reads if re.search(r'= (\d+)\s*$', l)]
        closes = [l for l in lines if 'close(' in l and '<' + name + '>' in l]
        sources[name.removeprefix('/root/garmin/')] = dict(
            exact_read_syscalls=len(read_values),actual_bytes_read=sum(read_values),
            open_syscalls=len(open_lines),close_syscalls=len(closes),
            all_open_flags_readonly=all('O_RDONLY' in l and 'O_RDWR' not in l and 'O_WRONLY' not in l for l in open_lines),
            returned_read_EOF_count=read_values.count(0))
        need(len(open_lines) == len(closes), 'All actual named source descriptors closed')
    need(not any('main_02bd.bin' in l or 'taiwan-latest.osm.pbf' in l or '.img>' in l or '/dev/sd' in l for l in lines), 'Trace excludes original firmware/full PBF/IMG/device')
    return dict(path=str(p.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),terminal_chunk=terminal,
                actual_exit_code=exit_code,sources=sources,
                payload_strings_suppressed_by_strace_s0=True,
                original_MAIN_IMG_PBF_device_opened=False,
                trace_command='strace -qq -f -yy -s 0 -e trace=openat,read,pread64,close,newfstatat')


def main():
    proof = json.loads((HERE / 'proof.json').read_text())
    cases = json.loads((HERE / 'actual-native-guest-cases.json').read_text())
    need(proof['all_assigned_checks_passed'] and cases['case_count'] == 12, 'Actual finite guest pass')
    need(sha((HERE / 'probe_native_jai_frontend.py').read_bytes()) == proof['script_sha256'], 'Exact actually executed runner unchanged')
    receipts = [trace_receipt('initial-SQL-table-guard-refusal.strace','48ac70',1),
                trace_receipt('initial-SQL-spacing-assertion.strace','8e17d7',1),
                trace_receipt('initial-memzero-bound-refusal.strace','b6ee74',1),
                trace_receipt('actual-guest-and-DB-IO.strace','b4873b',0)]
    save('actual-execution-receipts.json',dict(schema='actual-bounded-native-JAI-ABI-execution-receipts/v1',
        all_assigned_checks_passed=True,actual_final_exit_code=0,actual_final_terminal='b4873b',
        executions=receipts,initial_failures_retained=True,
        correction_details=[
            'Initial script expected16 SQL entries; sealed original table actually has exactly18. Corrected finite count before DB open.',
            'Initial text assertion expected single spaces; original record_info SQL literal has trailing spaces. Normalize whitespace only for assertion; original generated SQL was passed to actual SQLite unchanged.',
            'Initial memzero fixture cap624 was incorrect; original immediate125<<3 is exactly1000. Corrected to exact observed size1000; no guest/candidate code modified.' ],
        original_MAIN_capture=dict(terminal_chunk='a9290a',actual_exit_code=0,
            bytes_read=65536,receipt='MAIN-bounded-read-receipt.json',inherited_full_hash_not_recomputed=True),
        sealer_does_not_open_original_MAIN_DB_IMG_PBF_or_devices=True))
    lean = []
    for case in cases['cases']:
        queries = [e for e in case['events'] if e['kind'] == 'actual_readonly_complete_DB_SQL_fixture' and e['handle'] == 0x9100]
        lean.append(dict(name=case['name'],entry=case['entry'],encoded_input=case['input_encoded_token'],
            native_prefix_status=case['original_prefix_return_status'],stop=case['stop_reason'],
            r0_at_stop=case['native_return_r0'],native_function_return_status=case['native_return_r0'] if case['stop_reason']=='native_function_return' else None,
            guest_instructions=case['instruction_count'],host_SQL_queries=queries,
            only_first_SQL_row_consumed_by_native_caller=case['stop_reason'].startswith('native_fallback_first_')))
    save('frontend-ABI-results.json',dict(schema='native-JAI-prefix-fallback-ABI-results/v1',all_assigned_checks_passed=True,
        results=lean,new_source_street=dict(name='敦富六街',info_id=48219,native_record=805354680,
            native_record_hex='0x3000BCB8',nativeStreetID=48312,
            source_example='staging/navigation-native-new-street-source-example-v1/candidate.json',
            source_OSM_geometry='staging/navigation-beitun-district-geometry-v1/source-membership.json',
            source_alias_official_name_held=True),
        evidence_classes=dict(native_code='Unmodified original prefix consumer, caller branches, SQL-string builder and first-column consumer executed.',
            SQL='Actual complete readonly offline-prototype SQLite query, reached via explicit external boundary fixtures.',
            object='Synthetic initialized object/index8/filter/stack state; caller entry is genuine, initialization/UI are not executed.',
            frontend='No keyboard/page UI, full result materializer, native SQLite filesystem implementation or install acceptance.'),
        legacy_case_key_native_return_r0_means_register_at_stop_unless_stop_native_function_return=True))
    geometry_seal = ROOT / 'staging/navigation-beitun-district-geometry-v1/sealed-files.json'
    geometry_raw = geometry_seal.read_bytes()
    need(sha(geometry_raw) == '4f0e22ad6fc5feb9b810bff9abb168dd7ee8dbe00251fd51f51d55c813beb30a', 'Separate inherited geometry seal identity')
    save('final-proof.json',dict(schema='native-JAI-prefix-fallback-final-scope-proof/v1',all_assigned_checks_passed=True,
        actual_final_terminal='b4873b',actual_final_exit_code=0,actual_new_MAIN_content_bytes=65536,
        true_native_case_count=12,actual_guest_instructions=3056,
        final_read_receipt=receipts[-1],all_four_read_receipts=receipts,
        no_original_MAIN_read_after_capture=True,source_handles_closed=True,
        executed_runner_sha256=proof['script_sha256'],
        proof_sha256=sha((HERE/'proof.json').read_bytes()),
        actual_native_cases_sha256=sha((HERE/'actual-native-guest-cases.json').read_bytes()),
        actual_static_ABI_sha256=sha((HERE/'native-consumer-static-ABI.json').read_bytes()),
        separate_inherited_source_district_geometry_seal=dict(path=str(geometry_seal.relative_to(ROOT)),sha256=sha(geometry_raw)),
        missing_prefix_Done_status3_fallback_in_two_true_callers_executed=True,
        actual_full_prototype_SQL_and_native_first_scalar_new48312_verified=True,
        native_SQL_engine_not_executed=True,full_UI_not_verified=True,
        source_alias_official_name_held=True,install_candidate=False,full_Taiwan_complete=False,
        no_IMG_or_device_or_report_or_closed_suite_mutation=True))
    handoff = '''# Native JAI prefix/fallback ABI — finite offline evidence

實際執行：`b4873b`，EXIT 0，12 個新案例，3,056 guest instructions。新增 MAIN
讀取只有最初 65,536 bytes (`a9290a`)，runtime `0x04420000..0x04430000`；runner
只讀保存窗，未再開 firmware。所有完整 DB read handles 已關閉且 stat 未變。

`0x04424E4E` 的 ABI 為 r0=JAI object、r1=encoded token C string、r2=found uint8、
r3=prefix_id uint16、stack arg0=seg_id uint16。Object+0x10 的真 SQL statement
對應 `SELECT prefix_id,seg_id ... WHERE index_record=?`。ROW 回 0，DONE 回 3，
錯誤回 1。`敦`=`tkfadgj` 實際 DB 查無列，原指令回 3；`一`=`tkhcoep` 回 0、
prefix28/segment1116。真 segment helper `0x04424D4E` 亦讀出原 84-byte blob，SHA
`39e98d312e5461bf159fde445a3db0742f6f8823dd6d7bab1f8dc99334361a08`。

TRUE callers `0x04424F14` 與 `0x04425726` 分別在 `0x0442512C`／`0x04425942`
接受狀態 3、建立 `"token*"`，呼叫真 builder `0x04424A84`。第一條 SQL 取
index_record/id，第二條取 index_record/record。可選 filter 的真組合為
`record_info & 15 = ?`、`(record_info >> 4) & 15 IN (...)`，info ID 則 `>>8`。
這些 guest 使用 initialized object fixture 的 byte+0x50=1、level list=3、index8、
LIMIT0,16。原指令建立 SQL、bind wildcard/1/3、step並讀第一列。低 byte0x31
在這些條件下通過，level2 真 query 會空結果；不據此推論所有 lowflag 的語義。

完整 readonly 離線 prototype DB 的實際結果：單字敦 query 含原 5 名
敦化路一段／二段、敦平一街／二街／街及 prototype 敦富六街。新全名 query
唯一 info48219、record805354680=`0x3000BCB8`、street低ID48312。原 caller 真實
讀到這些第一列 scalar，但在 materializer 前停止；其餘列清單是 host SQL
fixture 的完整實際結果，不宣稱全列 native 輸出。舊5街 info IDs 不變、prototype
records 已按前 scope relocate，這輪未讀原 backup DB或修改 prototype。

底層 SQL/reset/bind/columns/finalize 與 libc/format/memcopy 是明示 host fixtures。
SQL 由完整實際 SQLite DB (`mode=ro&immutable=1`,query_only) 執行；native SQLite
implementation、filesystem、frontend startup、UTF/keyboard conversion、頁面與全
結果組裝皆未执行。`native_return_r0` 舊 case 欄在提前 stop 時只表示該時刻 r0；
應使用 `frontend-ABI-results.json` 的 r0_at_stop/native_function_return_status。

因此「缺單字敦 prefix 必然阻擋這兩條搜尋 consumer」已不成立。prefix/segments
維持原樣的 selected-family adapter 有來源支持的 fallback 前置證據；完整 UI、
跨檔 JAI→IMG/LBL 整合及實機接受仍待驗，沒有提供新 prefix serializer。

Source 為敦富六街368號、node8280986017、group37506。北屯 source/raw24 geometry
gate 已由独立 sealed `navigation-beitun-district-geometry-v1` 證明，舊 full-DB
scope 的當時 geometry gap 不改寫。歷史 alias／官方街名仍 held；沒有安裝候選，
全台更新亦未完成。Root 的 v2 新street payload scope另管此48312的IMG連結。

機器入口：`frontend-ABI-results.json`、`native-consumer-static-ABI.json`、
`actual-native-guest-cases.json`、`final-proof.json`、`actual-execution-receipts.json`。
3 次本 scope 初始 guard/assertion 失敗保留實際 trace及EXIT1，修正的是原 SQL
table實際18列、原literal空白比較及原memzero立即數1000；最終 genuine code未改。
沒有重跑任何已 closed suite；沒有 PBF、IMG、device、report 或舊 sealed 證據修改。
'''
    (HERE/'HANDOFF.md').write_text(handoff)
    files = []
    for p in sorted(HERE.iterdir()):
        if p.is_file() and p.name != 'sealed-files.json':
            p.chmod(0o444)
            raw = p.read_bytes()
            files.append(dict(path=str(p.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),mode='0444'))
    save('sealed-files.json',dict(schema='bounded-native-JAI-frontend-ABI-seal/v1',
        created_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,
        scope_work_completed=True,file_count=len(files),files=files,
        native_prefix_missing_fallback_proved_with_explicit_SQL_fixtures=True,
        native_full_frontend_UI_verified=False,install_candidate=False,
        source_alias_official_street_held=True,device_IO=False))
    (HERE/'sealed-files.json').chmod(0o444)
    print(json.dumps(dict(all_assigned_checks_passed=True,file_count=len(files),
        seal_sha256=sha((HERE/'sealed-files.json').read_bytes()),
        final_proof_sha256=sha((HERE/'final-proof.json').read_bytes()),
        actual_final_DB_bytes_read=receipts[-1]['sources']['staging/navigation-native-jai-full-db-adapter-prototype-v1/TWNJAI-offline-prototype.sqlite']['actual_bytes_read'],
        no_DB_MAIN_IMG_device_open_in_sealer=True)))


if __name__ == '__main__':
    main()
