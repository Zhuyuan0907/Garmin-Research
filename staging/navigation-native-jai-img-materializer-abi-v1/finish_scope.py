#!/usr/bin/env python3
"""Close and seal this actual one-container scope; no original source opens."""
import hashlib,json,re
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
def need(ok,msg):
    if not ok:raise ValueError(msg)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(name,row):
    with(HERE/name).open('x')as f:json.dump(row,f,ensure_ascii=False,indent=2);f.write('\n')
def main():
    proof=json.loads((HERE/'proof.json').read_text());case=json.loads((HERE/'actual-native-materializer-case.json').read_text())
    need(proof['all_assigned_checks_passed']and sha((HERE/'probe_actual_query_img.py').read_bytes())==proof['script_sha256'],'Actual executed source/proof binding')
    raw=(HERE/'actual-source-IO.strace').read_bytes();lines=raw.decode().splitlines();sources={}
    names=[proof['candidate']['path'],'evidence/firmware-analysis/main_02bd.bin',case['full_DB_identity']['path']]
    for rel in names:
        full='/root/garmin/'+rel
        opens=[l for l in lines if'openat('in l and full in l]
        reads=[l for l in lines if re.search(r'\b(read|pread64)\(',l)and'<'+full+'>'in l]
        counts=[int(re.search(r'= (\d+)\s*$',l).group(1))for l in reads if re.search(r'= (\d+)\s*$',l)]
        closes=[l for l in lines if'close('in l and'<'+full+'>'in l]
        need(len(opens)==len(closes)==1 and all('O_RDONLY'in l and'O_WRONLY'not in l and'O_RDWR'not in l for l in opens),'Single readonly source descriptor opens/closes')
        sources[rel]=dict(open_syscalls=len(opens),close_syscalls=len(closes),actual_read_syscalls=len(counts),actual_bytes_read=sum(counts),all_opens_readonly=True)
    need(sources[proof['candidate']['path']]['actual_bytes_read']==proof['total_actual_IMG_bytes_read']==75956,'Exact actual IMG reads')
    need(sources['evidence/firmware-analysis/main_02bd.bin']['actual_bytes_read']+4096==proof['original_MAIN']['total_actual_new_MAIN_bytes']==61440,'Actual original content count includes separately receipted first page')
    need(not any('taiwan-latest.osm.pbf'in l or'/dev/sd'in l for l in lines),'No source PBF or physical device')
    save('actual-execution-receipts.json',dict(schema='actual-query-materializer-container-finite-run-receipt/v1',all_assigned_checks_passed=True,
        actual_exit_code=0,actual_terminal_chunk='d103bd',all_source_handles_closed=True,
        source_at_run_sha256=proof['script_sha256'],proof_sha256=sha((HERE/'proof.json').read_bytes()),
        source_read_trace=dict(path=str((HERE/'actual-source-IO.strace').relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),
            options='strace -qq -f -yy -s 0 -e trace=openat,read,pread64,close,newfstatat',payload_strings_suppressed=True),
        exact_named_source_reads=sources,initial_MAIN_page_capture=dict(actual_exit_code=0,terminal_chunk='e5d4e5',bytes=4096,receipt='initial-code-capture-receipt.json'),
        repeated_full_IMG_MAIN_or_DB_hash=False,old_cases_or_suites_replayed=False,
        native_return_status_note='Observed return0 is the genuine 0x04425726 caller after executing 0x04425304 materializer/vectorcopy; no original return hook.',
        no_mutation_of_source_IMG_or_SQLite_or_firmware_or_report_or_device=True))
    district,street,house=[r['actual_native_fields']for r in proof['actual_native_prefixes']]
    save('query-to-container-binding.json',dict(schema='one-source-native-query-to-actual-container-crossbinding/v1',all_assigned_checks_passed=True,
        native_query_entry='0x04425726',native_materializer_entry='0x04425304',actual_caller_return_status=case['native_return_r0'],
        exact_native_chain=case['actual_native_chain_12byte_records'],actual_vector_count=case['actual_query_result_vector_count'],
        JAI_new_street_record_hex='0x3000BCB8',JAI_new_street_lowID=48312,
        actual_IMG_L2=dict(ID=74,fields=district,first=47871,count=442,last_inclusive=48312),
        actual_IMG_L3=dict(ID=48312,fields=street),actual_IMG_L4=dict(ID=3781595,fields=house),
        street_is_last_record_in_actual_district_range=True,street_actual_next4_first_matches_house_ID=True,
        source_node_ID=8280986017,source_group_ID=37506,source_raw24=[1127253,5625400],
        actual_native_LBL_labels=[dict(reference=x['native_ref'],text=x['expected_text'],IMG_source=x['actual_IMG_source'])for x in proof['actual_partial_original_LBL_labels']],
        uninterrupted_native_provider_getter_path_executed=False,native_UI_or_device_acceptance=False,
        official_name_or_alias_evidence_scope='Inherited inputs retain historical/official-name held. Root primary-source follow-up is separate and not mixed into this seal.'))
    handoff='''# One-source query materializer and actual 4K IMG linkage

實際執行 `d103bd` EXIT 0。Actual new disabled IMG SHA inherited
`26a47f00fc84de49cf107df5b50504ff62849cb61d384e2d97b236aca400b8f9`、132173824 B。
只讀75,956 B（真raw FS、one rb open/close）；新增原MAIN61,440 B（含initial page
`e5d4e5` 4,096 B），重用前scope保存JAI兩頁8,192 B。Cache不重讀原pages。
完整離線DB也只one readonly open/close；exact syscalls與bytes見actual receipt。
來源stat未變，source handles全部closed，沒有wholehash重跑或IMG/DB修改。

這輪跨過前scope stop：新完整敦富六街 token query在真 `0x04425726` consumer
缺prefix→FTSfallback支線實際執行 `0x04425304` materializer。原SQL family查詢
與原vectorcopy產生一個3項結果鏈（每項12 B）：
`[3,48312,0] → [2,74,FFFFFFFF] → [1,8,FFFFFFFF]`，原caller返回0。
其中第3word是這次觀察到的match offset／sentinel，不泛稱其全部語義。
0x3000BCB8 native record轉成level3/low48312不是host預先寫出的native結果。

SQL底層使用完整實際readonly prototype DB，是明示外部fixture；ASCII encoded
token compare/advance、JAI object ready/statement handles與预配vector/chain buffers
也明示fixtures。原JAI caller/materializer/parentloop/vectorcopy全部真指令，沒有
hook原函式return，也沒有执行allocator。不是原nativeSQLite或UI成功。

實際IMG由真DSKIMG/FAT讀出header/DIR。原header field-store/division fragment
`0x002CD480..0x002CD49E`接受實際header600..616 stack seam，接到原DIR decoder
`0x044B209E`。不是完整header FS/parser/startup。原packed prefix `0x044B10E4`
使用真未realign的record span及真following4 B，readonly tail後為unmapped page：

- L2 74：next3、first47871、count442，因此最後一筆為48312。
- L3 48312：next4、first3781595、count1、street textref475679。
- L4 3781595：leaf、house textref2967、source/raw24 `[1127253,5625400]`。

三筆皆從這個actual新容器讀，不重播先前v3 proposed-payload suite。packed prefix
停止在metadata `0x0448F740`前，未偽造metadata/registry成功。

Actual GMP指出LBL header，新header原field-store片段回label_start3812824、
label_size3805448、shift3、encoding10、CP950。由原address/bytecopy片段分別
讀出真容器「敦富六街」（ref475679）及「368號」（ref2967）。這是實際LBL
文字，仍是分段执行，並非完整map-registry getter返回。

最小下一缺口：接原query result-vector consumer至MDR provider/context，再跨
`0x0448F740`真metadata/map-registry與完整LBL getter。前sealed static bridge可
引用 `navigation-stock-jai-reader-bridge-v1` 的query→record topnibble/lowID片段；
不得把這輪以同ID連結的分開CPU結果當成 uninterrupted query/provider/getter。
需要先準備source/container一致的metadata context，未知初始化／callback／registry
須明示或保留停點，不直接提供假success。

機器入口為query-to-container-binding.json、actual-native-materializer-case.json、
proof.json及actual-execution-receipts.json。Root另外查到官方路名primary資料；
本scope只封舊source pins與query/IMG結果，不改舊alias/official held證據、不混成
全部alias通過。Source OSM北屯區/source/raw24 gate引用獨立sealed geometry。
UI、device/install acceptance、完整provider/getter及全台完成仍false；沒有包裝
可安裝檔、USB、report或舊sealed scope修改。封存後停止，不重跑case。
'''
    (HERE/'HANDOFF.md').write_text(handoff)
    save('final-proof.json',dict(schema='one-source-query-materializer-actual-container-final-seal-proof/v1',
        all_assigned_checks_passed=True,actual_exit_code=0,actual_terminal='d103bd',
        actual_IMG_bytes_read=75956,actual_new_MAIN_bytes_read=61440,saved_JAI_window_bytes_reused=8192,
        original_caller_materializer_branch_actual_return=0,true_result_chain=[[3,48312,0],[2,74,0xffffffff],[1,8,0xffffffff]],
        actual_IMG_packed_prefixes=3,actual_LBL_labels=2,all_handles_closed=True,
        proof_sha256=sha((HERE/'proof.json').read_bytes()),execution_receipts_sha256=sha((HERE/'actual-execution-receipts.json').read_bytes()),
        uninterrupted_provider_getter_UI_device_acceptance=False,old_suites_replayed=False,installable=False,
        source_alias_and_official_name_reassessment_owned_by_separate_root_scope=True))
    files=[]
    for p in sorted(HERE.iterdir()):
        if p.is_file()and p.name!='sealed-files.json':
            p.chmod(0o444);b=p.read_bytes();files.append(dict(path=str(p.relative_to(ROOT)),bytes=len(b),sha256=sha(b),mode='0444'))
    save('sealed-files.json',dict(schema='actual-one-source-JAI-materializer-IMG-crossbinding-seal/v1',created_utc=datetime.now(timezone.utc).isoformat(),
        all_assigned_checks_passed=True,scope_work_completed=True,file_count=len(files),files=files,
        all_handles_closed=True,installable=False,native_UI_uninterrupted_provider_and_device_acceptance=False))
    (HERE/'sealed-files.json').chmod(0o444)
    print(json.dumps(dict(all_assigned_checks_passed=True,file_count=len(files),seal_sha256=sha((HERE/'sealed-files.json').read_bytes()),
        final_proof_sha256=sha((HERE/'final-proof.json').read_bytes()),source_reads=sources,sealer_original_source_opens=0)))
if __name__=='__main__':main()
