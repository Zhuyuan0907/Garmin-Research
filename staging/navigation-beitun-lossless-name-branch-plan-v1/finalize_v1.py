#!/usr/bin/env python3
"""Document and hash-seal only this new normal-file classification namespace."""
import hashlib
import json
from pathlib import Path

BASE = Path('/root/garmin/staging/navigation-beitun-lossless-name-branch-plan-v1')


def main():
    assert not (BASE / 'SEAL.json').exists()
    rows = json.loads((BASE / 'name-branch-classification.json').read_text())['roster']
    proof = json.loads((BASE / 'proof.json').read_text())
    kinds = {
        'held_branch_existing_exact_parent': '原parent精確匹配；巷弄表示待驗',
        'held_branch_no_existing_exact_parent': 'raw parent缺原名；拒絕猜段／刪prefix',
        'held_branch_section_writing_candidate_parent': 'parent數字段寫法候選；同路未證',
        'held_flat_section_writing_candidate': '數字段寫法候選；同路未證',
        'held_existing_exact_suffix_locality_prefix': '里prefix＋原exact suffix；行政意義待核對',
        'held_flat_literal': 'flat文字形狀；正式名稱／關係待核對',
    }
    short_holds = {
        'plain_integer_house_and_label_agree': '原raw門牌整數guard失敗',
        'whole_flat_road_or_street_shape': '原flat guard失敗（巷弄另分枝）',
        'held_alias_relation': '原近名／prefix關係待判',
        'official_name_and_historical_alias_unverified': '官方／歷史alias未證',
        'coordinate_selection_metadata_ready': '座標衝突或未ready',
        'no_floor_unit_metadata': '樓層／單元metadata',
        'CP950_street_and_house_roundtrip': 'CP950失敗',
        'not_prior_closed_source368': '既有368來源；不重驗',
    }
    lines = ['# 全28名稱分類對照', '',
        '下列都是原字串的可逆文字表示，沒有放行任何街道／門牌。逐group的原門牌、group ID、capture line及原witness完整保存在name-branch-classification.json。', '',
        '|候選完整原名|groups|可逆分解／stock文字候選|分類|既有拒絕／待核對原因|',
        '|---|---:|---|---|---|']
    for r in rows:
        n = r['lossless_name_view']
        display = r['candidate_literal']
        if 'raw_parent_literal' in n:
            display = '＋'.join(x for x in [n['raw_parent_literal'], n['raw_lane_suffix'], n['raw_alley_suffix']] if x)
        if n.get('section_writing_candidate'):
            display += ' → 寫法候選 ' + n['section_writing_candidate']['writing_candidate']
        if n.get('parent_section_writing_candidate'):
            display += '；parent寫法候選 ' + n['parent_section_writing_candidate']['writing_candidate']
        if n.get('locality_prefix_candidates'):
            display = '／'.join(z['raw_prefix'] + '＋' + z['unchanged_suffix'] for z in n['locality_prefix_candidates'])
        hs = '、'.join(short_holds.get(k, k) + '(' + str(v) + ')' for k, v in r['original_failed_guard_group_counts'].items())
        if '之' in n.get('raw_complete_branch_suffix', ''):
            hs += '；巷弄之數字表示待驗，保留原token'
        lines.append(f"|{r['candidate_literal']}|{r['group_count']}|{display}|{kinds[n['class']]}|{hs}|")
    lines += ['', '原門牌表示：19個bare整數、57個保留號suffix的整數字串、26個之號。之號保持held；號suffix不刪掉來假造原strict integer guard通過。', '',
        '38個group的樓層或座標guard只能從mixed-name aggregate知道；不猜是哪一筆，不清除hold。其他群組的已知fail/pass只依aggregate全數或零數，未重新讀來源metadata。', '',
        '平田里文心路四段：舊技術shape合格不等正式flat；本scope補pending-locality分類，平田里＋文心路四段可精確還原且文心路四段在原441名册，prefix行政意義仍未證。北屯區和祥街185巷：整個suffix和祥街185巷不在stock，因此不准刪北屯區映射為既有道路。', '',
        '既有edit1近名保留原witness，沒有同路結論；崇德路2段→二段、3段→三段的精確stock結果只屬字面寫法候選，其他一段近名不被誤選。', '']
    (BASE / 'mapping-summary.md').write_text('\n'.join(lines))
    handoff = '''# navigation-beitun-lossless-name-branch-plan-v1 HANDOFF

已完成普通JSON資料分類：28個缺名literal、102個group的原街名／原門牌均可還原。實際analysis7b4462 EXIT0；新output readonly核對99cb68 EXIT0。沒有讀任何gzip、PBF、source-node ledger、IMG／DB／圖塊，沒有native／guest／編譯／device／audio。

主要結果：16個巷弄原parent在441名冊精確存在；2個raw parent不存在；1個巷弄parent只有數字段寫法候選；2個flat數字段寫法候選；1個pending-locality prefix；6個其他flat literal。所有28名稱仍held，near／prefix不等alias。

平田里文心路四段原classifier技術shape可接受但不能視為confirmed flat。本scope補平田里＋existing exact 文心路四段的待核對表示，不改舊seal、不自動刪prefix、不放行。北屯區和祥街185巷整suffix不在stock，prefix候選gate拒絕。東山路293巷的原parent東山路不在stock，不能補猜一／二段。東山路2段光西巷可保存raw東山路2段＋光西巷，二段只寫法候選。

兩項最小表示研究均為sidecar資料格式：(1)保留raw數字段token與確定中文字寫法candidate／exact stock文字引用；(2)anchored existing-parent＋raw巷／弄＋raw門牌＋group／capture-line／holds。昌平路二段50之6巷2弄／39號保持所有原token，之數字／floor holds未解除。沒有IMG／JAI／新labelref／新recordID。

可恢復範圍：全部102 group IDs、capture lines、原街名及raw house已展開；只有兩個崇德planning JSON含完整node IDs／point／native24，本scope直接保留這些原欄位。另100群組node IDs不在允許JSON，保留原sealed capture path＋SHA＋line＋group ID引用，未聲稱在此scope已materialize。Root另做capture gzip讀回，與本scope讀取範圍分開。38群組mixed-name aggregate不能指定個別floor／coordinate guard，標cannot-assess且held。全per-node原tags本來不在prepared capture中，沒有補造。

401898B是命名analysis runner的3個normal JSON input bytes；準備階段JSON inspection與新output readback另外保存actual chunk，沒有稱整turn single-pass。seal採hash／size／actual stat mode核對，沒有chmod或readonly444聲明，不修改任何舊封存來源。

容量僅算術：441＋28＝469，441＋最多2＝443；沒有配置記錄、測wire-width容量或claim install-ready。原backend owner／STOP_DONE／App／direct-phone／speaker／install／fullTaiwan flags全false；音樂執行線的中斷限制不變。

可讀28行表：mapping-summary.md；原詳細表：mapping-table.md；全逐group字串、IDs參照、近名witness與holds：name-branch-classification.json；两项格式研究：representation-research.json；证据和hash pins：proof.json/source-pins.json。Actual receipts和executed sources一併hash封存。seal後停止本scope，沒有追加來源或圖塊工作。
'''
    (BASE / 'HANDOFF.md').write_text(handoff)
    assert len(rows) == 28 and sum(x['group_count'] for x in rows) == 102
    assert len(json.loads((BASE / 'representation-research.json').read_text())['proposals']) == 2
    assert all(v is False for v in proof['flags'].values())
    files = []
    for p in sorted(BASE.iterdir()):
        if p.name in ['SEAL.json', 'post-seal-tool-receipt.json']:
            continue
        assert p.is_file() and p.suffix != '.gz'
        s = p.stat()
        data = p.read_bytes()
        files.append({'path': str(p.relative_to(Path('/root/garmin'))), 'bytes': len(data),
                      'sha256': hashlib.sha256(data).hexdigest(),
                      'actual_mode_octal': oct(s.st_mode & 0o777), 'mtime_ns': s.st_mtime_ns,
                      'ctime_ns': s.st_ctime_ns, 'inode': s.st_ino, 'device': s.st_dev})
    seal = {'schema': 'hash-size-observed-stat-seal/v1', 'files': files,
            'old_source_files_modified': False, 'chmod_performed': False,
            'new_scope_gzip_read': False, 'all_file_handles_closed': True,
            'seal_self_and_post_terminal_receipt_excluded': True,
            'post_terminal_receipt_expected': 'post-seal-tool-receipt.json',
            'seal_then_stop': True}
    data = (json.dumps(seal, ensure_ascii=False, indent=2) + '\n').encode()
    (BASE / 'SEAL.json').write_bytes(data)
    print(json.dumps({'status': 'new_normal_file_plan_hash_sealed', 'files': len(files),
                      'proof_SHA256': hashlib.sha256((BASE / 'proof.json').read_bytes()).hexdigest(),
                      'seal_SHA256': hashlib.sha256(data).hexdigest(),
                      'gzip_read': False, 'old_files_modified': False, 'stop_after_seal': True}, ensure_ascii=False))


if __name__ == '__main__':
    main()
