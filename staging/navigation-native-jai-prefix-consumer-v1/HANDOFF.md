完成一個新的 selected-family JAI/FTS8 writer 前置，並封存 prefix 最小缺口。

`selected_family_adapter.py` 的
`apply_selected_family_relocation(connection, snapshot, plan)` 接受 caller-owned
新離線 SQLite connection、已 pin 的完整選定家庭 snapshot 和 relocation plan。
它驗441 info preimages與其1444 index_8 rows，而不要求整個 index_8 等於這1444 rows。
其他 index_8 logical rows、其他info IDs/families、其他索引、prefix/segment、metadata
均可存在。它只改 selected info.record、其單一 family start，插入一筆 info/FTS8。

支援的 schema 僅原 stock japan_addr_family / japan_addr_info / FTS3 index_8 三型。
它拒絕 mutation-target/shadow application triggers、已有 caller transaction、未列入
的 selected tuple、info/record-range碰撞、schema或preimage mismatch。BEGIN IMMEDIATE
內執行所有檢查與 DML；任何寫入錯誤回滾441 remaps／family update／newinfo。
這個 API 不開檔、不拷原DB、不提供 production/fixture CLI。呼叫者必須只給新
離線副本連線並 pin source/plan；原 DB／device／canonical 不可傳入。此輪未建立
完整原DB副本，因此不是完整DB格式、pragmas/metadata/sourceidentity/installation
adapter 的認證。FTS3 shadow pages可以改變；保留的是原 logical tuples／其他tables。

新的8 focused controls實際 EXIT0 / bba7d8：原來源441／1444＋3 synthetic unrelated
FTS tuples、其他family/table/index/prefix/segment/metadata保留；extra/corrupt selected
tuple、newinfo collision、recordrange collision、trigger拒絕；FTS INSERT被authorizer
拒絕時整個 transaction 回滾；readonly fixture exact bytes不變。不是舊12controls
或舊sandbox suite replay，不把新host全名MATCH當原機前端成功。

有用的新prefix反例：原北屯441街名本來就有
敦化路一段／敦化路二段／敦平一街／敦平二街／敦平街。
它們的原encoded full names均以敦token `tkfadgj` 開頭，且各有actual full-name
FTS8 tuple；已封存的original tiny prefix query仍回傳敦prefix_rows=[]。
因此先前把『新首字敦缺prefix』直接稱為前端必然blocker，是未驗證推論。
這個反例也不能反過來證明fallback成功。見 `prefix-segment-name-observation.json`。

原SQL table runtime0x0457D644：
offset+0x2C → pointer0x047082A2:
SELECT prefix_id, seg_id FROM japan_addr_prefix WHERE index_record = ?
offset+0x30 → pointer0x04708268:
SELECT segment FROM japan_addr_segments WHERE seg_id = ?

本輪指定原MAIN content reads共12,288B：code0x04423400..0x04426000、SQLtable/text
各512B，依已驗startup copy runtime/load mapping讀出，無wholefirmware scan/hash。
該code窗口中未證實prefix/segment的真caller；candidate literal disassembly不當CFG
或reachable branch證据。沒有強行建立小ARM success case。原SQL字串與data pointers
有實際 bytes 核對。全MAIN SHA引用既有證據，未再全hash。

最小下一缺口：定位+0x2C/+0x30的reachable native caller，執行no-prefix分支與一個
stock有prefix分支；釐清84-byte 一段的21 u16 pairs和102-byte鏈狀infoID suffix段，
不猜兩型能互換，也不先造prefix/segment。Keyboard/page/provider/caller状态仍未知。

仍用敦富六街368號（group37506/node8280986017）作source-backed prototype。
source/raw24 city gate與current441-copy payload均只引用閉合證據，未重跑。
alias/history／北屯districtgeometry／官方道路認定仍held。沒有newIMG/JAI deployment、
USB／Bluetooth／ZIP／canonical／report／sealedv3修改，install_candidate=false。

`final-proof.json` 包含第一個executed API/SQL diagnostic proof與後續既有原名反例；
兩份source script與各terminal/receipt一起封，所有source handles已關閉。scope停止。
