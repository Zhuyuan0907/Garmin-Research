# Native JAI prefix/fallback ABI — finite offline evidence

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
