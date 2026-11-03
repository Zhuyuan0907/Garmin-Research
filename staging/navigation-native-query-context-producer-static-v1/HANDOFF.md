# 原 MDR context producer：五份有限靜態 witness

此輪找到真正的 context 初始化 callsite；沒有執行 constructor 或 CPU。

原 query engine 的條件分支 `044DCAE4 → 0448ED78`，經原 ARM veneer 到
`001F18CC`。後者取 **options+C**，按每槽 `0x408` bytes 處理，並在
`001F1952` 呼叫 **002CDAAC**。該函式將 primary name 寫到 context+0，
optional secondary name 寫到 +0D，original encoded source key 寫到 +1C；
**002CDB3A 是真正的 BL002CC44C MDR parser**。

五份 exact-byte witness 在 `context-producer-witnesses.json`：

- W1：cache+18 handle 解開後加4成為 options+C。32BB3C 只證配置 storage。
- W2：原 query engine 的條件 callsite、001F18CC 的 per-slot producer 與 guards。
  另核對 0448E160→17DBAE 是 `BX LR`，不能視為 context initializer。
- W3：002CDAAC 的名字／key 寫入、真正 parser BL，以及原 parser 的欄位 store。
- W4：044B20C0 寫 **DIR+154=MDRctx**；173BB8 的 cached store 與其相符。
  DIR+160 的 selected-child outputflags／fallback1 和 tuple level 分開保存。
- W5：已封存新 IMG header、真 materializer tuple、舊 getter fixture 的靜態資料對照。

`materializer-context-crossbinding.json` 固定 `[3,48312,0] → [2,74,FFFFFFFF] →
[1,8,FFFFFFFF]`，street48312→house3781595，ref475679／2967，原 labels
「敦富六街」／「368號」。所需 MDR fields 是 codepage950、MDR1
offset772／stride4／count1、DIR start124261391／stride20／count6／flags1。
這些由舊 sealed actual windows 檢查，**沒有重新讀 IMG**。舊 getter 的 DIR+154、
DIR+160、FS pair 與 cached GMP／marker 仍是明示 fixture；沒有改稱真冷建立。

最小下一入口是 **001F1952→002CDAAC** 的真 ABI。接續前需有原 1EE324
產生 primary／secondary name、32C4BE encoded-key lookup、原 query cursor／
slot count 與 original FS provider 的實際證據。這輪未追或 fake 這些 helper 的返回。
未繼續 heap／mutex bootstrap，也沒有執行音樂 allocator／admission guest。

本輪新 MAIN **12,288 B**（上限24KiB）、IMG **0 B**、CPU **0 cases**、
exact-byte witnesses **5**；所有 source stats/hash pins 與讀取在 ledger／capture
receipts。沒有新 IMG、裝置、報告、canonical 或舊封存來源變更。舊 parser、query、
getter cases 均未重跑。達五份 witness 後停止。

連續 query→provider→getter、真 SQLite/UI／裝置／可安裝 App／全台更新仍未驗。
root 的2016官方路名證據是另一 scope；此輪保留368地址、歷史 alias 與2026名稱延續的缺口。
