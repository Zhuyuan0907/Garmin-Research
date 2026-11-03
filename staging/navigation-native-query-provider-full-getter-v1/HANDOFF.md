# 原 MDR provider 與 LBL getter 的實際停點

本 scope 使用已封存的新 4K 單街離線 IMG，執行原生 metadata、registry lookup、cached GMP selection 與 LBL 解碼路徑。實際 guest 從 IMG windows 讀出「敦富六街」及「368號」，但公共 getter **尚未完整回傳**。兩案都停在原文字後處理 `0x044BFF32 → 0x0448E868 → 0x0049A711`；未知 callee 沒有執行或代填回傳。

這是新的 provider／解碼停點證據，不是原查詢到 UI 的連續成功。原 query result-vector 與 DIR/provider object 的建立／連接仍未執行。

## 實際來源與有界讀取

- Candidate：`staging/navigation-new-street-v2-4k-offline-prototype-v2/new-street-v2-original4k-experiment.img.disabled`，132,173,824 bytes，繼承 root 完整讀回 SHA-256 `26a47f00fc84de49cf107df5b50504ff62849cb61d384e2d97b236aca400b8f9`；本輪不重算整檔雜湊。
- 新 MAIN 原檔讀取共 65,536 bytes／16 pages；保存的原始頁面雜湊與三次 capture receipts 相符。另使用前一個封存 scope 的保存頁面，沒有重新讀 MAIN 或執行舊 cases/main。
- 新 IMG 只開一次，非 buffered，總實際讀取 76,129 bytes，包含真 FAT metadata、MDR header／mapordinal1、GMP／TRE／LBL public headers、level table、兩筆 packed spans 及兩筆 label windows。上限 131,072 bytes。
- `actual-source-windows.json` 保留實際 hex、SHA、FAT mapping、metadata 與原讀取 log。後續 guest 只用此保存的 bytes；沒有再次開 IMG。
- 原 IMG、MAIN 的 stat 不變，所有 handles 已關閉。未接觸 device、shared report、canonical、sealed sources 或可安裝包。

## 真實原始指令鏈

新案從原 `0x044B153A` 公共 MDR label consumer 開始，參數為 explicit DIR fixture、ID、output buffer、192 bytes；DIR `+0x160` 指定 level 3／4。這不是已證明的原 query-vector caller。

1. `0x044B10E4` 從實際未重新對齊的 packed span 解碼，越過舊 `0x0448F740` 停點。
2. `0x0448F740 → 0x00359038 → 0x001F7814` 從实际 MDR1 offset 772 讀 mapID `0x0053061A`（5,441,050）。native FS wrappers 自己處理 seek／position。
3. `0x001EE156 → 0x0032C2C2 → 0x0032BE40` 枚舉及查閱 registry。固定表 `0x01286BCC + slot*24`，head 指向 `{blockptr,next}`；block `+2` 是本函式使用的 signed count，descriptor 位於 block `+0x100 + index*80`，`+0x2C` 由本 getter 比對 mapID。
4. `0x001AF428` 比對 cached GMP object 的 mapID；真分支 `0x001AF4BA → 0x001BE518` 清除 object `+0xCC0/+0xCC4`，真實 return 0。不冒稱 cold GMP loader 或 Map admission 已執行。
5. label consumer 選 CP950 primary ref，再走 `0x001AFC7C(kind7) → 0x001AFB3E → ARM 0x002BF5F4 → 0x044C170E(kind5) → 0x044C0E9A`。
6. native LBL function 自己計算 `label_start + (ref << shift)`，經原 seek/map wrappers 從實際 GMP windows 讀取、處理 CP950 byte-copy，再進入 `0x044BFF18` 後處理。

兩個新案分別是 street ID 48,312／ref 475,679，以及 house ID 3,781,595／ref 2,967。原指令數為 3,671 與 3,607，沒有 guest invalid access。

house 案另保存原 `0x044B1550` 的實際 packed reader 回傳 `r0=0` 與 32-byte output。座標真實縮放到 `[288576768,1440102400]`（source raw24 `[1127253,5625400]` 各左移 8），不是 host 投影代替原回傳。actual TRE 最小 level 0、precision 24。

## Fixtures 與未證範圍

- Registry slot 0、linked block／一筆 descriptor 是**預初始化 fixture**，其 mapID 是實際 MDR1／TRE 值。不是本機或實機目前 registry，也不證明原 AP driver 應放 slot 0。
- GMP cached context、open-file pair、TRE/LBL 欄位為根據 actual public metadata 初始化的 fixture。沒有執行 cold provider／完整 header parser 或從原 caller 建立 object。
- OS mutex 邊界、152-byte temporary handle allocation／buffer lookup，以及已知兩參數 byte-zero API 是明示 fixtures。底層 FS read/map 僅提供實際 windows 的 bytes／可用長度；原 wrapper、位址與位元運算執行原始指令。
- 沒有 hook metadata／registry selector／LBL getter 的成功回傳。第一個未知文字 helper 及 missing-registry cleanup callee 都不代填回傳。
- 原查詢得到 `[3,48312,0] → [2,74,0xFFFFFFFF] → [1,8,0xFFFFFFFF]` 是前一 sealed materializer 的 frozen endpoint，本輪沒有重跑 SQL、prefix 或 materializer。從該 vector 到 DIR/provider object 的真實 consumer 仍未知。
- 完整 getter return、uninterrupted query、native SQLite、native UI、device acceptance、installable、全台完成均為 false。
- OSM node／source/raw24 district gates 沿既有 sealed source evidence。此 scope 不重新核驗歷史 alias／368 號或 2026 道路名稱連續性；root 後續官方 2016 路名公告是另一份證據，不改舊 held scope。

## 實際失敗與下一個最小入口

首次 source capture runner 真正 EXIT 1，因 missing registry 的已 open cached object 選擇 native status1 branch，繼續呼叫未保存的 cleanup `0x002CE94C`，出現 unmapped fetch。另一次只用保存 windows 的 observer 保存 1,664 条真實指令及故障地址；沒有把 native 函式完整 return1 寫成已驗證。這是有用的失敗 frontier。

接續的 street／house 路徑不重開 IMG。street 真 guest terminal `2e08a4` EXIT 0（停點被有界 harness 正確記錄）；house continuation terminal `adec19` EXIT 0，`all_assigned_checks_passed=true`。一個 SyntaxError 的 prep attempt `67db60` 在 import 前停止，沒有 source IMG／MAIN 讀取或 guest 執行；原 receipts 明示。

下一個小 scope 可捕獲原 `0x0049A710` helper 與必要 dependencies，核對 `r0=實際 CP950 output pointer, r1=0x1D`，再跨越原 `0x044BFF32`。先不要假設這是普通 strchr 或 stub 成功。本輪在 64 KiB code cap 停止，不再擴讀。cleanup `0x002CE94C` 可另作 missing-registry failure lifecycle 的最小入口。

## 檔案

- `proof.json`：scope、bytes/stat、real entry visits、success／held flags 與 fixtures。
- `actual-source-windows.json`：唯一 actual IMG pass 保存的 bytes／FAT mapping。
- `fixture-development-getter-attempt.json`：已成功取得 street 文字並停未知 helper 的真實 case，名稱保留，不重新執行或覆寫。
- `actual-house-getter-frontier.json`：剩餘 house 真實 case、packed return／coords observations。
- `fixture-development-guard-attempt.json`：missing registry 原始 cleanup fetch failure。
- `probe_actual_provider_getter.py`：原 source capture runner／Guest；其首次未完成的 main 保留作 actual run provenance，勿把該 main 當成功 suite 重跑。
- `continue_actual_house_getter.py`：只執行尚未做過的 house case並綜合保存結果，一次性 guard。
- `actual-execution-receipts.json`、`bounded-static-review.json`、`sealed-files.json`：各 terminal／exit、無新 CPU 的靜態 evidence核對、封存清單。
