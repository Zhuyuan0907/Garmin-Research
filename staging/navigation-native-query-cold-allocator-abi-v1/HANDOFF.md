# 原冷 allocator 的 mutex ABI 與下一停點

本 scope 使用既有 sealed 300000／388000 小頁與原 kernel／heap 小型證據。**新 MAIN 0 bytes、IMG 0 bytes、五個 exact-byte witnesses、一個 logical constructor continuation**；沒有 warm fullimage、音樂 admission guest、callsite patch 或舊 suite 執行。

Actual **87238d／EXIT0**：原 generic mutex initializer `3008A0` 執行8條指令，原 constructor ABI continuation從 `38854A` 執行42條指令，真正越過 `3009A0` 並停在 **3881BC 首指令前**。handle仍0、DIR未建立、allocator／constructor未完整回傳。

## 原 mutex 的實際 ABI

`3009A0` 是 mixed Thumb／ARM。原 ARM MRS／MSR 暫時遮罩 IRQ I bit，讀 current-task word `F09090`，unowned mutex設定 `mutex+8=TCB`、`mutex+4=TCB+20`、`mutex+0=舊 owned-list head`，並將 `TCB+20` 寫成 mutex。原碼回傳0並恢復IRQ／mode bits。

本案例實際證明這些 owned-list writes；current TCB是明示 fixture `09100000`，其 owned-list初始為空，沒有 OS return hook。mutex 是原 `3008A0` 六個zero stores建立的24-byte generic instance。這不是實機 current task，也不是完整 heap constructor／scheduler。

同 owner 的 recursive branch及 competing owner 的 `3009EC→300D08` 沒有測試。Frontier中mutex仍被TCB持有；丟棄本地guest不等於原 unlock、task exit 或 quiescence成功。

## Heap所需來源與未初始化部分

`38853C` 使用原 workspace `03A7F170`、mutex `03A7F18C`。新 stop觀測真正 `3881BC` ABI：size17C、flags0、out=&cache+1C、r3=原 caller LR173B8D。

Core需要 workspace+18 的 nonnull metadata，L1 bitmap、+78 L2 table及 freeextent linked-node state。新case沒有供應這些資料，workspace+18仍NULL；因此停在core之前，不把零metadata稱為可用empty heap。

原 reset `388B24` 清96-byte workspace；原 bootstrap `388B6C` ABI為 primary `[base,length]` array/count、secondary array/count。下一輪若要接core，須綁定isolated extents/header/reserve、L1/L2、原 mutex init/tag及 native exit listener/current-task ownership。原 bootstrap在 count gate之前即讀primary descriptor，不能任意傳NULL array。不得 reset live／owned／warm heap或 hook38853C/388804供應handle。

已有 `native/os20-task-bridge/allocator-contract-v1.json` 描述32KiBprivate、64KiBpublic的software extents，並明示TCB與L1/L2是fixtures；此 scope只讀契約，沒有重放其guest或挪用warm heap。原task生命周期證據仍維持自己的controlled allocation／bookkeeping／wake限制。

## 有界continuation與失敗保留

不是同一個舊guest恢復。使用前一sealed frontier的observed registers及原push/frame ABI重建24-byte wrapper frame；未複製完整guest或warm RAM。opaque MDR context、原query cache／native SQLite／FS未建立。

首active run **950531／EXIT1** 已通過 next-core-entry檢查，但post-run錯誤地要求完整CPSR等於3F；原 Thumb return MOVS合法改變NZCV。該次trace/register未保存，此限制明示，原source與failure receipt保留。後續只改host guard，分別比較IRQ/mode control bits並在assertions之前寫actual journal；不改原指令、IRQ值或return。中間 **00f97e** 是 IndentationError，沒有guest/source evaluation。相同logical continuation得到上述87238d；原完整CPSR在actual journal保存，不能宣稱NZCV完全不變。

`actual-runtime-journal.json` 保存實際setup與continuation的原碼trace／CPSR／owner fields。`proof.json` 分開1logical case、2executed attempts、1syntax prep failure，未保存的第一個trace不冒稱精確instruction count。前scope的banked-SP preparation failure保持原sealed資料不變。

所有 source handles已關閉，原MAIN stat未變；沒重算MAIN／IMG全hash。沒有system block或绕過、裝置I/O、shared report／canonical／sealed來源變更。

下一入口為 `3881BC` 的有效heap metadata／extent／owner來源，或在新的隔離範圍先驗原 `388B6C` bootstrap。此scope停止，不在seal後加case。真正地址constructor／query→getter／native SQLite／UI／實機接受／完整台灣更新／App與installable皆false。
