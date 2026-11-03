# 真 selector4006 callback 的 DIR constructor 與停點

本新有限 scope 確認 `00173B50` 是原地址 packed DIR 路徑。它真正呼叫 `044B209E` parser／`044B10E4` reader，並管理 reply cache 的 DIR handle。這不是因名稱相似而串接的一般 descriptor 假說。

新 MAIN 原檔讀取只有 **8,192 bytes**（173000、2E3000 各一頁）；IMG、PBF、DB、device 均讀取 0。共有五個 exact-byte witness，一個 logical constructor case。完整 constructor／query／UI 尚未成功。

## 真初始化與 pointer source

Callback 入口 `r0=reply, r1=output descriptor, r2=options`，先要求 `*(reply[0]+10)==12435687`。

- Cold：cache `+1C` handle=0，原 `38853C(size17C, flags0, out=&cache+1C)` 配置 handle，經原 `388804` 取得 DIR buffer；再呼叫 `35B4F4(buffer,17C)` 及 `2E3834(options+C,DIR)`。本輪只記 `35B4F4` 的真 call/arguments，未執行或新增其完整語義證據。
- `2E3834` 真 ARM veneer literal 指向 Thumb `044B209F`；parser 的原 `044B20C0` 寫 `DIR+154=input MDRctx`。這是原 parser store，未用人工填 DIR 取代。
- Cached：`173BB8` 直接把 `options+C` 寫入 DIR+154，重綁 context pointer。
- Options+C 的更早 source：原 `32DC78..7E` unwrap reply cache+18 handle，再加4，存 local options+C。Cold source `32DC6C..72 →32BB3C` 配置 `(options byte16*0x408)+4`，取得 block+4 並存 options+C。這只證明 context storage pointer 的原配置途徑，不能據此宣稱有效 MDR header／FS/provider 已初始化。

## DIR+160 新發現

原 setter 已找到：`173C3E..44` 把 selected descriptor 經真正 packed reader 輸出的 flags 低三位寫到 **DIR+160**。輸入 selected descriptor 的 level 是 `(byte9&3F)-2`，lowID 在 `+4`；因此儲存的是所選 record 的 child/next level，不能稱為原 query tuple 的 level3。

沒有 selected descriptor 或其第一 word 為零時，`173CE2..E6` 使用 fallback level1。以上均為本輪 exact-byte 靜態證據；沒有執行該 setter 或完整 child query。

## 唯一 logical 原指令案例

Actual terminal **b575b6／EXIT0**，原 Thumb `173B50` 開始，31 條真指令通過 magic guard/cold branch並真正進入 `38853C`。Observed allocation ABI：`r0=0x17C, r1=0, r2=&cache+1C`。

案例在 **38854A、原 BL3009A0 mutex 之前** 停止。未知 mutex／allocator core `3881BC` 沒有執行或假回傳，handle 維持0，DIR buffer 未配置，parser／DIR+154/+160 stores 均未執行。這是實際 frontier receipt，不是完整 native constructor success。

Fixtures 為 guard-passing reply/cache/options/output；cache 的 nativeStreetID48312 來自前一 sealed query chain，mapID／kind／level byte 是明示 fixture annotation，並非原 query 建立這個 cache。options+C 是 opaque zero RAM pointer，不能稱為真 MDR context；此有限案例未讀取該指標內容。沒有 FS、SQL、冷 heap／registry 或 unknown dispatch callback fixture成功回傳。

初次 active preparation **7da119／EXIT1** 把 SP 寫在 CPSR mode 切換之前，banked SP 變為0，原 guest 發生 `UC_ERR_WRITE_UNMAPPED`。原失敗 source 與 receipt 保留，未保存該次指令 trace，不能宣稱失敗指令總數。零 guest 指令的準備觀察 **759eb2** 確認此 banked-SP fixture 問題。相同 logical case 調整為先設 CPSR 再設 SP，得到上述有界原 allocator frontier；未重跑任何 closed case。

## 下一最小入口與旗標

若接續冷 handle 建立，先核實原 `003009A0` mutex/context ABI 與 `003881BC` allocator core 的 heap／manager 初始化。不得直接 hook `38853C/388804` 供應成功 handle。`32BB3C` 的 context storage 必須另接有效 MDR header／provider／FS 證據；source buffer allocation 本身不是完整冷初始化。

`constructor-witnesses.json` 有五個 witness；`proof.json` 分開 static setter 與 actual execution。原 source stat/hash pins、capture receipts、fixtures、initial failure source、actual31指令 trace、execution receipts 均保存。所有原檔 handles 已關閉，原 stat 未變。此次 scope 結束，不加測試。

原查詢到 getter 的連續 guest、native SQLite、native UI、實機接受、安裝候選、全臺更新完成與 App 完成皆 false。此輪沒有重評歷史 alias／官方368門牌／2026道路名稱連續性，root 官方路名 checkpoint 是另一份證據，不改旧 held scope。
