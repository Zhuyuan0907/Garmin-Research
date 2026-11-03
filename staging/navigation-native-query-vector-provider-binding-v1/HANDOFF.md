# 原 result-vector 與 provider 的靜態綁定

本有限 scope 找到真正的 result tuple caller、DIR handle consumer、DIR context store 和 selector callback 表。新 MAIN 讀取恰 32,768 bytes，IMG／DB／device 讀取均為 0；沒有執行 guest，也沒有重跑舊 query、prefix、frontier 或後處理 cases。這是原始 bytes 的靜態 ABI 證據，不是已閉合的 query→getter 或 UI。

## 已有據的 caller

- 原 query 外層 `0442250C` 在 `04422562` 以 selector 6 呼叫 `0448EE28 → 0032DB4C`，之後要求 reply object 的 handles `+18/+1C` 非零。`04422816` 把 SP+28 collection 傳給 collector `0442217E`；`04422842` 再把同一 collection 傳給 consumer `04421E5A`。
- Consumer `04421E8C..94` 從 input object 的 `+1C` handle，經原 `0448FD98 → 00388804` 取得 DIR pointer，保留在 SP+50。它沒有在這裡建立 DIR 或 MDR context。
- `04421F0A..1F1C` 把實際 12-byte tuple 的 level 放在第 5 個 stack argument，把 lowID 放 r3，DIR 放 r1，output descriptor 放 r2，outer context 放 r0，真正呼叫 `04421DB4`。
- `04421DB4` 直接把 tuple level 傳給 packed reader `044B10E4`。Reader 回來後才將 DIR pointer 加 `0x140`，然後用 `+14` 取得 MDR context，故實際位置是 **DIR+154**，不是 DIR+14。
- 真正 field producer 是 `044B209E`：原指令 `044B20C0: 4e61 / str r6,[r1,#14]`，其中 r1=DIR+140、r6=input MDRctx。另一個原 descriptor getter `044B28DE` 在 `044B296E` 呼叫此 parser，先清除 0x17C bytes local DIR，之後用 descriptor 的 level−2 及 lowID 呼叫 reader。這提供真 local constructor caller；尚未證明 query handle 的 allocation producer 是同一條路徑。
- 公共 sequential label consumer `044B153A` 使用 **DIR+160** 的 level；本 scope 尚未找到其 setter。直接 tuple level argument 的證據不等同於該 field 已初始化。

## 真 dispatch 與下一入口

`0032DB4C` 經 ARM veneer `00351770 → 044DC366` 進入原 engine。原 resolver `003C21A4 → 044DB2F8` 查閱 **008723A0 的 12-byte table**，完整有 52 rows（包含終止 selector30）。

- 裸 selector 6 沒有 exact row，resolver 在 sentinel index 51 停止。這本身 **不能判定 query 失敗**。
- 原 engine `044DC3A8` 呼叫 `0448E4E8 → 0032CCAA`，或測 input descriptor 的 `+18` 非零，設條件 flags `0x4000`。`0032CCAA` 是 kind 18/19 與 encoded key 的 native registry/count predicate，**不是字串 API**。其真正完整用途仍不命名。
- `044DC412..41C` 會依条件重新 resolve `selector|flags`；actual row **selector4006 / index46 / callback00173B51 / shared context872174**。因此下一個最小原函式入口是 **Thumb 00173B50**，不是臆造的 DIR constructor。
- callback 真 callsite `044DCB0E..16`：r3=SP3C 的原 table callback；r0=本段 R4 local；r1=SP8C 的 caller stack argument；r2=SP6C 的 input/options；`BLX r3`。R4 在此刻的完整結構與 callback 所需冷 context 仍須追原指令，不能直接填成 MDR/DIR。
- 另一個 8-byte size table `00B9E2E8` 的 selector6 size 是 `0x868`，與 callback table 的 12-byte stride 不同，不能混為 DIR bytes 或 record size。

## Frozen source 與限制

`abi-witnesses.json` 引用原 sealed `actual-native-materializer-case.json`：`04425726` genuine return0、vector count1、tuple chain `[3,48312,0] → [2,74,FFFFFFFF] → [1,8,FFFFFFFF]`。其原 SQL／預配置 vector buffers 是明示 fixtures；本輪沒有執行該 case。

舊 full getter 的 manual DIR+154/+160 fixture 與後來 reconstructed ABI 後處理 continuation 均保留原 scope，不改成 query constructor 成功。原 FS、冷 registry、MDR header object／handle allocation、callback173B50、DIR+160 setter、C++ string assignment helper4515AB4 尚未執行／閉合。

新 source cap 已用滿，在此停止。下一輪可先捕獲 `00173B50` 的最小原 callback／constructor ABI，確認是否填 reply handles+18/+1C 及呼叫真 `044B209E`，再決定是否執行一個 actual street48312 case。不得代填未知 dispatch return，也不得把 host field assignment 說成原 constructor。

本實例仍是原來源限定的新街 prototype。此 scope 不重新核驗歷史 alias／官方368門牌／2026連續性；root 新官方路名 checkpoint 是獨立證據。native SQLite、連續 query、native UI、physical acceptance、installable、全台更新完成與 App 完成皆為 false。

## 檔案與 actual receipts

`proof.json` 保留 scope／原 stat／8 個 actual MAIN reads／閉合來源 pins／已證與 held flags。`abi-witnesses.json` 保存 exact raw hex、逐指令 disassembly、原 callbacks table 及 frozen query chain。5 個 `capture-*-receipt.json` 與 `execution-receipts.json` 保存實際讀取及 terminal exits。`analyze_binding.py` 只做靜態核對，沒有 imports/執行舊 main/cases；`capture_binding_windows.py` 僅 explicit bounded windows，沒有整檔 hash。所有原檔 handles 已關閉，stat 不變。
