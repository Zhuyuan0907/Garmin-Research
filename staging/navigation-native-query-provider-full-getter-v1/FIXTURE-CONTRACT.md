# 精確 guest 初始化與邊界

此表只定義離線 guest scaffold，不代表 live registry／native cold initialization。

| 物件／欄位 | guest 值與依據 |
|---|---|
| DIR `0x09002000` | 前一 sealed actual IMG 的原 DIR parser 172-byte output；本輪 actual MDR header／record windows 與其身份相同 |
| DIR `+0x154` | MDR context `0x09000000`，手動建立 provider relation |
| DIR `+0x160` | 每案手動選 3／4，對應 street 48312／house 3781595；未驗真 query consumer 設定此值 |
| MDR context `+0x20/+0x24` | FILE `0x09001000`／mode0；file byte `+11=0x40` 表示 native FS wrappers 使用的 open flag；`+12=actual MDR bytes` |
| MDR context `+0x28` | codepage 950，明示 label-primary selection fixture |
| MDR context `+0x58/+0x5C/+0x64` | offset772／stride4／count1，actual MDR header 29／37／33 fields 導出 |
| MDR context `+0x3F4` | GMP object `0x09008000`；provider已開啟 fixture |
| MDR context `+0x3F8` | marker `0x09000600`，byte0=1，讓原 `0x35906E` 走已觀察的保留 cached-object 分支；不宣稱原 caller 如何建立此 marker |
| GMP `+0x20` | actual mapID `0x0053061A`，與 MDR1／TRE header 一致 |
| GMP `+0x34/+0x38` | GFILE `0x09001400`／mode0；同樣 explicit open-file flag 與 actual component size |
| GMP `+0x33C/+0x340` | label FS pair GFILE／mode0，原 LBL reader 實際讀取此 pair |
| GMP `+0x345/+0x346/+0x34C` | shift3／encoding10／codepage950，actual LBL header |
| GMP `+0x364/+0x368` | label_start3,812,824／label_size3,805,448，actual new GMP LBL header |
| GMP `+0x68` | min TRElevel0；GMP `+0x56`=24，actual public TRE level table 最小level的precision；不是 parser-init 的真實執行 |
| GMP `+0xCC0/+0xCC4` | 初始污染 `0xA5A5A5A5/0x5A5A5A5A`，原 cached selector 實際清為0／0 |
| `0xF004F0` | registry cachehandle=0，強制原 `0x1EE156` 使用真 enum／linked records 分支 |
| `0xF00114` | 99-byte slot types：slot0=3，其餘FF；使原 FE648(3)=0，FE648(47)=99。非 live AP slot 指派 |
| `0x01286BCC` | synthetic slot0 table，head=`0x09100000`，u16 `+0x0C`=1 |
| node `0x09100000` | word0=`0x09101000` block，word1=0；block signed u16 `+2`=1；descriptor block+0x100 的 `+0x2C`=actual mapID；其餘0 |
| current-thread global `0xF09090` | pointer `0x09000700`；thread+0x40 指回同 thread。原 `0x1C0600` 本身比較後 return0，不 hook thread helper |
| OUT `0x09003000` | output192-byte fixture；labels 真指令寫入 bytes |

底層邊界回呼：

- `0x3324B8`：只容許 FILE／count4／position772；把唯一 actual MDR1 source 4 bytes複製到原 destination、advance file position、返回底層 FS status0。前面的 `0x1F7814`／`0x1C8782` 都實際執行。
- `0x112194`：只容許 FILE/GFILE、mode0、精確 source window offset；返回 actual window readonly pointer及可用長度。每份 actual window放在頁尾，後方unmapped page；packed bytes沒有realign或假補padding。
- `0x3009A0/0x3008B0`：single-guest OS mutex邊界，沒有並行owner；不當作原OS真實執行。
- `0x38853C/0x388804/0x3887A2`：單次152-byte temporary allocator／handle buffer／free邊界。沒有實際原 allocator 或OOM語義驗證。
- `0x0448FD60`：已知兩參數 byte-zero API，僅zero有界guest buffer。未當作完整libc驗證。

`0x0448F740`、`0x359038`、`0x1EE156`、`0x32C2C2`、`0x32BE40`、`0x1AF428`、`0x1BE518`、`0x1AFC7C`、`0x1AFB3E`、`0x044C170E`、`0x044C0E9A` 均沒有 return hook。`0x0049A710` 後處理 helper 及 `0x002CE94C` cleanup 未呼叫成功、未代填回傳。
