# 原 getter 後處理 continuation

`0x0049A710` 已由原始 26-byte Thumb 指令確認是 byte-character search：將 `r1` 截成低 8 bits，逐 byte 搜尋，匹配則回傳指標，到 NUL 仍不匹配則回傳 0。舊停點 `0x044BFF32 → 0x0448E868` 正在找 `0x1D`。本 scope 直接執行原 helper，沒有 stub／NOP／代填回傳。

新 scope 街名與門牌各只有一個有限 continuation。從先前真正尚未執行的 BLX `0x044BFF32` 繼續，原 byte search、formatter、LBL decoder、dispatcher 與公共 MDR getter 尾段都實際回傳 0；文字仍為「敦富六街」及「368號」。指令數分別為 407／329，terminal `437f78` EXIT 0，`all_assigned_checks_passed=true`。

**這是按原 ABI 重建 call frames 的 fixture 結果。舊 seal 沒有完整 CPU／RAM snapshot，本次不是恢復同一個 guest，也不宣稱 uninterrupted query／完整冷初始化／native UI。** 先前 3,671／3,607 條前段成功路徑沒有重跑，未執行任何先前 query／IMG／CPU suite。

## 實際入口與 return observations

| 觀察位址 | 結果 |
|---|---|
| `0x0049A710` | 實際入參 output pointer、`r1=29` |
| `0x0049A728` | 原 byte search 的 BX LR 前，兩案 `r0=0` |
| `0x044C12D4` | 原 label formatter 返回 decoder，`r0=0` |
| `0x044C1B4E` | 原 LBL decoder 返回 dispatcher，`r0=0` |
| `0x001AFBA0` | 原 dispatcher 返回 provider wrapper，`r0=0` |
| `0x044B1590` | 原 kind7/provider wrapper 返回公共 getter尾段，`r0=0` |
| guest RET | 原公共 getter的 pop／return 真正到達，`r0=0` |

現行 raw flags 是 `0x00800000`，兩筆 plain CP950 文字無 `0x1D`，也沒有其他 formatter 控制字元。原 formatter 跳過進階選項，逐 byte 掃描後返回 0，沒有修改文字。不能由這兩筆推論所有 flags／控制字元／Unicode formatter 都已驗證。

原下層 `0x001ACD62 → 0x001ACA1E → 0x001C8594` 也執行。GMP `+0x774` 的 format context 沿舊 fixture 保持零欄位；原 validity helper 自己回傳 0，因此原文字長度 helper 使用 byte-terminal scan fallback。不是代填文字長度或把這個 context 當成原完整文字 provider 已初始化。

## 有界來源與讀取

- 新 MAIN 原檔讀取 12,288 bytes：`0x0049A000`、`0x001AC000`、`0x002FC000`，上限 24,576 bytes。`0x002FC000` 是靜態下層候選頁，本案沒有用到其指令。
- 新 IMG／DB 讀取 0 bytes，沒有開 IMG 或 SQLite。只使用前一 sealed actual endpoint／小型 source windows。
- MAIN stat 不變。IMG 僅 stat pin，繼承 whole SHA `26a47f00fc84de49cf107df5b50504ff62849cb61d384e2d97b236aca400b8f9`，沒有重算整檔 hash 或改動 inode。
- 所有 handles 關閉，無 MAIN／IMG patch、device、report、canonical 或可安裝包變更。

## Call-frame fixture 的精確限制

原先只保存停點入參、output bytes、trace／訪問摘要，沒有完整 RAM snapshot。續行重建六個 saved frames，依原 push／sub／add／pop 的大小及 call-site return PC 設置；每案 696 bytes，完整 frame hex／SHA 保存在 `actual-continuation-*.json`。

| frame | SP |
|---|---|
| 公共 `0x044B153A` | `0x09012FB8` |
| kind7 `0x001AFC7C` | `0x09012F68` |
| provider `0x001AFB3E` | `0x09012F30` |
| kind5 `0x044C170E` | `0x09012E10` |
| decoder `0x044C0E9A` | `0x09012D88` |
| formatter `0x044BFF18` 的停點 | `0x09012D48` |

已知 output pointer／192-byte長度、raw flags、context／descriptor、mapordinal／label refs、原 return PCs 沿 frozen evidence 與原指令 ABI。未保存、與此尾段無關的 caller-preserved registers 明示為零 fixture，不能称原 RAM 完整重建。既有 152-byte allocation 的 handle／buffer 也從舊 event 重建，原 free call 到達相同明示 memory-free 邊界；這是本輪唯一 return fixture event。沒有 metadata／getter／未知文字 helper 的 return hook。

## 剩餘缺口

`native_public_getter_tail_return0_under_reconstructed_frame_fixture=true`；`same_original_guest_resumed=false`、`actual_uninterrupted_query_vector_to_MDR_to_full_getter=false`。下一個主要缺口是原 query result-vector consumer 如何建立／選取 DIR、MDR provider/context，以及 cold registry／GMP／format context 初始化，不需重跑這兩筆文字後處理。

Native SQLite、UI、實機接受、installable、全台完成仍 false。OSM source／區界結果沿既有 seal；本 scope 不新增官方門牌368、歷史 alias 或2026道路名稱連續性證據。

## Receipts／檔案

- `proof.json`：scope、pins、fixtures與真 return／held flags。
- `actual-continuation-48312.json`、`actual-continuation-3781595.json`：每案完整 reconstructed frame、原 return observations、指令數／trace hash。
- `initial-capture-receipt.json`、`additional-capture-receipt.json`：唯一新 MAIN reads。
- `prep-guard-failure-receipt.json`：`f3d719` EXIT 1；預備 byte-identity literal誤用同語義另一encoding，真原始 bytes保留，未執行 guest、無新 source reads。修正的是 harness expected literal，沒有修改原 code。
- `probe_postprocess_continuations.py`：有限一次 runner，既有case/proof時拒絕再執行。
- `execution-receipts.json`、`bounded-static-review.json`、`sealed-files.json`：actual run、無 CPU 重跑的 saved-evidence核對、封存。
