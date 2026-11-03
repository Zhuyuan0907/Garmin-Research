# Query context 的內部名字與 key

這輪以五份原指令靜態 witness 判明：**2CDAAC context 前兩個名字是內部
component/file 名稱模式，沒有把「敦富六街」當成檔名。** 真實產生的名字、key
及 FS pair 尚未觀察；沒有新 guest 或 native frontend 成功宣稱。

`name-key-witnesses.json` 保存 exact bytes／literal／source hashes：

- W1：32C4BE 要求 key high8=80，以 low16 在 **01287A3C 的99槽**定位。
  每個 block 首 u16 為 count，結果是 `block+0C+28*relative_index`。
  這是 source record lookup，不能直接套 JAI0x3000BCB8／street48312／house3781595。
- W2：1F18CC 從該 record byte0 low7 取 numeric prefix，模板 literal
  **`:????????`**；r3 是原 key cursor 的值。record+6／byte1 控制 secondary 分支。
- W3：1EE324 literal **`%d%s`**，將 number／template 傳給3472D4；原 MDR parser
  接 **`.MDR`**。secondary caller 接 **`.SRT`** 後才交2CC3E0，不是2CC3E0自行接尾碼。
- W4：1C8682 按副檔名首字母 M／S 選 source record **+4／+6 u16**，再呼叫
  **2FBA70(outputpair, internalfilename, selected_u16)**。MDR pair=&ctx+20，
  SRT pair=&ctx+384；它們與 ctx+1C encoded key 分開。
- W5：只引用既有132,173,824 B新 IMG 的真 materializer tuple／refs：
  `[3,48312,0] → [2,74,FFFFFFFF] → [1,8,FFFFFFFF]`，street→house3781595，
  refs475679／2967，「敦富六街」／「368號」。未把這些資料反填 filename 或 key。

Symbolic primary 是 `decimal(recordbyte0&7F) + :???????? + .MDR`；這只是
literal 與原參數的靜態關係，不是 native formatter 執行結果。numeric prefix
更廣的含義仍未知，不能命名為實體磁碟、mapID、priority 或 address record ID。
record+4/+6 u16 也不能猜成 FAT block／offset／有效 handle。

最小下一缺口：**1F18F0→32C4BE** 之前的實際 registry block／28-byte record
producer與 key cursor，以及 **2FBA70** 的原 FS ownership/open-pair contract。
沒有 source record／FS 證據時，不能建立一個成功 context 代替它們。此 scope 不接
allocator／mutex／admission guest，也未執行任何未知 helper 或偽造返回。

新 MAIN **0 B**（上限16KiB；重用六個 sealed code pages）、IMG **0 B**、CPU
**0 cases**、witness **5**。`source-artifact-read-ledger.json` 保存每個 bounded
artifact 的 stat／hash／seal pin。達五份後停止；沒有 MAIN、IMG、裝置、報告、
canonical 或舊 seal 改寫，也未重跑舊 suites。

連續 query→getter／原 SQLite／UI／裝置接受／可安裝 App／全台仍未驗。
368地址、歷史 alias與2026名稱延續不因內部 ABI 分析變成已驗。
