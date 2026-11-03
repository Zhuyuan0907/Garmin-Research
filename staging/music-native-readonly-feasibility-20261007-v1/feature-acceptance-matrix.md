這是停止於 reader guard 的 partial 唯讀整理，不是完整獨立驗收。三次普通檔案讀取均在保留 snapshot 的自訂容量 guard 失敗，沒有重試 guest，也沒有建立完整來源 hash/stat journal。下列已觀察 compact 內容與既有 parent 確證分開列明。

| 使用者功能 | 已有離線證據 | 已有實機證據 | 尚缺／驗收狀態 |
|---|---|---|---|
| Pixel 7 Pro 直接配對並使用原機 A2DP Sink | endpoint compact checkpoint 記錄自製 provider、三個 SEP 容量及原 ready/media/disconnect/reconfigure 路徑；provider 不等 recovered／installed 原機註冊 API | 既有 Pi 轉 HFP 是另一條路徑；本 scope 沒有 direct A2DP 實機證據 | 真實 SEP／SDP activation、手機協商／封包與連線生命期未驗收 |
| AVDTP configure／START／suspend／disconnect／重連 | ready compact checkpoint 保留 modeled IRQ、initializer event fixture、session 與原 kernel 限定案例 | 無直接手機完整 lifecycle 實機證據 | 真實 radio context、取消、錯誤及來源切換待證 |
| SBC 解碼／格式轉換 | resident contract：4 SBC frames／1024 PCM bytes、guest-C commands、原 CURRENT／POST／WAIT；既有 converter 證據沿用 parent 確證 | 無原機直接手機 SBC→喇叭整鏈證據 | 解碼正確不能當 DAC／喇叭已播放 |
| copied media→typed FIFO | FIFO contract：tickets4/8/12/16；1024 decoded PCM、896 fixture-consumed PCM、ticket16 仍有128 bytes；full-return lease 有限定離線證據 | 無 | consumer 是 private controller／test RAM，原 mixer／硬體未由此案例證明 |
| 原 Source OS20 READY | 新 ready contract：initializer 完整返回、初始化旗標、controller0x400 POST 與 POST return 分開；原 CURRENT／POST／WAIT 真執行 | 無 | 舊 static contract 的 runtime_guest_executed=false 屬舊 scope；新 READY 成功仍非音訊實機 ready |
| Source→factory／reader→mixer | parent 確證前移 CONFIG grant 後進入原 selector／factory／mixer；admission9eb25d EXIT1 | 無 | 無完整 PCM／1792布局／held-lease journal及 seal；build-media-v2 未執行，不算通過 |
| backend 獨占與導航語音共存 | source／FIFO contract 保留 ownership witness−200 | 無 | 原 Composer／Audio 全 writer 排除、callback barrier／anchor generation 尚未證明 |
| Stop／restart／完整生命期 | resident STOP 保留同一 TCB；FIFO STOP 拒絕新 admission、保留部分 PCM並 pin storage；local stop 不等完整音訊停止 | 無 | STOP_DONE=false；held leases、native callback完整返回、排程／硬體 stop、safe reclaim／unload 均未完成 |
| 原生 App／音樂選單 | adapter 文件列明12 host controls、typed bindings／完整 cleanup-frame 設計；ARM artifact 非 loader package | 無 integrated App／選單驗收 | ownership_snapshot、session glue、publication／iteration／cleanup／stream admission call sites及合法 GUI launch 尚待整合；不執行或安裝 |
| VPM／修改碼接受性 | 既有 preserving package 限定離線證據沿用 parent 確證 | 使用者看到修改版 M7Q9；還原原語音後看到2.10 | marker 只證明該修改碼觀察；完整 music VPM／SIG、40 TTS介面功能與 App 接受性仍未知 |
| 原機直接手機音樂出聲 | 尚無完整鏈驗收 | Pi→HFP 的舊成功不能替代此功能 | App／direct phone／speaker／install／fullgoal 均 false |

下一個安全唯讀方向：只從已存 compact Source/FIFO/adapter contract 列出 ownership_snapshot 的 epoch／source record／TCB／generation／anchor／callback-barrier 必要證書，對照目前 software CONFIG grant 與原 all-writer ownership 的差別。保存精確 missing ABI 清單；不重試中止的 admission guest，不改 call-site、不編譯、不要求實機，也不繞過限制。
