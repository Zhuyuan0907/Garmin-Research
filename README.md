# Garmin nüvi 2565RT 研究紀錄

台灣版 Garmin nüvi 2565RT 導航機的逆向工程與改造研究存放處。研究目標是了解這台 2011 年代的導航機
（GarminOS／OS20 平台）還能加入哪些功能：更新圖資、藍牙音樂、在原機加入自製程式，以及評估 Android Auto。

> [!IMPORTANT]
> 這份 repo 只放**自己寫的程式、文件與小型研究證據**。原廠韌體、原廠圖資／語音、完整機台備份、
> 單機序號與配對紀錄都**沒有**上傳，原因見 [未上傳資料](docs/wiki/09-未上傳資料.md)。
> 這裡沒有可直接安裝到車機的原生程式套件。

## 機台

| 項目 | 內容 |
| --- | --- |
| 型號 | nüvi 2565RT（台灣） |
| HWID | 1352（不可套用 2585 或國外 HWID 1371 的結論） |
| 軟體版本 | 8.00 |
| 平台線索 | MAIN 內有 ST STA2064 驅動路徑，與 ARM1176 平台相符；實體 CPU／RAM 未拆讀 |
| 無線 | 只有藍牙（使用者確認沒有 Wi-Fi） |
| 研究主機 | Raspberry Pi 5（Debian、BlueZ、BlueALSA） |

## 目前成果一覽

| 項目 | 狀態 | 說明 |
| --- | --- | --- |
| 完整 USB 邏輯磁碟備份 | 完成 | 1,402 個檔案讀回驗證；備份本身不在 repo |
| 自訂地圖主題 Pi Contrast | 實機確認 | 使用者在一般模式選用並確認顯示正常 |
| 台灣 OSM 路網圖 | 實機可見 | 自行編譯、含路由與繁中標籤 |
| 門牌補充（原廠 Address Point 擴充 v2） | 有限實機通過 | 民權路 6／150／184 號搜尋、位置、路線正確；之後依使用者指示停止導航研究 |
| 門牌 v3（8K 容器） | 已退回 | 實機出現道路消失，已精確還原 |
| 藍牙音樂：Pi 中繼 | 實機成功 | 手機 A2DP → Pi → Garmin HFP 通話音訊，連續 60 秒有聲；8 kHz 單聲道 |
| 原機執行自製程式 | 實機確認 | 修改過的語音模組在 Aud Ver 顯示自訂標記（M7Q9、WFFF），並已還原成 2.10 |
| 原機直接 A2DP／原生播放器 | 未完成 | 在模擬器中跑通大量原廠核心／音訊流程，未安裝到車機 |
| Android HFP 播放 App | 已編譯、未實測 | 手機端自管來電，將本機音檔送到 Garmin 喇叭的實驗 |
| Android Auto | 主機端原型 | TLS／封包／控制／H.264／觸控／音訊核心在 Linux 主機通過測試；原機 USB host 與執行入口未證實 |
| Google Maps | 延後 | — |

詳細說明請看下方 Wiki。整體研究依里程碑估計約 37%，這是工程估計，不是功能完成率。

## Wiki

| 頁面 | 內容 |
| --- | --- |
| [首頁](docs/wiki/Home.md) | 研究背景、時間線、閱讀順序 |
| [01 機台與韌體](docs/wiki/01-機台與韌體.md) | 硬體識別、GCD 韌體解析、記憶體配置 |
| [02 備份與實機操作](docs/wiki/02-備份與實機操作.md) | 備份方式、安裝／還原流程與安全規則 |
| [03 導航圖資與門牌](docs/wiki/03-導航圖資與門牌.md) | OSM 圖、原廠門牌索引擴充、v2／v3 結果 |
| [04 藍牙音樂](docs/wiki/04-藍牙音樂.md) | Pi 中繼方法、原機 A2DP 研究、限制 |
| [05 原生程式與 GarminOS](docs/wiki/05-原生程式與GarminOS.md) | 載入器、OS20 核心、菜單、原生播放器原型 |
| [06 Android Auto](docs/wiki/06-Android-Auto.md) | 主機端接收器原型與上機缺口 |
| [07 Android HFP App](docs/wiki/07-Android-HFP-App.md) | 手機端實驗 App |
| [08 目錄與工具索引](docs/wiki/08-目錄與工具索引.md) | 資料夾結構、腳本命名規則、如何重現 |
| [09 未上傳資料](docs/wiki/09-未上傳資料.md) | 沒放進 repo 的檔案與原因 |

完整的逐輪研究日誌在 [docs/research-log.md](docs/research-log.md)（很長，已遮蔽單機識別資料）。

## 資料夾

```
android/    Android HFP 播放 App 原始碼
docs/       Wiki、研究日誌、查核文件
evidence/   研究證據（JSON），含韌體分析、實機觀察摘要
native/     自製原生程式（C／組語）：音訊、菜單、Android Auto 元件
reports/    研究報告網頁、App APK、測試圖
scripts/    分析、模擬、建置、安裝、發布用 Python 腳本
services/   報告網頁的 systemd 服務設定
sources/    第三方來源的下載紀錄與雜湊（不含原始檔）
staging/    各輪實驗的工作目錄（只保留小型文字檔）
```

## 注意事項

- 這是個人研究紀錄。改裝導航機可能讓機器無法開機或失去保固；文件中的實機操作都伴隨備份與精確還原步驟。
- Garmin、nüvi 為 Garmin Ltd. 的商標。本 repo 不包含 Garmin 的韌體、圖資或語音檔案。
- OpenStreetMap 資料採 ODbL 授權；第三方程式碼保留在各自資料夾的原始授權條款下。
- 整個 repo 尚未指定統一授權；`native/aa-framing` 等由 GPL 專案衍生的部分維持 GPL-3.0-or-later。
- 檔案中的 `REDACTED_PRIVATE_ID`、`REDACTED_HOSTNAME` 是上傳前遮蔽的單機序號與主機名稱，
  因此部分舊紀錄裡的雜湊值會和遮蔽後的檔案不一致。
