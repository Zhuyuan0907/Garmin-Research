# 07 Android HFP App

`android/garmin-hfp-player/`：手機端實驗 App，想用手機本身取代 Pi 中繼。

## 做法

1. 手機與 Garmin 在系統設定配對（只讀已配對裝置，不自動配對）。
2. App 先以公開 HEADSET profile 確認所選 Garmin 已連線。
3. 建立一通**自管的本機來電**（`garminmusic:0000`，不是電話號碼），由 Garmin 或 App 接聽。
4. 確認通話音訊確實走到所選 Garmin 的 SCO 輸出後，按「播放最多 10 秒」播放本機音檔。

沒有 `RECORD_AUDIO`、`CALL_PHONE`、`INTERNET` 權限，不撥真實電話，也不使用隱藏 API。

## 狀態

| 項目 | 結果 |
| --- | --- |
| 版本 | 第五版（versionCode 5），APK 45,459 bytes |
| 編譯 | API 35 typecheck、D8、AAPT2、min API 28、V3 簽章通過 |
| 主機端測試 | 40 項（播放閘門 18、播放器 lease 12、HFP 預檢 10） |
| 手機實測 | **尚未進行**；Pixel 是否把自管來電送到 Garmin 喇叭、能否省掉 Pi 都未知 |

APK 在 `reports/garmin-hfp-prototype.apk`。簽章私鑰沒有放進 repo，要重新建置須自行產生測試金鑰。

更多細節（路由檢查、逾時、Stop 行為）見 `android/garmin-hfp-player/README.md`。
