# 06 Android Auto

> 優先順序在藍牙音樂與原機 App 之後。原機**沒有 Wi-Fi**，無線 Android Auto 不能只靠內建藍牙。

## 想法

Android Auto 是手機上的 App 把畫面投影到車機，車機只需要實作接收端，不需要移植 Android 系統。
有線模式下車機要當 USB host 並提供 5V 供電，經 AOA 協定讓手機切換成 accessory 模式。

## 主機端原型（Linux，已測試）

全部是自己寫的 freestanding C，在 Pi 上用本地 OpenSSL 當對端測試，沒有連過真手機：

| 模組 | 內容 |
| --- | --- |
| `native/aa-tls` | MbedTLS 3.6 記憶體 BIO 介接，呼叫端提供亂數與可信時間 |
| `native/aa-wire`、`native/aa-framing`、`native/aa-message` | 外層封包切分與明文訊息組裝 |
| `native/aa-receiver`、`native/aa-sender` | 接收佇列、單一傳送者與提交規則 |
| `native/aa-bootstrap` | 版本協商、TLS 握手、AUTH 完成後交接同一 TLS session |
| `native/aa-proto`、`native/aa-control` | nanopb 靜態 Protobuf、服務探索、通道開啟、焦點與媒體 ACK |
| `native/aa-video`、`native/aa-h264-port` | OpenH264 解碼（呼叫端配置器／時鐘），輸出 480×272 RGB565 |
| `native/aa-input`、`native/aa-audio` | 單指觸控與按鍵、48k 立體聲／16k 單聲道 PCM |
| `native/aa-interactive` | 以上全部在同一 TLS session 整合 |
| `native/aoa-prototype` | AOA 握手、介面選擇、bulk 傳輸核心 |

H.264 解碼與 FFmpeg 參考結果逐 byte 相同（7 組測試、61 個畫面）。測試圖：`reports/android-auto-decoded-pattern.png`。

## 上機缺口

1. **USB host／VBUS**：診斷頁顯示 USB Type-B；原廠程式有 USB 控制器的 device 模式路徑，沒有找到可用的 host 驅動或供電證據。
2. **執行入口**：需要常駐、可排程、能取得畫面／觸控／音訊的原生平台介面。
3. **效能**：主機的原型是 64 位元 Linux；ARM32、記憶體上限與即時解碼效能都未測。
4. **相容性**：參考的是較舊的 aasdk／OpenAuto 實作，沒有用目前的 Pixel／Android Auto 驗證。

## Google Maps

延後。Android Auto 成功前不研究；原機離線 Google Maps 不能用 OSM 圖代替。
