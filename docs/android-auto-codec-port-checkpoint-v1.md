# H.264 主機移植原型：2026-10-08

已完成獨立的公開 OpenH264 解碼器主機建置，將 runtime 配置、時鐘及執行緒相關依賴改為明確的呼叫端契約。原解碼器、既有整合與測試證據保持不變。這個成果仍未在 GarminOS 載入，也沒有手機或硬體輸出驗證。

## 實際證據

- 官方來源 commit：`1a0073f0322c8b74cbcb75ca1bb1c3d19d75538d`，原封裝 SHA-256 與選定來源逐檔核對。
- [建置紀錄](../staging/android-auto-h264-port-v1/build.json)：29 個未修改的上游 CPP，加上新平台 adapter 與原有 wrapper；只在新的 header 副本替換 `WelsTime`。
- 普通版 ELF64／AArch64 共享程式 447,952 bytes，實際沒有未解析 dynamic symbols 或 `DT_NEEDED`。ASan／UBSan 版另使用主機檢查程式庫。
- [測試證據](../evidence/android-auto-h264-port-host-v1.json)：76 項原介面案例與 36 項獨立平台控制，共 112 項。七組碼流的 61 個參考畫面與重新產生的 FFmpeg I420 結果逐 byte 相同。
- 86 個非終止案例正常結束後，adapter 與外部配置紀錄均為零；26 個刻意終止案例在隔離子程序中檢查 fatal 或 trap。
- 測試的最高 callback requested backing 為 12,340,820 bytes；這包含 adapter／上游配置前綴，但不含 caller canaries、配置器額外資料、context、workspace、其他元件或 RSS。

最終 build 工具結果為 `ffdab2 EXIT0`，測試結果為 `6ca601 EXIT0`；報告發布為 `0cfa0a EXIT0`。實際結果保存在新 staging 目錄。初次 hosted-header 編譯及數學函式連結失敗也有保留紀錄。

## 行為與限制

呼叫端提供配置／釋放、非倒退的微秒時鐘與非返回 fatal 回呼。單一序列化 binding 要求先銷毀 decoder，再解除綁定；這不提供執行緒鎖、非同步回呼靜止或安全卸載。配置器必須提供獨立、不重疊、對齊的可寫 backing。

CPU 數固定為 1。執行緒、事件、mutex、semaphore 與 sleep 呼叫會明確終止；日誌明確丟棄。原 wrapper 已拒絕 FMO，新測試也確認此拒絕；留下的 `log`／`ceil` 分支若意外被呼叫則終止，不提供完整 libm。沒有對這兩個 hidden 函式做直接動態測試。

配置失敗不是可恢復 OOM。公開上游 constructor 存在缺少 NULL 檢查的路徑，因此本原型選擇非返回 fatal，不以 longjmp 繼續部分建立的 decoder，也不聲稱失敗建構已完整清理。

仍需 Linux hosted C++ headers 及上游私人型別；GCC 14 的完整來源無法直接使用 `-ffreestanding` 編譯。零 runtime imports 不證明 ARM32／GarminOS ABI、元件載入、原機記憶體或即時性能。原機 USB host／VBUS／AOA、可達平台入口、顯示／觸控／音訊所有權與實際手機 session 仍未驗證。這些程式不可當成 Garmin 安裝包。

完整 Android Auto／Google Maps 目標維持 active／未完成。導航與麥克風研究維持使用者取消狀態；Pi 藍牙音樂 60 秒的歷史實機成功與 Android HFP APK 的主機建置證據保留。
