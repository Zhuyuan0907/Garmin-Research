# Garmin HFP 本機音檔試驗

這是 **Android 手機端、尚未做實機驗證的原型**：使用者選取本機音檔，經自管 `ConnectionService` 建立一個本機來電，接聽後嘗試用 Garmin 的 HFP 通話輸出播放。沒有真實電話、網路或麥克風輸入；不是 Garmin 原生 App，也沒有替 Garmin 加入 A2DP。

原始碼使用 Java／Android platform API，min API 28、compile／target API 35，沒有 AndroidX 或其他 runtime 依賴。此編寫工作沒有安裝 SDK、執行 Gradle、安裝 APK、操作 Bluetooth 或播放音訊；編譯與封裝的實際結果由上層工作另行記錄。

## 操作流程（之後由使用者現場進行）

1. 在 Android 系統設定把手機與這台 Garmin 配對，並啟用其通話功能。
2. 開啟 App，以畫面按鈕授予 Bluetooth Connect／通知權限。只讀已配對裝置，不掃描、不自動配對。
3. 選本機 `audio/*` 文件與**這台 Garmin**；Android 文件選擇器要求 `EXTRA_LOCAL_ONLY`。畫面只保存持久讀取授權；按播放後，既有背景 player job 才查文件 flags 並拒絕 virtual document，然後開啟音檔。原型信任文件供應者遵守 local-only 要求，App 本身沒有 INTERNET 權限。
4. 在可見畫面按「建立本機來電試驗」。先註冊 self-managed PhoneAccount、啟動 phoneCall 前景通知，再非同步取得 HEADSET profile proxy。在背景做一次所選裝置的連線快照、關閉 proxy；確認 permission／bond／選定身分與期限後，才 `addNewIncomingCall()`。只有已配對仍不足以建立來電；App 不自動配對或連線。地址為 `garminmusic:0000`，沒有 tel URI／outgoing call 路徑；API31以上明確申請系統通話介面可見性，實際可見性尚未驗證。
5. 從 Garmin 接聽，或在 App／來電通知按接聽。只有 `onAnswer()`／`onAnswer(int)` 後才 `setActive()`；接聽不自動播放。
6. 等待「READY」後明確按「播放最多 10 秒」。播放器先音量 0 開始，實際 SCO 輸出核對通過後才設音量 0.5。播放期限包括最長 2 秒靜音核對；最多一次播放，完成即結束來電。
7. App 與前景通知皆有 Stop；Activity 關閉後仍由前景服務維持有限期限。掛斷、拒接、hold、失去 Telecom／audio focus、route loss、媒體錯誤或逾時都釋放播放器、斷開 Connection 並移除通知。服務不自動重新啟動。

## Route 與权限邊界

- API 28–33 對使用者選定的 `BluetoothDevice` 呼叫 `requestBluetoothAudio()`，並要求 `CallAudioState` 的實際 route 為 Bluetooth、active device 與所選已配對裝置相同。官方明示請求可能被系統改送其他 Bluetooth，因此請求成功本身不啟用播放。
- API 34+ 只使用 `onAvailableCallEndpointsChanged()` 提供的 Bluetooth CallEndpoint，以 `requestCallEndpointChange()` 請求，核對 `onCallEndpointChanged()` 與 current endpoint 的 identifier。CallEndpoint 沒有公開 Bluetooth MAC；因此所選 bonded device 的精確名稱必須在全部 bonded devices 與 available Bluetooth endpoints 中各出現一次。缺少、別名不同、改名、重名或 endpoint 被替換均拒絕，不猜任意 Bluetooth。
- 兩條路都再核對 MediaPlayer 的實際 `getRoutedDevice()`：必須為 `TYPE_BLUETOOTH_SCO`，且 address 等於所選裝置的 runtime 私密 Bluetooth address。空 address、不同輸出、不唯一的 SCO 輸出都拒絕。播放器 specific preferred-device 只是補強；不將它當作實際 route 證明。
- 公開 `AudioDeviceInfo.getAddress()` 只定義裝置特定、非 null 字串，沒有保證每台手機的 SCO 都提供完整 MAC。第四版只記 SCO 輸出數／空位址數／選定裝置匹配數，不記位址或名称；若身分無法確認，仍拒絕播放。Android15固定三份來源的有限分析見 `evidence/android-sco-route-identity-review.json`，未證明 Pixel 的實際位址格式或權限匿名化管線。
- 沒有 `AudioManager.startBluetoothSco()`、`setCommunicationDevice()`、手動 communication mode、root 或隱藏 API。不嘗試 fallback 至手機 speaker 或其他 Bluetooth。
- Android 公開 API 在切換 route 與通知 callback 之間存在空隙；即使加上 100 ms 監視，也**不能保證突發硬體換路由完全零洩音**。API 35 的單一 `getRoutedDevice()` 也不能證明不存在廠商同時輸出。此處是受限現場試驗，未達可依賴的播放隔離保證。
- 前景類型只有 `phoneCall`，公開宣告 `MANAGE_OWN_CALLS`／`FOREGROUND_SERVICE_PHONE_CALL`。沒有 `RECORD_AUDIO`、`CALL_PHONE`、`INTERNET`、microphone FGS 或 full-screen notification 權限。
- API 31+ 使用 `Notification.CallStyle`。Android 13 的通知權限豁免只用於此已宣告 MANAGE_OWN_CALLS、實作 ConnectionService、註冊 self-managed PhoneAccount 的 CallStyle。普通通知不能套用此豁免。被封鎖的通知 channel 或系統 foreground／Telecom 權限拒絕會顯示事件錯誤並停止，不追加錄音權限。

## Source 與時間限制

第五版的 `HfpPreflightLease` 由 production `HfpPreflight` 實際使用。全 process 最多一個未回收的 profile request；在 foreground ready 後，公開 `getProfileProxy(HEADSET)` 的 ServiceListener 接受主 looper 回呼，連線快照與 `closeProfileProxy()` 則在單一可重用背景 worker 執行。快照同時要求 `getConnectionState(selected) == STATE_CONNECTED` 與 `getConnectedDevices()` 恰有一個相同 selected device，沒有增加週期性的 HFP Binder 查詢。

檢查期限為 8 秒，第一個連線查詢起算的快照最多保存 2 秒；建立 incoming 前再核對期限。這只是建立本機來電前的有限觀察，不保證之後持續 HFP 連線、SCO route 或喇叭聲音。其他 endpoint 與精確 SCO MAC 檢查、手動 Play、最多 10 秒播放與背景文件工作 lease 全部保留。兩次平台查詢不是原子快照，普通 Binder／Android 排程仍可能阻塞；期限只在執行檢查的程式獲得執行時拒絕晚結果，不是硬時間或 UI 不阻塞保證。

Stop／逾時先作廢該 session 的 admission，不等待平台 API 或釋放操作。公開 API 未提供取消尚未回呼的 proxy request；若永不回呼或查詢／close 永不返回，lease 保持忙碌，不能透過再次按 Start 累積 requests。晚 proxy 回呼會先清理、不能替舊 session 建立來電；close 拋錯也維持忙碌。意外收到第二個不同 proxy 時，立即作廢 admission、排入 close，並鎖住 process 的 retry；即使兩次 close 都返回，也不把這種未預期通知序列當成可再試的清理證據。同一 proxy 的重複回呼不重複 close。重開 Activity 不清除這項 process 層級限制，沒有用逾時假装資源已回收。已成功 close 後仍可能有平台晚回呼；API 未保證同步 callback quiescence，亦未在 Android 實測這些路徑。

`PlaybackGate.java` 是 production session 實際使用的 Android-free 狀態機，所有事件都核對隨機 session token，舊 session callback 不影響新試驗。接聽期限 60 秒、路由期限 20 秒、準備期限 20 秒；READY 等手動播放亦最多 60 秒。160 筆有界事件只記 API、call／route／player 狀態與錯誤類型，不 dump 裝置 MAC、電話簿、檔案 URI、endpoint identifier 或 exception message。

第二版將 document provider 開啟、FileDescriptor data source，以及 MediaPlayer 建立／準備／播放／實際路由查詢／音量／釋放，全移到同一背景 looper；主 looper 管理 Telecom 與播放規則。Stop 先原子作廢 player ticket，再排入背景清理，不等待 provider 或 release。所有背景回呼回到主 looper 後核對 session 與 player 身分，開音前再核對實際 SCO、期限與 ticket。

第四版補上此前仍留在 `MainActivity.onActivityResult()` 的 `COLUMN_FLAGS` provider 查詢：文件辨識、query、cursor 存取／close 都在上述同一 player job。取消或逾時的查詢結果在開啟音檔前再次核對 ticket；不新增選檔工作執行緒，也不在 Stop 等待 query 返回。此修正針對來源中的 provider 呼叫位置；普通系統 Binder 呼叫、實際介面反應與 Android 排程沒有硬性不阻塞保證。

整個 process 最多一個未回收的 player job；取消或逾時不等於资源已回收。provider 若永不返回，或 cursor／descriptor／MediaPlayer 清理失敗，新試驗會顯示忙碌並拒絕，避免重試累積工作。**不能強制中止已阻塞的 provider／平台 API，不保證立即清空硬體音訊，也不是系統停頓／凍結下的硬時間保證。** 主機 lease 控制與 Java typecheck 不驗證 Android 排程、實際 provider 或車機出聲。

主要檔案：`MainActivity`（文件／裝置／可見按鈕）、`CallForegroundService`（CallStyle／Stop）、`GarminConnectionService`／`GarminConnection`／`EndpointGarminConnection`（Telecom 與 route）、`TestSession`（唯一試驗、播放器與 cleanup）、`PlaybackGate`（播放門檻／期限）、`EventLog`（私密有界事件）。

## 建置與尚缺證據

Gradle 設定使用 AGP 8.7.3，需要 JDK 17、Gradle 8.9 與 Android API 35 環境；未附下載 wrapper。已有這些工具的環境可由此目錄執行 `gradle :app:assembleDebug`。不要把 Java typecheck 當成 Gradle／manifest packaging／installability 驗證。

尚未驗證 Pixel 7 Pro 的 Android/OEM Telecom 是否允許此不用 microphone 的本機 call、是否向 Garmin 發出 HFP 來電及接聽／掛斷 callback、endpoint 名稱與 SCO address 是否可唯一核對、VOICE_COMMUNICATION MediaPlayer 是否進入 HFP，以及 Garmin 喇叭是否可聽。也未測 real call 共存、route-switch callback 空隙、Stop／app task 關閉／權限撤回或 provider 阻塞。任何實機聲音測試仍由使用者在方便時明確發起。

## 官方 API 依據

- [ConnectionService self-managed lifecycle](https://developer.android.com/reference/android/telecom/ConnectionService)
- [Connection requestBluetoothAudio / CallEndpoint change / answer callbacks](https://developer.android.com/reference/android/telecom/Connection)
- [CallEndpoint 的公開名稱、類型與 identifier](https://developer.android.com/reference/android/telecom/CallEndpoint)
- [CallAudioState 的 active Bluetooth device](https://developer.android.com/reference/android/telecom/CallAudioState)
- [MediaPlayer 實際 route 與 preferred-device 的限制](https://developer.android.com/reference/android/media/MediaPlayer)
- [Android 14 phoneCall foreground prerequisites](https://developer.android.com/about/versions/14/changes/fgs-types-required#phone-call)
- [Android 13 自管 CallStyle 通知豁免](https://developer.android.com/develop/ui/views/notifications/notification-permission#apps-configured-to-self-manage-phone-calls)
- [Bluetooth Connect runtime permission](https://developer.android.com/develop/connectivity/bluetooth/bt-permissions)
- [取得 HEADSET proxy：ServiceListener 在主 looper 回呼](https://developer.android.com/reference/android/bluetooth/BluetoothAdapter#getProfileProxy(android.content.Context,%20android.bluetooth.BluetoothProfile.ServiceListener,%20int))
- [不再使用時關閉 profile proxy](https://developer.android.com/reference/android/bluetooth/BluetoothAdapter#closeProfileProxy(int,%20android.bluetooth.BluetoothProfile))
- [HEADSET profile 的連線清單與選定裝置狀態](https://developer.android.com/reference/android/bluetooth/BluetoothHeadset)

## 本機實際建置紀錄（第四版，2026-10-07 台灣時間）

上層已完成API35 Java typecheck、D8 DEX、AAPT2 manifest封裝與API28以上V3簽章驗證；資源工具使用API34已存在的framework manifest資源，target仍35。production PlaybackGate的18項與PlayerLoadLease的12項主機案例通過。沒有跑Gradle或Android實機；手機安裝、通話、路由與Garmin喇叭仍未驗證。

APK大小37,267 bytes，SHA-256：`ee82bd3038358527aeb7216ac04de91c804de8c055f367afa6bb9636b07a39f4`。

[同一區網下載實驗APK](http://172.16.60.187:8765/garmin-hfp-prototype.apk)。完整建置紀錄位於`staging/android-hfp-prototype-apk-v4/proof.json`；簽章私鑰不包含在專案或下載檔。

第二版（versionCode 2，0.2-background-loader）曾重新編譯並簽章核對。上述30項是主機控制，包含受控的等待／取消／晚結果／單一owner案例；沒有執行Android provider或手機／Garmin測試。下載檔已更新；第一至三版建置紀錄保留作歷史對照。

第三版（versionCode 3，0.3-local-hfp-identity）：本機自管incoming handle統一為garminmusic:0000，保留custom scheme；API31以上以PhoneAccount公開extra明確請求支援自管通話的InCallService可見性。這不是電信撥號，也不證明Pixel實際visibility、Bluetooth service binding、最終HFP caller-ID bytes或出聲。固定AOSP15來源分析見evidence/android-aosp-hfp-interop.json。30項控制與API35編譯／簽章再次通過。

第四版（versionCode 4，0.4-background-document-check）：文件 metadata 查詢與 cursor 清理移到既有背景載入工作，另加只含計數的 SCO preflight 診斷。Gradle 的版本宣告與本機封裝版本同步。十份 Java 源碼經 API35 編譯、DEX、manifest 與 API28簽章核對，原有18項 gate／12項 lease 控制通過；未新增模仿實作的測試，也沒有跑 Android provider、安裝 App 或驗證喇叭。

第五版來源（versionCode 5，0.5-hfp-preflight）：新增上述 before-call HEADSET 檢查。原有18項 gate／12項 player lease 與新增10項 preflight lease 主機控制通過；新控制涵蓋選定連線的單次 admission、永無 callback／逾時仍保留 owner、Stop 後晚清理及跨 session、token／device／ticket 隔離、連線清單矛盾、permission 撤回、快照期限、受控 query 阻塞與取消、close 失敗的 process retry 鎖，以及第二個不同 proxy 清理尚未完成就到來時，第一份連線結果仍不得建 call／釋放 retry。主機執行記錄在 `staging/android-hfp-preflight-v5/host-policy-proof.json`，沒有執行 Android Bluetooth／Binder 或車機。這份來源修改尚未由此工作封裝 APK；上方第四版 APK 與歷史編譯記錄不因此變成第五版實機證據。


## 第五版實際建置與下載（2026-10-08 10:27 台灣時間）

官方 API35 Java 編譯、DEX、manifest版本及API28以上V3簽章驗證已通過；18項播放gate、12項音檔lease、10項HFP preflight主機控制共40項通過。首次ECJ編譯拒絕timeout lambda在blank final ticket初始化前引用；改成anonymous Runnable.run後重新建置通過，初次失敗保留於staging/android-hfp-prototype-apk-v5/build-attempts/。

目前下載為versionCode5／0.5-hfp-preflight，45,459 bytes，SHA-256 `aaae4986db4093b4514c2a9bb78648587b0777dbf048af2176973d8c399c79cc`。同一區網：[第五版實驗APK](http://172.16.60.187:8765/garmin-hfp-prototype.apk)。完整proof與實際工具回執位於staging/android-hfp-prototype-apk-v5/；先前版本APK與證據保留。

主機控制未執行Android proxy/Binder、手機安裝或車機聲音。before-call快照不是持續HFP／SCO連線保證；兩次profile查詢非原子操作，期限不能強制取消平台API，未來回呼quiescence仍未知。完整Garmin位址無法辨識仍拒絕播放；尚未證明省去Pi、直接A2DP、原機App或音質改善。
