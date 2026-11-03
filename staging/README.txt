Pi Contrast 地圖配色實驗

依實機 United Kingdom.kmtf 建立，保留原有欄位與日夜模式。
已新增到導航機並讀回核對 SHA-256；使用者已在一般模式選取，確認正常顯示。
安裝位置：導航機 Themes/Map/Pi_Contrast.kmtf。
主題位置：工具 > 設定 > 導航 > 汽車 > 地圖主題 > Pi Contrast。
還原：選回原主題，刪除新增的 Pi_Contrast.kmtf；原廠檔案不用改。
這只改地圖顏色，不會增加 Android Auto 或藍牙音樂功能。

藍牙喇叭播放（已實測成功）

Pi 已與 Garmin 配對，使用者確認模擬通話畫面與測試旋律都有出現。
需要 BlueALSA 的標準 org.bluealsa 服務，以 hfp-ag 啟動，並維持一般模式藍牙連線。

重播短旋律：
  python3 /root/garmin/scripts/test_hfp_call_audio.py --repeat 1 --call-sequence incoming --live-cind-test

播放其他檔案：
  python3 /root/garmin/scripts/test_hfp_call_audio.py --wav /path/to/audio.wav --repeat 1 --call-sequence incoming --live-cind-test

檔案必須是單聲道、8000 Hz、16-bit PCM WAV；不符合格式會在傳送通話狀態之前拒絕。
Pi 現已安裝 FFmpeg，可轉換 MP3 等音源：
  ffmpeg -i input.mp3 -ac 1 -ar 8000 -c:a pcm_s16le output.wav
也可直接用新播放器，自動轉檔並透過同一免持通道播放：
  python3 /root/garmin/scripts/garmin_music_player.py /path/to/music.mp3 --call-sequence incoming --live-cind-test
  python3 /root/garmin/scripts/garmin_music_player.py /path/to/music-folder --shuffle --volume 0.5 --call-sequence incoming --live-cind-test
多首歌曲以空格分開；整段最多一小時，達上限會截短。
只準備音訊而不播放：加上 --prepare-only。
程式在 Pi 上執行；Garmin 使用原生電話畫面，未安裝原機音樂 App。
追加重新配對後起初有電話畫面但無聲；暫時同步 CIND 通話查詢狀態後，使用者已確認模擬來電與旋律都有出現。
上述 --live-cind-test 是現場實驗方法：只暫時同步 Pi 音訊程序的查詢格式，結束時還原並由監護程序備援。需在 Garmin 接聽。
正式來源修正已編譯且通過協定測試，見 staging/bluealsa；目前尚未替換已連線的 daemon。新服務部署後不需此暫時實驗旗標。
原始成功紀錄未覆寫；本次成功見 evidence/audio-playback-20261002T175259349859Z.json。
可加 --call-sequence outgoing 測完整撥出狀態；incoming 需要在機台接聽模擬來電。

這條路徑使用 HFP/SCO/CVSD 通話音訊，音質有限；一般手機音樂 App 不會自動走此通道。
程式只送本機模擬通話指示，不撥打真實電話；完成、出錯或 Ctrl-C 時會清除指示。
可在 Garmin 電話畫面掛斷停止播放。測試只播放過短旋律，尚未驗證長時間穩定度。
配對或連線需要處理時，第一優先恢復連線，再做其他工作。

Android 手機音樂轉送（已實測）

Pixel 7 Pro 經 A2DP/SBC 送到 Pi（44.1 kHz 立體聲），再轉為 Garmin HFP（8 kHz 單聲道）。
使用者確認第二次 60 秒測試可以持續聽到手機音樂。
重播：
  python3 /root/garmin/scripts/garmin_phone_audio_bridge.py --max-seconds 300 --volume 0.7 --live-cind-test
在 Garmin 接聽模擬來電，並在 Pixel 播音樂。掛斷或 Ctrl+C 可停止；最長一次 3600 秒，未驗證長時間穩定度。
仍需 Pi 在中間轉送，Garmin 使用電話畫面；不是在導航機安裝 A2DP 音樂播放器。
Pi 手機接收服務 org.bluealsa.phone 與 Garmin 的標準 org.bluealsa 並存。
自訂服務只新增精確 D-Bus 目的地權限；未重啟 Garmin 音訊服務。
現在的代理只接受已指定的 Garmin 與 Pixel，手機只開放音訊類服務。

原生語音套件內部檔案系統研究（僅本機模擬）

scripts/analyze_native_vpm_filesystem.py 已區分外層 FAT 檔案及內層 DSKIMG 容器。
scripts/emulate_native_vpm_filesystem.py 讓原廠 remount、parser、目錄搜尋、
分配表換算與讀取指令處理備份中的三個原廠 VPM，再經五個原始檔案回呼
由原廠 DLL 載入器初始化。完整語音 RAM 與四十個跳板符合獨立控制組。
兩個記憶體中的 DLL／SIG 修改控制組仍可被內層讀取，但沒有執行修改指令；
四個錯誤標頭或資料不足控制組被拒絕。沒有保存修改 VPM 或安裝到導航機。
這仍使用底層 byte I/O、初始化 cache／heap／IRQ／mutex 等測試資料，
尚未證明高層語音選取與校驗政策接受自製套件，也未加入實機 App。
完整播放原型與這次檔案系統測試是分開的證據，尚未串成修改 VPM 的實際播放。
檢查點：scripts/check_native_vpm_checkpoint.py。

原廠高層語音資訊檢查（最新，仍為離線研究）

scripts/emulate_native_voice_metadata.py 已執行275590的原END標記、
字元轉換、標籤及數字解析。三個原廠包通過後，在同一個VM完成原DLL初始化，
完整語音RAM與40介面符合獨立控制組。七個記憶體控制中，舊checksum、
零SIG、零／缺少checksum tag通過這段檢查；缺少語言、錯誤／缺少END被拒絕。
未執行或保存修改包，不代表全系統接受安裝或不檢查簽章。

scripts/analyze_native_voice_enumeration.py 的10個靜態CFG確認外層還檢查類型與
平台條件。scripts/emulate_native_voice_predicate.py 的6例執行原條件分支，
storage key13A及cached config byte20的輸入是fixtures；不是實機HWID資料。
完整外層列舉、語音選取、實機App／藍牙直接音樂／UI仍未完成。
最新檢查點：scripts/check_native_voice_metadata_checkpoint.py（32項）。

報告網址：http://172.16.60.187:8765/，同一區網瀏覽即可。
此服務部署於目前REDACTED_HOSTNAME，不能當作以前連Garmin的Pi。
更新reports/nuvi2565RT.html後直接重新整理，不需重啟服務。
