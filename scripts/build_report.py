#!/usr/bin/env python3
"""Build a self-contained Traditional Chinese report from recorded findings."""
import datetime as dt
import html
import json
from pathlib import Path
from report_progress import build_progress, render_progress

ROOT = Path(__file__).resolve().parents[1]
BACKUP = ROOT / 'backups/20261002T154458Z'

SOURCES = [
    ('台灣 nüvi 2565RT 官方產品資料', 'https://www.garmin.com.tw/products/discontinued/nuvi2565RT/'),
    ('2555／2565T／2565RT 台灣使用手冊', 'https://download.garmin.com/tw/download/manuals/nuvi2555_2565T_2565RT_TW_0B.pdf'),
    ('官方更新版本清單', 'https://www.garmin.com.tw/_js/api_products_software/nuvi2565RT/'),
    ('2011 發表資料：2565RT 與 2585 的功能差異', 'https://www.garmin.com.tw/news/newscenter/news20110524/'),
    ('2565 系列最後地圖更新為 2017 第一季', 'https://www.garmin.com.tw/news/announcement/news-2017-jan-stop-update/'),
    ('台灣 RDS-TMC 於 2019/6/30 停止', 'https://www.garmin.com.tw/news/announcement/news-2019-aug-tmc-no-service/'),
    ('Garmin 自訂 POI／GPI 說明', 'https://www.garmin.com.tw/support/05/'),
    ('Android Auto 官方設定與相容車機需求', 'https://support.google.com/androidauto/answer/6348029?hl=en'),
    ('OpenAuto 專案原始說明', 'https://github.com/f1xpl/openauto'),
    ('aasdk 原生 Android Auto 接收端協定原始碼', 'https://github.com/f1xpl/aasdk'),
    ('Android USB 主機與配件角色', 'https://developer.android.com/develop/connectivity/usb'),
    ('Android Open Accessory 控制與資料傳輸', 'https://source.android.com/docs/core/interaction/accessories/aoa'),
    ('Android Open Accessory 2.0 版本與介面組合', 'https://source.android.com/docs/core/interaction/accessories/aoa2'),
    ('Android 官方核心配件介面原始碼（固定版本）', 'https://android.googlesource.com/kernel/common/+/d2101e7384ec08fe13cc9faf5eccaa6a84048ac9/drivers/usb/gadget/function/f_accessory.c'),
    ('Linux MUSB 原始暫存器定義（比對用）', 'https://raw.githubusercontent.com/torvalds/linux/v6.12/drivers/usb/musb/musb_regs.h'),
    ('Android Auto 無線連線需求', 'https://support.google.com/androidauto/answer/6348019?hl=en'),
    ('Crankshaft 2026 新架構討論', 'https://github.com/opencardev/crankshaft/discussions/798'),
    ('mkgmap 地圖編譯、SD 與字元編碼選項', 'https://www.mkgmap.org.uk/doc/options'),
    ('Geofabrik 台灣 OpenStreetMap 最新資料', 'https://download.geofabrik.de/asia/taiwan.html'),
    ('Garmin Linux 原始碼清單；nuvi25xx 檔案實際標示 2585', 'https://developer.garmin.com/open-source/linux/'),
    ('Raspberry Pi 顯示設定文件', 'https://www.raspberrypi.com/documentation/computers/config_txt.html'),
    ('BlueALSA 音訊服務與 HFP／SCO 使用方式', 'https://github.com/arkq/bluez-alsa'),
    ('Google 地圖官方離線使用說明', 'https://support.google.com/maps/answer/6291838?hl=zh-Hant'),
    ('Maps Go 不支援離線地圖', 'https://support.google.com/maps/answer/7566112?hl=en'),
    ('ST STA2064 原廠資料表', 'https://mm.digikey.com/Volume0/opasdata/d220001/medias/docus/581/STA2064.pdf'),
    ('GCD 格式研究原始文件', 'https://www.memotech.franken.de/FileFormats/Garmin_GCD_Format.pdf'),
    ('BIN 格式研究原始文件', 'https://www.memotech.franken.de/FileFormats/Garmin_BIN_Format.pdf'),
    ('BlueZ AVDTP 實作', 'https://github.com/bluez/bluez/blob/master/profiles/audio/avdtp.c'),
    ('BlueALSA v4.3.1 RFCOMM 原始碼', 'https://github.com/arkq/bluez-alsa/blob/v4.3.1/src/ba-rfcomm.c'),
    ('Android 原生程式 ABI；ARMv7 與 ARMv6 不相容', 'https://developer.android.com/ndk/guides/abis'),
    ('Arm ARM1176JZF-S 原廠技術手冊', 'https://documentation-service.arm.com/static/5e8e294efd977155116a6ca3'),
    ('GDR 10 官方規格與車架影像輸入', 'https://www.garmin.com.tw/products/discontinued/gdr10/'),
    ('Bluetooth SIG SDP 格式', 'https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-60/out/en/host/service-discovery-protocol--sdp--specification.html'),
    ('Bluetooth SIG AVDTP 1.0 原始規格', 'https://www.bluetooth.org/docman/handlers/DownloadDoc.ashx?doc_id=8241'),
    ('BlueZ SBC 2.1 上游來源封裝', 'https://www.kernel.org/pub/linux/bluetooth/sbc-2.1.tar.xz'),
    ('SciPy 官方多相 FIR 取樣轉換說明', 'https://docs.scipy.org/doc/scipy/reference/generated/scipy.signal.resample_poly.html'),
    ('SciPy 官方 Kaiser 濾波窗定義', 'https://docs.scipy.org/doc/scipy/reference/generated/scipy.signal.windows.kaiser.html'),
]

OPTIONS = [
    ('缺乏支持', '原機執行離線 Google Maps', '仍未達成。Google 的離線功能在 Google Maps 應用程式內運作；本台未找到 Android 執行環境或任意程式載入入口。Maps Go 官方明確不支援離線下載，靜態 Help HTML 也沒有證據可執行其所需的瀏覽器環境。原生 Garmin IMG 或外部裝置顯示是不同方案，不能當作此目標已完成。', 'Google 官方離線與 Maps Go 文件；精確 HWID 1352 韌體分析'),
    ('已確認', '保留離線導航／語音導引', '原生導航、路線模擬、步行等模式仍可使用；現存圖資版本標記 16.11／16.10，較舊。官方最後更新為 2017 第一季；原台灣 RDS-TMC 已停。', '實機 XML、官方手冊及公告'),
    ('可實驗', '更新 OSM 地圖', '可用 mkgmap 產生 IMG，先以導航機 SD 卡的 Garmin/gmapsupp.img 或實機宣告的 Map 資料夾測試。須驗證繁中顯示、搜尋、路線計算和圖資大小；保留原廠地圖及授權檔。SD 槽目前沒有可讀卡。', '實機宣告補充地圖介面；mkgmap 文件。此台新版 OSM 尚未實測'),
    ('已確認', '自訂收藏點、旅程與 POI', '可匯入 GPX 與 GPI；能整理旅遊景點、補給站、私人清單。POI 格式需正確；GPX 航線不保證每種第三方路線都會直接變成可導航行程。既有 GPX 可匯出做歷史行程分析。', 'GarminDevice.xml、實機 GPX／POI 目錄、官方手冊'),
    ('可實驗', '地圖日夜配色', '這台有 12 個 KMTF XML 主題；已準備 Pi Contrast，修改背景、水域、綠地、導航路線色彩。原格式及欄位保留、XML 檢查通過；尚未在實機畫面驗證。', '本機 staging/Themes/Map/Pi_Contrast.kmtf；evidence/prepared-theme.json'),
    ('已確認', '圖片、相簿、桌布、照片導航', '原生 JPG／JPEG 瀏覽與投影片；帶有定位資訊的照片可做照片導航。可製作 480×272 的說明圖、旅行卡片或照片；實際裁切方式需在螢幕確認。', '官方手冊、實機 Pictures 目錄'),
    ('已確認', '主畫面捷徑與原生工具', '台灣功能清單列出 Custom Main Menu；機內說明有新增、編輯捷徑。另有語音辨識、世界時間、計算機、單位換算、ecoRoute 與螢幕截圖。語音辨識用途是原生導航指令。', '實機 supported_features.html 與 Taiwanese 說明；官方手冊'),
    ('可實驗', '離線 HTML 資料卡', '機內 Help 為靜態 HTML，有連結和圖片。可研究以備份後的說明頁替換方式放旅行清單、保養手冊。新增頁面是否出現在選單、版面及編碼仍待驗證；沒有證據顯示能執行 JavaScript 或一般 App。', '實機 Help 目錄及 HTMLViewer 韌體字串'),
    ('研究中', '原機自製 App／手機直接播音樂', '已找到原生元件載入器：讀入 dllimg.bin、建立 ARM 函式跳板並呼叫檔案入口。原始指令的 7 項模擬通過，包含註冊並呼叫兩個合成函式；實機觸發條件、檔案位置與完整 API 尚未知。另已編譯無 Linux 執行環境依賴的 ARMv6 SBC 解碼原型，32 組格式／162 個音框與上游 PCM 完全一致，17 項資料與緩衝檢查通過。需繼續連接原生 UI、SDP Audio Sink、AVDTP 音訊端點與喇叭混音，尚未達成原機 App 或手機直接音樂播放。', 'evidence/firmware-analysis/native-component-loader.json；native-loader-emulation.json；native-sbc-emulation.json；avdtp-discover-emulation.json'),
    ('已確認', '藍牙免持電話／喇叭', '手冊及實機說明列出電話配對、通話、電話簿。一般模式才可做實際配對；隨身碟模式適合檔案操作。喇叭可用於導航及免持功能。', '台灣手冊、機內 Bluetooth 設定頁'),
    ('待實測', '從手機播放藍牙音樂', '未確認 A2DP Sink。韌體有 A2DP／AVRCP 字串，但可能只是共用藍牙堆疊；功能清單和手冊未列音樂播放器。需要正常開機後讀取 SDP 的 Audio Sink（0x110B）服務並實際送音訊。HFP 通話音訊與音樂串流不能混為一談。', '實機功能清單、匹配韌體字串；SDP 與播放未測'),
    ('待實測', '通話音訊傳送實驗', '若只有免持電話功能，可研究由外部設備扮演 HFP Audio Gateway，建立 SCO 通話音訊再送音源。可能受通話狀態、角色與編碼限制，品質也偏通話用途；目前沒有完成可用的實作。', 'HFP 功能與韌體字串；屬條件式研究路線'),
    ('可實驗', '自訂來電鈴聲候選', '實機有 .System/BTM/006-D2484-00.wav，格式為單聲道 16-bit PCM、44.1 kHz、約 0.93 秒；匹配韌體直接參照該檔名，並含播放來電鈴聲的程式訊息。可先用正常模式的來電測試確認用途，再研究替換短音效。目前未改此檔，也未確認任意長度音源可播放。', '實機 WAV 格式、精確韌體路徑與 ringtone 程式字串；屬有線索的推論'),
    ('缺乏支持', '直接安裝 Android Auto／Android', '本機匹配的官方韌體含 GarminOS、OS20 系統標記，不是可直接安裝 APK 的 Android 平台。Android Auto 需相容車機接收端與影像解碼、音訊、USB／網路及輸入整合。未找到這個台灣 HWID 1352 可用的移植或完整驅動。不能用有 CPU／USB 推論能直接安裝。', '匹配的 v8.00 GCD、Google 文件；診斷頁顯示 128MB，CPU／可用 heap 尚未量測'),
    ('待實測', '外接裝置跑 Google Maps／Android Auto，借用 Garmin 螢幕', '台灣手冊第 18 頁的車架有兩個不同介面：7 為圓形視訊輸入埠，8 為 GDR10 的 microUSB 連接埠。GDR10 官方資料也列車架可接倒車攝影機，不能把兩者混為 USB 影像協定。影像埠尺寸、腳位、NTSC／PAL、啟用方式仍待確認，再評估手機或 Pi 的影像轉換；目前只有導航機，沒有車架或線材。觸控回傳也未知。外部顯示方案尚未成立，Google Maps 也未在原機執行。', '精確台灣手冊 PDF 第 19 頁、GDR10 官方規格；本組合未驗證'),
    ('已確認', '行車記錄器／原生錄影回放', '需 GDR10、專用車架及原規格 2A 車用供電。手冊列 Motion JPEG AVI，最高 1280×720／24fps，另有 640×480／30fps。攝影機 SD 與導航機 SD 分開；目前導航機 USB 備份不涵蓋攝影機卡。', '精確台灣手冊；目前配件及攝影機卡未檢查'),
    ('待實測', '改成簡單影片／音源播放', '有行車記錄 AVI 回放，不等於有一般媒體播放器。可做符合攝影機格式的小測試檔，確認檔案索引、編碼與聲音是否可讀；若限制嚴格，不能只改副檔名。官方的 MP3／多媒體介紹屬 2585 系列。', '官方精確手冊與 2011 型號功能區分；未做轉檔播放'),
    ('可實驗', '語音、車輛圖示、文字資源', '實機有 VPM 語音、SRF 車輛圖示、語言與鍵盤資源，可用同型號相容檔替換或增加。自製 VPM／SRF 需要理解格式並測試；不能把 MP3 隨意改名為 VPM。', '實機檔案及 XML 支援方向'),
    ('待實測', '當成即時 USB GPS 接收器', '目前 USB 只曝光隨身碟介面，沒有序列埠或 ADB。既有 GPX 是已存軌跡，不是即時 NMEA。一般／維修模式是否支持可用 PVT 協定還需驗證。', '實際 USB descriptors、實機 XML'),
    ('可實驗', '拆機研究／保留螢幕喇叭再利用', '可先讀診斷頁、辨識韌體格式與板上晶片，再找 UART／JTAG／螢幕及觸控介面。精確 CPU、RAM、電壓、腳位、bootloader 恢復路徑目前未知，還沒有可執行的刷機方案。', '實機韌體 OS20／ARM 字串與 ARM 寄存器診斷；晶片未拆讀'),
]


def native_research_detail(research):
    findings = research.get('native_app_music', {}).get('static_findings', {})
    loader = findings.get('native_component_loader', {})
    component = findings.get('sbc_component_integration', {})
    pcm = findings.get('native_pcm_route', {})
    extension = findings.get('native_voice_extension', {})
    media = findings.get('native_media_pipeline', {})
    audio_format = findings.get('native_audio_format', {})
    converter = findings.get('pcm_converter_prototype', {})
    converted = findings.get('native_converted_media_pipeline', {})
    flow_control = findings.get('native_pcm_flow_control', {})
    native_task = findings.get('native_task_creation', {})
    task_lifecycle = findings.get('native_task_lifecycle', {})
    media_queue = findings.get('native_media_queue', {})
    media_worker = findings.get('native_media_worker', {})
    media_consumer = findings.get('native_media_consumer', {})
    audio_registration = findings.get('native_audio_registration', {})
    audio_messages = findings.get('native_audio_messages', {})
    pcm_initialization = findings.get('native_pcm_initialization', {})
    memory_audio = findings.get('native_memory_audio', {})
    memory_completion = findings.get('native_memory_completion', {})
    memory_notice = findings.get('native_memory_notice', {})
    memory_output = findings.get('native_memory_output', {})
    owned_media = findings.get('native_owned_media', {})
    owned_worker = findings.get('native_owned_worker', {})
    mixer_creation = findings.get('native_mixer_creation', {})
    mixer_worker = findings.get('native_mixer_worker', {})
    mixer_start = findings.get('native_mixer_start', {})
    mixer_capacity = findings.get('native_mixer_capacity', {})
    mixer_timer = findings.get('native_mixer_timer', {})
    output_driver = findings.get('native_output_driver_inventory', {})
    source_controller = findings.get('native_source_controller', {})
    source_control_flow = findings.get('native_source_control_flow', {})
    output_manager = findings.get('native_output_manager', {})
    output_stop = findings.get('native_output_stop', {})
    playback_control = findings.get('native_playback_control', {})
    playback_control_passed = playback_control.get('test_result') == 'passed'
    coordinator = findings.get('native_media_coordinator', {})
    coordinator_passed = coordinator.get('test_result') == 'passed'
    source_worker = findings.get('native_source_worker', {})
    source_worker_passed = source_worker.get('test_result') == 'passed'
    app_component = findings.get('native_app_component', {})
    app_component_passed = app_component.get('test_result') == 'passed'
    voice_mount = findings.get('native_voice_mount', {})
    acceptance = findings.get('native_voice_acceptance', {})
    loaded_playback = findings.get('native_loaded_playback', {})
    vpm_filesystem = findings.get('native_vpm_filesystem', {})
    voice_metadata = findings.get('native_voice_metadata', {})
    loaded_playback_passed = loaded_playback.get('test_result') == 'passed'
    output_manager_passed = output_manager.get('test_result') == 'passed'
    consumer_passed = media_consumer.get('test_result') == 'passed'
    worker_passed = media_worker.get('test_result') == 'passed'
    converted_passed = converted.get('test_result') == 'passed'
    parts = ['已找到原廠 TTS 元件載入器及 Voice/*.vpm 內的 DLLIMG.BIN。']
    if loader.get('original_module_bootstraps_emulated'):
        parts.append(f"{loader['original_module_bootstraps_emulated']} 個原廠元件在模擬器完成初始化，每個註冊 {loader['original_exports_registered_per_module']} 個 API。")
    if component and not converted_passed:
        parts.append(f"自製 ARMv6 SBC 解碼元件已經原始載入器與函式跳板執行，{component['configurations']} 組格式／{component['decoded_frames']} 個音框 PCM 與上游相同。")
    if pcm and not converted_passed:
        parts.append(f"另完成自製元件 → 原廠音訊緩衝 → 原廠讀取流程，{pcm['ring_cases']} 種起點／{pcm['decoded_and_routed_frames']} 個音框保持一致，{pcm['guard_cases']} 項拒絕與排程檢查通過。")
        parts.append('目前僅送入 16 kHz 單聲道，其他格式拒絕，尚未加入手機立體聲取樣轉換；OS 排程、優先權與通道操作仍由模擬器控制，未測實際喇叭或硬體時脈。')
    if audio_format:
        parts.append('原始音訊類型 17 的 factory／格式查詢已執行，會選取同一緩衝讀取函式，邏輯格式為單聲道 16-bit／16 kHz；這是原廠程式依據，尚未驗證實體 DAC 時脈。')
    if converter.get('test_result') == 'passed':
        parts.append(f"ARMv6 立體聲合併／FIR 降採樣原型的獨立驗證通過：16／32／44.1／48 kHz 共 {converter['configuration_count']} 組聲道／取樣率、{converter['signal_cases']} 項訊號及 {converter['guard_cases']} 項拒絕／邊界案例。音框切分不影響輸出，一秒 44.1 kHz 輸入產生 16,000 個輸出取樣；過大峰值會飽和而不溢位。")
        if not converted_passed:
            parts.append('此轉換器尚未完成 SBC／AVDTP／原廠緩衝的整合驗證。')
    if extension:
        parts.append(f"新增共存原型：{extension['original_voices']} 個語音元件各保留原有 40 個介面位址與跳板，原廠初始化後的記憶體保持相同；附加解碼器 {extension['decoded_frames']} 個音框與上游一致，另送入原廠音訊緩衝 {extension['decoded_and_routed_frames']} 個音框。只實際呼叫一個原廠查詢介面，未驗證完整語音合成。")
    if converted_passed:
        parts.append(f"最新共存元件已串接原廠 AVDTP 接收回呼 → SBC 解碼 → 立體聲合併／取樣轉換 → 原廠 PCM 緩衝及讀取。{converted['original_voices']} 個語音元件，每個 {converted['configuration_cases_each']} 組格式與 {converted['guard_cases_each']} 項錯誤／狀態案例通過；有效串流共 {converted['decoded_converted_and_routed_frames']} 個音框／{converted['accepted_valid_stream_packets']} 個封包，輸出與上游 SBC 解碼加獨立卷積相同。44.1／48 kHz 的封包切分與變動位元池不影響輸出，CRC 後會清除舊濾波狀態。原廠 40 個介面位址、跳板與原廠記憶體仍保持一致，輸出為 mono 16 kHz。端點／ring 是合成 RAM，OS 優先權／排程被攔截；沒有真實手機封包或實機聲音、即時性能、導航多工驗證。")
    elif media:
        parts.append(f"原廠 AVDTP 接收處理程式已呼叫附加的原生 RTP/SBC 回呼，再接入原廠音訊緩衝與讀取；{media['decoded_and_routed_frames']} 個音框／{media['accepted_rtp_packets']} 個封包的 PCM 相同。每個語音元件另通過 {media['guard_cases_each']} 個封包及狀態檢查。端點和串流狀態為合成 RAM，尚未註冊真實音訊端點或收到手機封包。")
    if flow_control.get('test_result') == 'passed':
        parts.append(f"原廠啟動要求與空間等待另有 {flow_control['startup_cases']}／{flow_control['reservation_cases']} 項離線案例通過：已初始化流程累積 10,240 bytes 才要求啟動，空間不足時會反覆等待，且 host 成功回傳不代表通道啟動成功。需研究獨立播放工作與有界封包佇列，避免阻塞藍牙回呼。OS／通道操作是受控 hook，冷初始化及真實排程、喇叭啟動仍未驗證；0.32 秒僅是邏輯格式的緩衝長度。")
    if task_lifecycle.get('test_result') == 'passed' and not worker_passed:
        parts.append(f"工作程序生命週期已有 {task_lifecycle['restore_cases']} 組恢復與 {task_lifecycle['self_exit_cases']} 組結束案例通過：原廠 ARM／Thumb 流程會恢復暫存器、堆疊及執行模式，再啟動自訂入口；返回後會解除工作清單、清理屬於該工作的等待紀錄，並恢復下一個工作的 context。結束通知的原廠註冊／移除與重複／缺失案例也已執行。通知發生時仍使用即將結束工作的堆疊，不能在通知中立即釋放堆疊或元件。建立時的配置／喚醒及 ready list 仍由模擬器控制，沒有真實 IRQ 排程或多工驗證；此結束路徑仍保留 wrapper 工作槽，回收、跨工作取消與元件卸載尚未完成。")
    elif native_task.get('test_result') == 'passed' and not worker_passed:
        parts.append(f"原生工作建立介面的 {native_task['creation_cases']} 組離線案例已通過，包含原廠 ARM／Thumb kernel context 建構與入口傳遞參數。配置／喚醒操作仍受控，入口是手動呼叫，沒有執行真實排程；取消、結束清理及實機 worker 仍未驗證。原建立函式沒有完整處理配置失敗與滿槽，須先完成啟動與回收策略。")
    if media_queue.get('test_result') == 'passed':
        detail = f"原生封包佇列已接入原廠接收回呼與既有解碼／轉換流程：{media_queue['voices']} 個語音元件的有效串流共 {media_queue['decoded_converted_and_routed_frames']} 個音框／{media_queue['accepted_stream_packets']} 個封包與參考 PCM 相同，另 {media_queue['guard_and_interleaving_cases']} 項邊界／交錯執行案例通過。回呼只複製封包，原始資料被覆寫後仍能正確處理；4 槽各 4,096 bytes，滿槽拒收，PCM 空間不足會先返回等待狀態。metadata 保護執行原廠 IRQ save／restore，交錯測試使用暫停的 ARM context 與另一個堆疊。停止會丟棄待處理封包，已選取的封包仍可能完成送音，不會立即靜音或清空原廠 PCM。"
        if not worker_passed:
            detail += '工作步驟仍由測試明確呼叫，尚未接 OS task／event loop；實機排程、原廠緩衝獨占權、導航多工、冷初始化與實際喇叭未驗證。'
        parts.append(detail)
    if worker_passed:
        detail = f"整合已由原廠事件／工作切換驅動原生解碼工作，{media_worker['voices']} 個語音元件的有效串流共 {media_worker['decoded_converted_and_routed_stream_frames']} 個音框／{media_worker['accepted_stream_packets']} 個封包與參考相同，另 {media_worker['additional_control_cases']} 項控制案例通過。編譯的回呼送出事件，真正的 kernel post／wait、優先序插入及 context save／restore 會切換到固定 16 KiB 堆疊的工作；入口只啟動一次，處理完後等待並恢復原工作，測試沒有直接呼叫 work step。已測多包共用一次喚醒、空間不足後明確通知重試、CRC 後恢復、高優先序搶先執行及原廠退出清理。初始 controller／idle 清單與藍牙端點／ring 為合成 RAM，建立 bookkeeping 與音訊 policy 仍受控；沒有實機 IRQ 時脈、真實導航多工或喇叭驗證。"
        if not consumer_passed:
            detail += '空間通知尚未接到真正 consumer，冷初始化、輸出 ring 獨占權及 interrupt-context post 仍待驗證。'
        detail += '退出後保留 stack／元件並拒絕直接重啟，安全回收及元件卸載未完成；此 ELF 尚未合併到 DLLIMG／VPM。'
        parts.append(detail)
    if consumer_passed:
        parts.append(f"最新讀取回呼原型使用原廠 factory 建立類型 17 的單一測試 instance，只替換讀取指標，再呼叫原廠 reader；factory、清零、讀取及事件通知均執行原指令。{media_consumer['voices']} 個語音元件共 {media_consumer['decoded_converted_stream_frames']} 音框／{media_consumer['accepted_stream_packets']} 封包及 {media_consumer['additional_control_cases']} 項控制通過。原廠 reader 真正推進 read index、釋放空間後，編譯回呼自動喚醒等待的解碼工作，不必再收到封包或由測試明確送容量通知；既有 PCM 與新解碼 PCM 均保持相同。另在受控 IRQ mode／stack 執行原廠全 ARM 的通知分支，保留 mode／mask 與 SB，低優先序工作在回到一般 context 後才處理。這不是實際 IRQ 進入／退出排程或高優先序中斷搶先測試。instance、最初 PCM 及 producer 初始化仍合成；尚未證明實機音訊註冊會選取此 instance，也未驗證 ring 獨占、導航多工、冷初始化、安全卸載及喇叭。")
    if audio_registration.get('test_result') == 'passed':
        parts.append(f"原廠音訊註冊路徑另已執行：來源表有 18 槽，註冊先建立來源佇列，來源選取再由 factory 寫入類型 17 的讀取介面，原廠 pull 函式經間接指標讀出 PCM 並複製到 mixer 緩衝。通道 5／8 共 {audio_registration['registered_routes']} 條路徑各讀出 768 bytes 且環形跨尾複製正確，讀取指標由原廠流程產生；另 {audio_registration['guard_cases']} 項失敗／通道檢查通過。compiled consumer 能接到此選出的 descriptor，但 {audio_registration['attachment_reselection_controls']} 組測試確認：原廠再次選取來源會重建整組方法、覆寫自訂 reader，consumer metadata 仍標記 installed，detach 正確偵測 provider 替換。單次 attach 無法維持回呼，該測試本身未處理重接或 callback lifetime。註冊配置失敗可留下空佇列、factory 不執行，而 host 仍成功；active 狀態來自受控 start hook，不代表實機故障時仍啟動。通道初始化／mapping、handle allocator、mutex、priority／訊息與 mixer RAM 仍合成或受控，pull 由測試明確呼叫；沒有真正導航多工、硬體排程、cold init 或實機播放。")
    if audio_messages.get('test_result') == 'passed':
        parts.append(f"後續訊息迴圈測試已執行原廠 18 通道 mapping／全域來源佇列初始化及來源啟動 primitive；初始化的目前來源為 65535，原啟動程式才設為 0。原廠 mixer 迴圈處理來源選取訊息 13，再以訊息 18 呼叫讀取介面。{audio_messages['message_routes']} 條通道路徑各經兩次選取與兩次讀取，{audio_messages['pcm_bytes_each']} bytes 與參考一致；新增 compiled refresh 在原 selector 返回後只恢復 reader，重複操作可接受，沒有 attach 或遇到其他 reader／format 會拒絕。測試在該邊界暫停，從另一堆疊明確呼叫 refresh，再由 Python 恢復 CPU context；尚未安裝真正的自動重接位置，也未證明實機 callback 已退出。訊息 16 是 seek／硬體重設要求，原流程會阻止繼續讀取；不把它當成一般暫停，硬體 reset actor 與訊息 17 完成流程未測。wait／訊息傳輸、handle、mutex、priority 及 mixer 啟動仍受控，尚未與解碼 worker 的容量通知接成同一測試，也未驗證冷 PCM 初始化、導航共存或實機播放。")
    if pcm_initialization.get('test_result') == 'passed':
        parts.append(f"原廠 producer 首次初始化另有 {pcm_initialization['cold_routes']} 條路徑及 {pcm_initialization['control_cases']} 項控制通過。起點使用精確 initialized data 的未初始化狀態，由原 host 設旗標並呼叫初始化，通道 5／8 各累積 10,240 bytes、註冊來源、原 factory／reader 讀回一致。原語音設定查找、ARM VFP 音量運算與模組呼叫 wrapper 已執行；模擬的語音設定／模組 export、環境查詢、busy／start、handle／mutex 等仍受控，VFP 權限亦明確提供，沒有實機冷開機或喇叭證明。共存測試揭露：不同 host 呼叫參數仍串接同一個全域 PCM ring，原廠清空會丟棄全部待播音訊；四次讀空會清除 producer 旗標，現有編譯佇列隨後持續 defer，須測試明確呼叫 host 才解除，尚未實作正式恢復協定。盤點原 factory 的 23 類型，1／2／5／18／19 共用零填讀取函式，已實際驗證為靜音；該輪對其餘來源只盤點介面。借用全域語音 ring 的路徑仍需共存／啟停規則，不能直接假設有獨占權。")
    if memory_audio.get('test_result') == 'passed':
        parts.append(f"後續已識別原廠記憶體音訊來源：kind10／11 與 flags12 經真正的註冊、來源佇列、factory 和 IO constructor 產生原廠回呼，再由原 pull 複製進 mixer；沒有提供假的 reader。{memory_audio['registered_routes']} 條路徑涵蓋單聲道 16 kHz 與立體聲 44.1 kHz，共 {memory_audio['pcm_bytes_total']} bytes 讀回相同，尾段及跨尾複製正確，沒有改動導航語音 context 或整個 ring。另 {memory_audio['control_cases']} 項控制驗證不同 instance、個別清理及槽位重用、與原冷初始化 TTS／清空的資料隔離；這是依序執行的模擬資料測試，尚未證明導航多工或喇叭共存。原廠函式保留 PCM 原始指標，呼叫者須保持資料有效；每種來源只有五槽，第六個 kind10 配置失敗後，原 constructor 使用 channel5 當清理 index，會清除相鄰 kind11 第一槽的使用標記。外層 selector 仍回傳成功，所以需要槽位保留與 prepared 狀態檢查。下一步追真正的來源完成／切換流程，製作持有音訊資料的有界 adapter，再接 SBC 解碼工作；現有編譯佇列仍用 TTS 輸出，未改成此來源。邏輯格式不證明硬體取樣率轉換，元件載入、A2DP 端點、UI 與實機音樂仍未達成。")
    if memory_completion.get('test_result') == 'passed':
        parts.append(f"原廠記憶體來源的生命週期另已測試：先排入 {memory_completion['queued_blocks']} 個來源節點，只有選取時才占用來源槽。原 mixer actor 以訊息 13 選取、18 讀取、15 停止、19 清理，再由原 list-remove 刪節點；共 {memory_completion['pcm_bytes']} bytes 相同，每段都重用 slot0，TTS 緩衝不變。讀取結束仍保持 prepared／來源槽及佇列節點，清理事件 22 與刪除事件 23 是不同階段。{memory_completion['control_cases']} 項控制确认：單獨刪節點後 reader 仍可讀原 PCM；事件 23 在節點釋放及 count 更新前就送出；來源切換後才送達的 22／23，翻譯 wrapper 會讀通道目前的識別欄位，而 25／26 使用通知內的舊欄位。測試使用不同的合成識別值來核對讀取位置，尚未確定這些值的實機用途，不能稱為已重現真實 App 通知錯置。來源 report mask6 只送出 22／23，翻譯後 main flags 為 2／8，兩者不同。原 notice dispatcher／wrappers 執行到 main event0x246，廣域 main dispatcher 是 capture stub，真正 client／App 接收端尚未追出。wait／傳輸、控制端堆疊、Python context restore 與 mixer activation 仍合成；未執行硬體啟動訊息 14、真正 drain 觸發或導航並行，也未實作自動切換及資料回收 adapter。下一步需確認通知接收及 callback 退出，不能只靠刪除／翻譯完成旗標回收音訊資料。")
    if memory_notice.get('test_result') == 'passed':
        parts.append(f"最新通知測試已撤掉上述 main capture stub，執行原廠派送器及前段子系統；在可選 context 查詢受控為 0／1 的 {memory_notice['main_query_cases']} 個案例中，事件 0x246 都走到預設返回位置。恢復完整查詢會進入原檔案系統，再因缺少模擬狀態停於 0x26A24C，不能推論實機故障或完全不存在 App 接收機制。新增 {memory_notice['flat_binary_bytes']}-byte ARMv6 原始通知捕捉元件，保留原廠派送參數及回傳值，4 槽各複製 20 bytes；接入兩段原記憶體來源、{memory_notice['pcm_bytes']} PCM bytes 及 {memory_notice['raw_notices_copied']} 個通知的測試，來源切換和原輸入被覆寫後仍保留原通知欄位，TTS 緩衝不變。另 {memory_notice['control_cases']} 項控制覆蓋佇列滿載／繞圈／篩選、無效參數／短輸出／未知事件、IRQ mask 保留，以及派送途中停止、拒絕重設和 epoch 溢位。這是明確呼叫的離線原型，沒有安裝自動 hook 或註冊原生 App；epoch 僅代表通知佇列設定，不能當作音訊來源世代。通知遺失、停止或收到刪除事件都不能證明 reader 已退出，仍須完成持有 PCM、來源槽保留及安全回收，再把解碼工作接到這條獨立來源。原 decoder／queue／worker 未改接；繼承的模擬器只執行既有 consumer 初始化，沒有呼叫其音訊流程。")
    if memory_output.get('test_result') == 'passed':
        parts.append(f"最新已加入 {memory_output['flat_binary_bytes']}-byte ARMv6 音訊持有原型，4 個固定緩衝各 4,096 bytes，先複製 PCM，再由原 kind10／flags12 註冊讀取；內部票號帶遞增世代，不傳給原廠作 App 識別。4 段共 {memory_output['pcm_bytes']} bytes 經原 mixer 的選取、讀取、停止、清理與節點移除，資料與參考相同，呼叫者輸入覆寫後仍可播放資料。原型在排入、EOF、只有停止、尚未移除節點或 reader 尚未返回時拒絕回收，完整序列完成才允許重用；舊票號不能操作重用的緩衝，TTS context／ring 不變。另 {memory_output['control_cases']} 組控制覆蓋參數／方法／世代、原節點配置失敗後重試、五個原 kind10 槽滿載時拒絕執行 constructor 並保留相鄰 kind11、移除尚未返回及 reader 進行中的情況。4,096-byte 案例也確認小型 mixer 未消耗時會在 1,792 bytes 暫停，再由測試明確推進消耗 index 才續讀，沒有真正 DMA 或容量喚醒。這些保護依賴單一 actor 與通道佇列獨占的呼叫契約，來源槽檢查只是入場檢查，不能防止其他 actor 同時配置；也未排除尚未進入的 callback。選取後包裝及生命週期呼叫仍由測試安排，沒有安裝自動 hook、安全卸載或把 SBC／FIR／解碼 worker 改接此輸出，實機導航共存與喇叭仍未驗證。")
    if owned_media.get('test_result') == 'passed':
        parts.append(f"最新獨立輸出整合已通過：原廠 AVDTP handler／lookup／回呼跳板把合成封包送到編譯佇列、SBC 解碼及 FIR 轉換，整個封包完成後才提交自有 PCM 緩衝，再由原 kind10 actor 讀取、停止、清理和移除。{owned_media['routes']} 條路徑涵蓋單聲道 16 kHz、立體聲 44.1／48 kHz，正常路徑共 {owned_media['decoded_frames']} 個音框，輸出與上游 SBC 加獨立卷積參考逐 byte 相同，導航語音 context／整個 ring 不變。四個 PCM 槽都持有時，第五包留在壓縮佇列，codec／FIR 狀態不前進；釋放後明確呼叫 step 才續處理。後段 CRC 失敗會丟棄整包暫存而不提交前段，下一包恢復正確；停止在解碼或私人複製途中也取消尚未提交的輸出。最大 15 音框封包的 3,840 PCM bytes 同樣相符。已提交 PCM 在 stop 後仍保留，重新 begin 會等其清空，這不是立即靜音功能。佇列 readiness 的衍生版本只替換輸出容量函式，既有版本不變；memory_output 標頭整理後整個 ELF 雜湊不變，原五組控制重跑通過。這輪仍由測試明確呼叫 step、來源 hook／release 和推進 mixer 消耗位置；decoder worker／kernel 容量喚醒只連結，尚未啟動驗證。藍牙端點仍是合成狀態，單 actor／通道獨占／配置順序也仍是呼叫契約，沒有實機 App、真正手機音樂、硬體喇叭或載入接受證據。")
    if owned_worker.get('test_result') == 'passed':
        parts.append(f"後續已啟動自持輸出的解碼工作，使用原廠 kernel 建立、事件、等待、優先權切換和自行結束流程；{owned_worker['routes']} 組測試涵蓋 16 kHz 單聲道、44.1／48 kHz 立體聲及較高優先權的搶先情況。第五包因四個 PCM 槽持有而等待，完整釋放第一個來源後，編譯的 release 會送出原廠容量事件，解碼工作在自己的堆疊恢復並處理第五包，沒有新的封包、測試通知或明確 step 呼叫。較低優先權要等控制工作讓出，較高優先權在 post 中恢復；輸出均與獨立參考相同。測試明確設定一般工作的 System mode，mixer 的受控等待另外使用 Thumb 返回跳板，沒有改寫真正 decoder wait。原廠自行結束已執行，但堆疊／TCB／元件保留，不代表可安全卸載。音源 actor 仍是訊息與 Python context fixture，post-selector／release／mixer 消耗位置也由測試安排，尚未完成全原生自動播放、硬體 DMA、實機音樂或導航多工。")
    if mixer_creation.get('test_result') == 'passed':
        parts.append(f"另執行原 mixer initializer，通道 {mixer_creation['channels']} 分別建立自己的 TCB、8,192-byte 堆疊與 240-byte 訊息儲存區；共用 0x2FA0DC 入口不代表只有一個音訊工作。測試停在原廠喚醒前，沒有實際運行這兩個 actor。原 kind10 配置函式在受控交錯中，第一個呼叫讀到空槽後暫停，第二個呼叫取得槽 0，第一個恢復也回傳槽 0。這是兩個堆疊與 Python context 恢復的控制例，不是真正 OS／IRQ 搶先或實機競態，也未排除外層鎖與排程保護。後續須查所有 caller 的保護與優先權，建立跨通道配置及來源存活協定，不能將現有空槽檢查當作保留機制。")
    if mixer_worker.get('test_result') == 'passed':
        parts.append(f"最新後續已讓原廠音訊工作與編譯解碼工作都在原 kernel 排程中運行。原 initializer 建立並喚醒 mixer，原 post/get/wait 處理 12-byte 訊息與 20 格、240-byte FIFO；三種來源格式共 {mixer_worker['decoded_frames']} 音框，{mixer_worker['native_message_count']} 筆訊息的順序、複製與索引繞回相同，音訊工作只進入一次，沒有使用 Python 恢復 actor context 或提供假訊息。原 actor 會自行排入下一筆 read18，正常路徑共 {mixer_worker['actor_self_posted_reads']} 次；每次實際讀取不超過受控 256-byte scratch，聚合輸出與 codec／獨立卷積參考相同。最大 15 音框的 3,840-byte 來源也通過：小型 mixer 先讀 1,792 bytes 後等待，測試明確前進消耗 index 並再送 read18，接著讀 1,792／256 bytes，沒有丟失或重讀。輸出目前為單聲道 16 kHz／16-bit。來源啟動／選取後掛接、15/19 清理、移除／release 仍是控制工作明確安排的邊界；硬體啟動、buffer/scratch、消耗位置、通用 mutex／優先權／外部音訊狀態提示仍有 fixture。只运行一個音訊通道，沒有跨通道獨占或完整自動 FIFO 生命週期／真實 DMA／導航多工證據。decoder 結束保留 stack／TCB／module，mixer 保持等待並保留原 allocation，尚不能安全卸載。")
    if mixer_start.get('test_result') == 'passed':
        parts.append(f"後續已撤掉上述測試代填的啟用旗標與 256-byte scratch，改由原廠開始播放訊息 14 取得 kind10 真正的 4,096-byte 區塊大小、呼叫配置／鎖定服務，再自行首次讀取；停止訊息 15 呼叫解鎖／釋放並清除指標。三種來源格式共 {mixer_start['decoded_frames']} 音框、{mixer_start['normal_pcm_bytes']} PCM bytes 與獨立參考相同，{mixer_start['normal_scratch_allocations_and_frees']} 次配置均由原 actor 完成對應釋放。輸出描述及 8,192-byte ring 仍是合成狀態，設定同為 16 kHz 以驗證不需重取樣的分支，這不是實體 DAC 格式或硬體啟動驗證。另 6,144-byte ring 控制例已讀入全部 3,840 bytes，卻因剩餘空間不足 4,096 bytes 而不再探測 EOF；明確推進消耗位置並送 read18 後才讀到 EOF。EOF 仍保留啟用中的 actor、來源、鎖定緩衝及節點，不能當作已播完或允許回收。來源選取後掛接、15／19／移除／release 邊界仍由控制工作安排，配置服務本身、真正容量事件、硬體排空與重取樣未驗證；原生 App、手機直接播放、跨通道協定及安全卸載仍待完成。")
    if mixer_capacity.get('test_result') == 'passed':
        parts.append('容量處理的後續控制已改用原 kernel 事件 0x200，控制工作不再送 read18：原 actor 自行查目前 TCB 對應通道，空間不足時不讀取，有空間後自行排入 read18 並探測到 EOF。消耗位置與兩次事件到達仍由測試明確提供，尚未驗證真正 timer 到期、DMA／IRQ 來源或硬體排空；這是容量事件的原生處理證據，不是完整自動播放。')
    if mixer_timer.get('test_result') == 'passed':
        parts.append(f"計時器的後續測試已執行原 descriptor 初始化、kernel 建立及 priority 1 的原 timer 工作，沿原 schedule／insert／tick／到期迴圈送出容量事件；控制工作不再直接送音訊 0x200 或 read18。{mixer_timer['routes']} 組、{mixer_timer['decoded_frames']} 音框／{mixer_timer['pcm_bytes']} PCM bytes 覆蓋未到期不喚醒、恰到期、空間不足重新排期、有空間後自行讀 EOF，以及 32 位元時間計數繞回，資料與參考相同。原計時器共向 audio actor 送 {mixer_timer['one_shot_expiries_total']} 筆 0x204 事件。模擬 tick 到達、獨立事件堆疊及 idle 後明確呼叫原 restore 的派送仍是 fixture，並非實體 IRQ entry／exit、時鐘或 DMA；消耗位置與來源啟停／清理邊界仍由測試安排。原 entry 也是 wait-loop head，flag 0 也可表示暫停的 compact wait context，因此以 saved PC 驗證每組只有一次 initial dispatch，沒有把迴圈誤當重啟。靜態 timer 堆疊與其他工作配置保留，仍不能安全卸載或聲稱完整自動播放。")
    if output_driver.get('test_result') == 'passed' and not output_manager_passed:
        parts.append('另由精確 ROM descriptor 與命令跳轉表辨識 output manager、上層來源控制工作及通知工作：原預設優先權分別為 22／92／93，訊息佇列分別為 56-byte×20、12-byte×15、20-byte×30。音訊驅動的結果訊息 11／12 送往上層來源控制工作，而非直接送每通道 mixer 的 START14。這是靜態盤點，沒有執行上述工作或讀取實機 RAM；不能推論所有實際優先權、跨通道獨占或 DAC 格式。下一步應串原上層來源要求與音訊驅動，確認實際配置／重取樣／播放完成／排空及自動來源切換，再整合原機 App 與真正藍牙端點。')
    if source_control_flow.get('test_result') == 'passed':
        parts.append('新的靜態控制表確認中央要求 11／12 共用回覆分支；混音器的 START14 來自另一個原廠配置回呼。停止要求 3 會發出驅動停止命令並進入狀態 5，完成要求 7 另有清理／切換流程，不能把停止要求返回當成資源已釋放。')
    if source_controller.get('test_result') == 'passed' and not output_manager_passed:
        parts.append(f"後續離線測試已實際建立原中央音源控制及通知工作，執行原公開同步啟動要求、原 mutex／condition 等待與回覆，再由原 mixer 選取／準備來源。{source_controller['routes']} 組、{source_controller['decoded_frames']} 音框／{source_controller['pcm_bytes']} PCM bytes 與獨立參考相同；16 kHz 單聲道使用 15 音框，44.1／48 kHz 立體聲各使用 2 音框控制，未證明最大立體聲封包或即時效能。原驅動要求順序為 1／0／4；另一個原配置回呼自行公布描述並送 START14，控制程式不再自行呼叫 queue-start／mixer-init 或直接排入 START14。原 11／12 結果回覆也實際經中央工作接收，沒有啟動音源。硬體驅動要求、仲裁、電源查詢／設定、配置完成回呼的觸發及輸出描述／消耗仍是模擬邊界；通知工作僅建立及等待，沒有 App 通知封包。掛接 reader、停止／清理／移除／release 仍由測試安排，真正排空、完整自動來源切換及跨通道所有權尚未完成；也沒有實機 App、SEP、手機或喇叭驗證。")
    if output_manager_passed and not playback_control_passed:
        parts.append(f"最新離線測試已執行原廠輸出工作與 56-byte 訊息佇列，由原配置程式建立播放緩衝、自行公布描述並啟動 mixer。{output_manager['routes']} 組來源格式共 {output_manager['decoded_frames']} 音框、{output_manager['pcm_bytes']} 單聲道 PCM bytes 經原解碼／轉換及讀取流程，另 {output_manager['peripheral_pcm_bytes']} bytes 在虛擬輸出緩衝符合逐取樣複製為立體聲的參考。原輸出函式的第三參數是第一個音源旗標；緩衝長度來自實體通道描述，資料為 16-bit。測試提供通道、16 kHz 格式及音量 100，使用原格式／音量政策；沒有驗證其他音量、重取樣或多音源混音。")
        parts.append(f"{output_manager['source_lifetimes']} 個來源由原函式消耗資料、辨識結束，再經原中央控制工作停止、清理、執行下一來源選取並移除唯一節點；播放緩衝與 reader／scratch 都有釋放證據。控制程式沒有直接送 STOP15、CLEANUP19、移除節點或推進消耗位置，但仍逐一註冊／啟動每個已產生的 PCM 區塊、稍後掛接 reader 並釋放票號。這尚非自動連續音樂串流。硬體啟動、電源／仲裁、配置服務及音訊輸出事件仍由模擬器提供，虛擬跳板也略過原多音源輸出迴圈；沒有真正 IRQ／DMA／DAC 或喇叭出聲證據。首次讀取早於 reader 包裝，PCM 靠測試的持有契約保留；正式存活保護、跨通道保留及安全卸載仍待完成。")
    if output_stop.get('test_result') == 'passed' and not playback_control_passed:
        parts.append('另已執行原公開停止要求：要求返回時音源與緩衝仍活著，之後由原輸出及中央完成流程釋放驅動緩衝、scratch、provider 並清除方法。原佇列節點仍保留，所以自持 PCM 的 release 正確拒絕回收。測試為已產生 EOF 的短音源、首次虛擬消耗前停止；完整來源取消、重播／重新選取、長串流及實際靜音品質尚未驗證，不能將停止完成當成可卸載或重用 PCM。')
    if playback_control_passed and not coordinator_passed:
        parts.append(f"最新新增 {playback_control['flat_binary_bytes']}-byte ARMv6 控制元件，在模擬器的原配置回呼入口接入；先掛接編譯的 reader 保護，再執行保留的原廠 START14 流程。{playback_control['routes']} 種來源格式共 {playback_control['decoded_frames']} 音框、{playback_control['source_pcm_bytes']} PCM bytes，初播與重播合計 {playback_control['guarded_read_calls']} 次原廠 reader 進入都經保護，包含首次讀取，控制程式沒有稍後才掛接 reader。此包裝保留原廠堆疊，只對新增 C 呼叫對齊，模擬器入口修改後也會重播被移位的原指令；既有解碼／音訊元件未修改。")
        parts.append(f"停止後原佇列節點與 PCM 仍持有。新增編譯的 rearm 先檢查原 provider／methods／mixer／driver 已清理、來源回到閒置、節點仍存在且 reader 已退出，才把自有來源重新排為待選取；沒有改寫原廠狀態或釋放 PCM。原廠重新選取及重播通過，{playback_control['replay_peripheral_pcm_bytes']} bytes 虛擬立體聲輸出與參考相同；忙碌、停止尚未完成、重複要求、節點已刪及過期票號均拒絕重播。這仍依賴序列化且獨占的通道呼叫契約，IRQ 保護與狀態檢查不能證明未進入 callback 的存活保護、跨通道保留或安全卸載。")
        parts.append('這次修改只存在模擬器 RAM，使用指定版本元件的私人介面與虛擬位址，沒有製作原機可接受的載入套件。測試音源在停止前已產生 EOF，完整來源取消、長串流、自動接續下一個 PCM 區塊、其他來源的旁路及導航多工尚未驗證。實體通道／音量輸入、硬體啟動、電源／仲裁、heap 與輸出事件仍是模擬邊界；没有真正 IRQ／DMA／DAC／喇叭或即時效能證據。下一步串完整取消及連續播放，再整合原機載入、UI 與真正藍牙端點。')
    if coordinator_passed and not source_worker_passed:
        parts.append(f"最新新增 {coordinator['flat_binary_bytes']}-byte ARMv6 音源控制元件，由原 kernel 查詢取得呼叫工作的識別。控制元件自行註冊、啟動、釋放與接續下一段已解碼 PCM，沿用首次讀取前的保護包裝；既有解碼及播放元件保持不變。三種格式共 {coordinator['decoded_frames']} 音框／{coordinator['packets']} 包，{coordinator['pcm_bytes']} PCM bytes 及 {coordinator['peripheral_pcm_bytes']} bytes 虛擬立體聲輸出與參考相同。四個資料槽持有時第五包等待，控制元件釋放後會透過原 kernel 事件讓解碼工作繼續，沒有測試直接執行解碼 step。")
        parts.append('取消流程也已測試：先停用合成封包接收、丟棄等待解碼的封包，再等待原廠停止／清理完成，經原 mutex 保護的移除介面刪除節點，最後釋放自持 PCM。四段已提交資料全部清除，其中三段未播放資料只註冊再移除，沒有讀取；等待解碼的一包與停用後晚到的封包均未提交。移除期間私人 native_calls 保持持有，原事件 23 出現時節點仍存在，直到原移除介面返回後才放行釋放。重複取消也通過，沒有將原廠狀態或 FIFO 直接改成空值。')
        parts.append('這輪仍由測試程式定期呼叫 pump，並提供合成封包與虛擬輸出事件；尚未建立自行等待／喚醒的控制工作，也沒有長時間連續播放或無縫輸出證據。呼叫工作識別檢查不能代替跨通道保留或尚未進入 callback 的存活保護，錯誤呼叫工作、重入與解碼途中取消還需要驗證。虛擬位址、私人匯入及模擬器入口包裝不是原機載入證據；真正硬體、UI、藍牙端點及手機播放仍待整合，元件和工作記憶體也仍保留。')
    if source_worker_passed:
        parts.append(f"最新新增 {source_worker['flat_binary_bytes']}-byte ARMv6 工作元件，讓原 kernel 建立並排程音源控制工作。完整解碼提交之後與原廠來源清理函式返回之後，編譯的包裝會發出喚醒事件；工作自行註冊、啟動、釋放並接續下一段音訊，測試程式不再定期呼叫 pump 或補送控制元件的喚醒。既有五個元件檔案保持不變，入口修改只存在模擬器 RAM。")
        parts.append(f"三種來源格式、兩種工作優先權共 {source_worker['routes']} 組，{source_worker['decoded_frames']} 音框／{source_worker['packets']} 包、{source_worker['pcm_bytes']} PCM bytes 與 {source_worker['virtual_stereo_bytes']} bytes 虛擬立體聲輸出符合獨立參考。第五包在四個自持資料槽已滿時等待，原生釋放事件會讓解碼工作繼續。較高優先權的控制工作等待原同步啟動回覆時，解碼工作仍能提交後續封包；私人待處理旗標保留事件，沒有將這些事件誤當啟動完成。")
        parts.append('非同步取消也由原生工作處理：等待原廠停止／清理完成的事件，再經原 mutex 保護的刪除介面清除四段資料，其中三段未播放資料沒有被讀取，等待解碼的一包及停用後晚到封包也未提交。原生工作與解碼工作都執行原廠退出流程並到達 0x80 結束狀態；本輪沒有另行遍歷全部工作清單。堆疊、TCB 和元件仍保留，這不是安全卸載。')
        parts.append('測試仍提供合成手機封包與虛擬輸出音框；硬體通道、音量、heap、電源與仲裁也有模擬邊界。沒有長時間連續或無縫播放、實際 IRQ／DMA／DAC、喇叭、導航共存或原機載入證據。解碼途中取消、失敗重整、跨通道保留及尚未進入 callback 的存活保護仍待驗證；下一步將原型接到原機可接受的元件與 UI、真正 SDP／SEP 及手機串流。')
    if voice_mount:
        parts.append('已追到原廠語音選取訊息、套件開啟、DLL 載入流程，以及 dllinfo.txt 的 dll_chksum 欄位。語音識別複製長度為 20 個 UTF-16 單位／40 bytes；套件映射與內部檔案系統初始化後才會讀取 DLL。尚不能判定修改套件會被接受。')
    if app_component_passed:
        parts.append(f"最新把解碼器、音源控制與兩個工作重新連結到原廠語音元件保留的 3 MB 範圍，新增程式 {app_component['appended_code_bytes']} bytes、BSS {app_component['bss_bytes']} bytes，另保留四段 PCM、壓縮佇列和兩個堆疊。三個原廠語音版本均經原始載入指令完成初始化，40 個原廠介面與跳板保持一致；私人介面中的解碼器共 {app_component['decoded_frames']} 個音框符合上游參考，一個已知原廠查詢介面也保持原行為。")
        if not loaded_playback_passed:
            parts.append('這次完整原型在新位址已編譯，但只執行載入入口、解碼器和該查詢，尚未重跑移動後的工作／事件／播放流程。')
        parts.append('測試使用合成 DLL 檔案回呼，未執行真正 VPM 掛載；沒有產生修改語音包或自動啟動工作。額外初始化超過舊模擬指令上限後，新測試與原廠控制組使用相同的提高上限，不代表實機效能結果。')
    if loaded_playback_passed:
        parts.append(f"後續已在同一個模擬系統中串接原廠載入器與完整播放。先結束準備環境用的舊解碼工作，再由原廠指令載入整合 DLL，啟動保留範圍內的新解碼與音源工作；載入後禁止執行舊獨立元件。三個語音版本輪替音訊格式與兩種優先權，共 {loaded_playback['routes']} 組、{loaded_playback['decoded_frames']} 音框、{loaded_playback['source_pcm_bytes']} PCM bytes 和 {loaded_playback['virtual_stereo_bytes']} bytes 虛擬立體聲輸出符合參考。這是六組輪替矩陣，沒有測完全部十八種組合。")
        parts.append('三個語音版本各通過取消測試，合計移除及釋放十二段已提交資料，其中九段未播放資料未被讀取，另外丟棄三個待解碼封包。工作自行接續與取消，沒有測試定期呼叫 pump 或補送音源喚醒。三十次原生同步啟動均等到原廠回覆，原廠語音記憶體、四十個介面及已知查詢行為保持不變；自訂工作結束後才移除模擬器入口修改。')
        parts.append('實體手機、SEP 註冊、音訊硬體、heap、音量、電源及仲裁仍有模擬邊界；沒有原機 App／UI、真正套件接受、手機直接播放或導航共存證據。工作、TCB、堆疊及元件仍保留，語音切換、重載、卸載與解碼途中取消尚未驗證。')
    if acceptance:
        parts.append('已解析中繼資料函式的跨區跳板與十三個分支：它依語音產品代號調整顯示名稱。外層開檔流程透過執行時建立的磁碟驅動函式表呼叫，與套件內部的 DSKIMG 檔案系統不同；不能由這個名稱處理函式推論簽章不檢查。')
    if vpm_filesystem.get('test_result') == 'passed':
        parts.append('最新已識別外層 FAT 驅動註冊與內層 DSKIMG 解析器，修正先前將映射檔案開啟統稱為掛載的描述。在模擬器中執行原廠套件重新掛載、目錄搜尋、分配表換算、檔案讀取及關閉，再由原廠 DLL 載入器初始化三個未修改的語音包。載入器的五個開檔／讀取／定位／關閉回呼也執行原始指令；各版本的完整語音記憶體及四十個函式跳板均與獨立載入控制組一致。')
        parts.append('兩個只存在記憶體的控制組顯示：內層檔案系統仍可完整讀出校驗值不符的 DLL，以及內容被清零的簽章檔。四個錯誤標頭／初始資料不足控制組都未成為可用磁碟，找不到的檔案也被拒絕。修改內容沒有執行，也沒有存成修改語音包；這只能定位內層讀取行為，不能推論高層語音選取不檢查簽章。')
        parts.append('底層檔案位元組 I/O、檔案系統與快取初始配置、暫存路徑 heap、IRQ、mutex、執行快取同步和 ASCII 字元分類仍由測試提供。外層真實檔案開啟／映射、高層中繼資料與校驗政策、修改包載入及實機執行仍待驗證。下一步追高層套件檢查、語音選取與自製 UI 入口。')
    if voice_metadata.get('test_result') == 'passed':
        parts.append('原廠高層資訊檢查已完成新一輪模擬：三個原廠語音包經真正的內部檔案系統、結尾 END 標記檢查、字元轉換、UTF-16 標籤與數字解析及產品名稱調整，再於同一個模擬環境執行原 DLL 初始化；原廠記憶體與四十個介面仍符合獨立控制組。七個只存在記憶體的控制組中，舊校驗值、清空簽章、零值或缺少校驗欄位仍通過這個資訊檢查函式；缺少必要語言欄位、錯誤或缺少結尾標記則被拒絕。缺少校驗欄位時原廠預設值為 0xFFFFFFFF。修改套件沒有執行或保存，不能由這一段結果宣稱整台機器不驗證簽章。')
        parts.append('另追到兩個外層列舉呼叫者：資訊檢查後仍會檢查套件類型與另一個平台條件，才加入語音清單。六組真正指令模擬確認該條件會讀取／快取儲存項目 0x13A，特定值 0xA1E 再配合另一個快取欄位的 0x4C 值會拒絕；實機欄位值及含義尚未讀出，不能把它當作本台 HWID。兩條列舉流程本身尚未完整執行。新的 heap 測試讓原廠指標查詢與空白相容回呼執行原指令；這不是記憶體鎖定、安全卸載或導航共存證據。下一步串完整外層列舉／語音選取與自製 UI，並追原機藍牙端點及真正手機／喇叭播放。')
    parts.append('修改語音包能否通過檢查、所有原廠介面的實際功能、UI 入口、真實 A2DP 端點及實機播放仍未驗證。原生 App 與手機直接音樂播放尚未達成，實驗元件不是安裝候選。')
    return ''.join(parts)


def main():
    metadata = json.loads((BACKUP / 'sda.json').read_text())
    verification_path = BACKUP / 'verification.json'
    verification = json.loads(verification_path.read_text()) if verification_path.exists() else None
    installation_path = ROOT / 'evidence/theme-installation.json'
    installation = json.loads(installation_path.read_text()) if installation_path.exists() else None
    installed = bool(installation and installation.get('state') == 'installed_readback_verified' and installation.get('unmounted'))
    ui_verified = bool(installed and installation.get('device_ui_verified'))
    sdp_path = ROOT / 'evidence/nuvi-sdp-paired.json'
    sdp = json.loads(sdp_path.read_text()) if sdp_path.exists() else None
    sdp_verified = bool(sdp and sdp.get('sdp_returncode') == 0 and sdp.get('hfp_handsfree'))
    audio_path = ROOT / 'evidence/call-state-audio-test.json'
    if not audio_path.exists():
        audio_path = ROOT / 'evidence/third-sco-audio-test.json'
    audio = json.loads(audio_path.read_text()) if audio_path.exists() else None
    audio_transmitted = bool(audio and (
        (audio.get('returncode') == 0 and audio.get('transport_verified', {}).get('synchronous_connect_success'))
        or (audio.get('playbacks') and all(p['returncode'] == 0 for p in audio['playbacks']))
    ))
    audio_heard = bool(audio and audio.get('heard_on_device') is True)
    research_path = ROOT / 'evidence/deep-research-state.json'
    research = json.loads(research_path.read_text()) if research_path.exists() else None
    map_manifest_path = Path(research.get('map_update', {}).get('manifest',
        str(ROOT / 'staging/maps/Taiwan_OSM_20261001_UTF8/manifest.json'))) if research else ROOT / 'staging/maps/Taiwan_OSM_20261001_UTF8/manifest.json'
    map_manifest = json.loads(map_manifest_path.read_text()) if map_manifest_path.exists() else None
    map_install_path = ROOT / 'evidence/map-installation-latest.json'
    map_install = json.loads(map_install_path.read_text()) if map_install_path.exists() else None
    map_installed = bool(map_install and map_install.get('state') in
                         ('installed_readback_verified', 'already_installed_readback_verified')
                         and map_install.get('unmounted'))
    options = []
    for status, idea, detail, evidence in OPTIONS:
        if research and idea == '直接安裝 Android Auto／Android' and research.get('native_android_auto', {}).get('requested'):
            status = '研究中'
            idea = 'GarminOS 內建 Android Auto 接收端'
            detail = '依使用者最新指示列為主線，goal 保持 active。已核對固定版本 OpenAuto／aasdk 的 376 個來源檔：需移植 AOA USB 主機傳輸、TLS／Protobuf、多媒體與輸入通道及自製 UI。舊版畫面最低設定為 800×480，需適配本台 480×272；影片為 H.264，不能以原機 JPEG／MJPEG 功能代替。原廠觸控測試頁的事件處理已通過六項離線模擬；實際輸入驅動、新 App 註冊、手機連線與螢幕顯示均未完成。STA2064 資料表列 USB OTG，但板上主機接線／VBUS、韌體驅動、H.264 解碼與速度仍未知。'
            evidence = 'native-android-auto-feasibility.json；native-projection-touch-emulation.json；精確 HWID 1352 韌體與固定 commit 上游來源'
        if research and idea == '原機自製 App／手機直接播音樂':
            detail = native_research_detail(research)
            evidence = 'evidence/firmware-analysis/native-component-loader.json；tts-vpm-containers.json；original-tts-module-emulation.json；native-sbc-component-emulation.json；native-sbc-pcm-emulation.json；native-voice-extension-emulation.json；avdtp-media-dispatch-emulation.json；native-voice-media-emulation.json；native-audio-format-emulation.json；native-pcm-converter-emulation.json；native-voice-convert-emulation.json；native-pcm-flow-control-emulation.json；native-task-creation-emulation.json；native-task-lifecycle-emulation.json；native-runtime-code-inventory.json；native-media-queue-emulation.json；native-task-event-static.json；native-media-worker-emulation.json；native-media-consumer-emulation.json；native-media-header-refactor-verification.json；native-audio-registration-emulation.json；native-audio-message-emulation.json；native-pcm-initialization-emulation.json；native-memory-audio-emulation.json；native-memory-completion-emulation.json；native-memory-notice-emulation.json；native-memory-output-emulation.json；native-owned-media-emulation.json；native-source-worker-emulation.json；native-voice-mount-static.json；native-app-component-emulation.json；native-loaded-playback-emulation.json；native-voice-acceptance-static.json'
        if research and idea == '原機自製 App／手機直接播音樂' and research.get('native_app_music', {}).get('static_findings', {}).get('native_vpm_filesystem'):
            evidence += '；native-vpm-filesystem-static.json；native-vpm-filesystem-emulation.json'
        if research and idea == '原機自製 App／手機直接播音樂' and research.get('native_app_music', {}).get('static_findings', {}).get('native_voice_metadata'):
            evidence += '；native-voice-metadata-emulation.json；native-voice-enumeration-static.json；native-voice-predicate-emulation.json'
        if research and idea == '原機執行離線 Google Maps' and research['google_maps'].get('research_deferred_by_user'):
            detail = '使用者已要求先延後此研究，優先更新台灣離線圖資。' + detail
        if research and idea == '更新 OSM 地圖' and research.get('map_update', {}).get('prepared'):
            status = '已準備'
            detail = '已使用 Geofabrik／OSM 2026-10-01 資料編譯台灣全區地圖，134,852,608 bytes（約 129 MiB）。36 個區塊的顯示、標籤及 NET／NOD 路由元件、全域地址索引、UTF-8 繁中文字標和無重疊區塊配置均通過檢查。'
            detail += (' 已新增到 Map/Taiwan_OSM_20261001.img、讀回 SHA-256 通過並卸載。' if map_installed
                       else ' 安裝程序已準備，等待導航機以 USB 隨身碟模式接到 Pi。')
            detail += ' 保留原廠地圖；實機繁中顯示、搜尋和路線計算仍待驗證。這是 OSM 道路圖資，不會更新原廠 JCV 路口照片。地址自動歸屬為推估，完整性需實測。'
            if map_installed:
                status = '已安裝'
            if research['map_update'].get('map_list_visible') or research['map_update'].get('device_map_list_visible'):
                detail += ' 使用者已確認一般模式的地圖清單出現 OSM Taiwan 2026-10-01。'
            if map_manifest and map_manifest.get('credit_text'):
                detail += ' 產品與系列名稱已加入署名，但使用者回報畫面未顯示；依使用者指示取消後續署名修正。'
            evidence = str(map_manifest_path.relative_to(ROOT)) + '；' + str(map_manifest.get('structural_evidence', 'evidence/taiwan-map-structural-verification.json')) + '；scripts/install_taiwan_map.py'
        if installed and idea == '地圖日夜配色':
            detail = detail.replace('已準備 Pi Contrast', '已新增 Pi Contrast 到導航機並獨立讀回核對 SHA-256')
            evidence += '；evidence/theme-installation.json'
            if ui_verified:
                status = '已實測'
                detail = detail.replace('尚未在實機畫面驗證', '使用者已在一般模式選取此主題，確認可正常顯示')
        if sdp_verified and idea == '從手機播放藍牙音樂':
            status = '已實測'
            detail = '一般模式配對後完整 SDP 查詢成功：列出 SPP、HFP 1.5 與 PBAP PCE，沒有 A2DP Audio Sink。此模式不能當一般手機音樂串流接收器使用。韌體仍有 A2DP 字串，可能是共用堆疊／未啟用功能，無法據此宣稱已能播放音樂。'
            evidence = '實機完整 SDP 瀏覽：evidence/nuvi-sdp-paired.json'
            if research:
                detail += ' 追加實測：未公告的 AVDTP PSM 25 可連線，但 Discover 接受回覆沒有任何音訊端點。不是只藏起 SDP 項目即可接收音樂；端點初始化及解碼仍待逆向。'
                evidence += '；evidence/avdtp-discovery-*.json'
                if research['audio'].get('phone_a2dp_bridge_audible_verified'):
                    idea = '手機音樂經 Pi 轉接到 Garmin'
                    detail += ' 已另完成 Pixel 7 Pro → Pi A2DP/SBC → FFmpeg → Garmin HFP 的實驗，使用者確認 60 秒持續聽到手機音樂。仍需接聽模擬來電，輸出為 CVSD／單聲道 8 kHz。使用者回報音質差、音量起伏，原因尚未確定；Pi 目前只作取樣率與固定音量轉換，沒有加入降噪處理。長時間播放未驗證。'
                    evidence += '；' + research['audio']['phone_bridge_evidence']
        if sdp_verified and idea == '藍牙免持電話／喇叭':
            status = '已實測'
            idea = '藍牙配對／免持通話服務'
            detail = '已在一般模式與 Garmin-Pi 成功配對，主機顯示 Paired／Bonded，使用者也確認機台顯示已連接。HFP 1.5 使用 RFCOMM channel 5；PBAP 為電話簿客戶端。這證明配對與服務存在，聲音輸出另以短音源測試。'
            evidence = '實機 BlueZ 狀態、SDP 與使用者機台回報'
        if sdp_verified and idea == '通話音訊傳送實驗':
            detail = 'Pi 已提供 HFP Audio Gateway，並建立過 CVSD／單聲道 8 kHz 音訊介面。目前繼續測試 SCO 短音源是否能從機台喇叭發聲。通話音訊可能受通話狀態限制，即使能播放，也不是標準 A2DP 音樂模式。'
            evidence = '實機 HFP 握手與 BlueALSA 音訊介面；最終可聽結果尚待驗證'
            if audio_transmitted:
                detail = 'Pi 與機台已成功建立 eSCO／CVSD 通話音訊通道，播放程序完成單聲道 8 kHz 測試旋律。仍待使用者確認喇叭是否可聽；程序成功不等於實機一定出聲。這是通話音質的替代路徑，不是一般 A2DP 音樂模式。'
                evidence = str(audio_path.relative_to(ROOT)) + '；實機 HCI／BlueALSA 紀錄'
            if audio_heard:
                status = '已實測'
                detail = 'Pi 透過 HFP Audio Gateway 建立 eSCO／CVSD 通道。直接送音訊沒有聲音；補上通話中指示後，使用者確認電話畫面出現，Garmin 喇叭播放兩次旋律成功。這台可作為通話音質的音源播放裝置：單聲道 8 kHz，需由 Pi 轉換及送音源。一般手機音樂 App 不會自動走這條通道。可重用 scripts/test_hfp_call_audio.py。'
                if research:
                    detail += ' 已新增 Pi 端 garmin_music_player.py，自動解碼 MP3 等音檔並串接歌曲。'
                    if research['audio'].get('current_speaker_confirmed'):
                        detail += ' 本次重新配對起初有電話畫面但無聲；暫時同步 CIND 通話查詢狀態後，使用者確認模擬來電及接聽後旋律都有出現，測試含 Pi 解碼的 MP3。正式來源修正版已編譯、通過協定測試，目前未替換連線中的音訊服務。'
                        evidence += '；' + research['audio'].get('latest_physical_test_evidence', '')
                    else:
                        detail += ' 本次重新配對後仍在查音訊復現問題；原始成功證據另行保留。'
        if sdp_verified and idea == '當成即時 USB GPS 接收器':
            idea = '即時 GPS／藍牙序列埠研究'
            detail += ' 新的實測發現藍牙 SPP 服務 COM5、RFCOMM channel 1，可研究是否能接收定位或 Garmin 協定；僅有序列埠服務仍不代表已能取得即時 NMEA。'
            evidence += '；實機配對後 SDP'
            if research:
                detail += ' 已做 SPP channel 1 的被動連線測試，遭拒絕，尚未取得即時 GPS 資料。'
        options.append((status, idea, detail, evidence))
    time = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(timespec='seconds')
    findings = {'updated': time, 'device': {'marketing_model':'nüvi 2565RT Taiwan', 'reported_model':'nüvi 2565', 'hwid':1352, 'software':'8.00', 'usb':'091e:2548', 'logical_disk_bytes':3879731200, 'display':'5 inches, 480×272'}, 'backup': {'state':metadata['state'], 'image':str(BACKUP / 'sda.img'), 'sha256':metadata.get('sha256'), 'file_verification':verification}, 'theme_installation':installation, 'audio_test':{'transmitted':audio_transmitted,'heard_on_device':audio_heard,'evidence':str(audio_path)} if audio else None, 'options':[{'status':s,'idea':i,'detail':d,'evidence':e} for s,i,d,e in options], 'sources':[{'title':t,'url':u} for t,u in SOURCES]}
    findings['deep_research'] = research
    progress = build_progress(research, backup_verified=bool(verification and metadata['state']=='verified'),
                              theme_verified=ui_verified, map_verified=map_installed)
    findings['research_progress'] = progress
    findings['map_build'] = map_manifest
    findings['map_installation'] = map_install
    if research:
        findings['audio_test']['historical_success'] = audio_heard
        findings['audio_test']['current_reconnection_speaker_confirmed'] = research['audio'].get('current_speaker_confirmed')
        findings['audio_test']['current_evidence'] = research['audio'].get('latest_physical_test_evidence')
    report = ROOT / 'reports'
    report.mkdir(exist_ok=True)
    (report / 'findings.json').write_text(json.dumps(findings,ensure_ascii=False,indent=2))
    e = html.escape
    rows = ''.join(f'<tr data-state="{e(s)}"><td><span class="status">{e(s)}</span></td><td><strong>{e(i)}</strong></td><td>{e(d)}<small>{e(ev)}</small></td></tr>' for s,i,d,ev in options)
    sources = ''.join(f'<li><a href="{e(u)}">{e(t)}</a></li>' for t,u in SOURCES)
    state = '備份映像已通過 SHA-256 校驗' if metadata['state'] == 'verified' else '備份映像仍在處理'
    files = f"另外已讀出 {verification['files']:,} 個檔案，檔名與大小均符合實機清單；重要檔案和先前直接讀取的實機內容相符。" if verification else '完整檔案讀出驗證尚待完成。'
    document = '''<!doctype html><html lang="zh-Hant"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>nüvi 2565RT 改造調查</title><style>body{font:17px/1.7 system-ui,sans-serif;margin:0;background:#f1f4f7;color:#162637}main{max-width:1120px;margin:auto;padding:28px}h1{line-height:1.3}h2{margin-top:32px}.card{background:white;border:1px solid #d7dee6;border-radius:12px;padding:20px;margin:16px 0}small{display:block;color:#526579;font-size:13px;margin-top:8px}table{border-collapse:collapse;width:100%;background:white}th,td{text-align:left;vertical-align:top;border-bottom:1px solid #d7dee6;padding:14px}th{background:#dce9f4}td:first-child{min-width:72px}td:nth-child(2){min-width:130px}.status{font-size:14px;font-weight:700}select,input{padding:9px;border:1px solid #94a6b7;border-radius:6px;font-size:16px;max-width:100%}code{overflow-wrap:anywhere}a{color:#075b9e}.scroll{overflow:auto}[hidden]{display:none!important}li{margin:7px 0}@media(max-width:600px){main{padding:14px}th,td{padding:10px;font-size:15px}}</style><main>'''
    document += '<style>.research-progress-card{border-top:5px solid #13699e}.progress-heading{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}.progress-heading h2{margin:0}.progress-status{font-size:14px;background:#e5f2ed;color:#216049;padding:4px 12px;border-radius:20px}.progress-total{display:flex;align-items:baseline;gap:8px;flex-wrap:wrap;margin:18px 0 8px}.progress-total strong{font-size:42px;line-height:1.2;color:#075b9e}.progress-total span{font-size:14px;color:#526579;margin-left:8px}progress{display:block;width:100%;height:20px;border:0;border-radius:10px;overflow:hidden;background:#e0e7ee;accent-color:#13699e}progress::-webkit-progress-bar{background:#e0e7ee;border-radius:10px}progress::-webkit-progress-value{background:linear-gradient(90deg,#13699e,#218977);border-radius:10px}progress::-moz-progress-bar{background:#13699e;border-radius:10px}.progress-note{font-size:14px;color:#526579}.progress-times{display:flex;gap:6px 24px;flex-wrap:wrap;padding:12px 0;border-top:1px solid #d7dee6;border-bottom:1px solid #d7dee6}.progress-times p{margin:0;font-size:14px}.progress-times p:last-child{flex-basis:100%;color:#526579}.progress-phases td:first-child{min-width:160px}.progress-phases td:nth-child(2){min-width:76px;white-space:nowrap;font-weight:700}.progress-calculation{font-size:14px;color:#526579}.progress-calculation summary{cursor:pointer}@media(max-width:600px){.progress-total strong{font-size:36px}.progress-times{display:block}.progress-times p{margin:3px 0}.progress-phases td:first-child{min-width:110px}}</style>'
    document += f'<h1>nüvi 2565RT：能改什麼、還缺哪些實測</h1><p>調查對象是台灣版 HWID 1352，從實機 USB、檔案與匹配官方韌體核對。</p>'
    document += render_progress(progress,time)
    if research:
        player_widget=research.get('native_app_music',{}).get('static_findings',{}).get('native_player_widget',{})
        if player_widget.get('all_passed'):
            document += '<div class="card"><h2>最新離線進展：原廠按鈕建構與播放器訊號</h2><p><strong>三組完整驗證通過。</strong>原廠外層載入器進入播放器元件後，原廠菜單選取函式現在會執行真正的按鈕工廠、基礎與子物件建構、方法表、回呼複製和訊號訂閱。測試呼叫原廠按鈕的軟體訊號兩次，原訊號清單與回呼處理都能呼叫常駐元件內的播放器，送出 WAV 登錄及開始播放請求；沒有由測試直接呼叫播放器回呼。</p><p>工廠第五個參數為 0 時會綁定播放事件；參數為 1 的控制案例同樣建立按鈕，但沒有播放訂閱，發出訊號也不會呼叫播放器。另一組執行完整的原廠「新增菜單項目」建構函式，名稱「Pi 播放器」、附加欄位、編號與方法表皆核對。這是單一新增項目的建構，完整新增菜單頁仍待接通。</p><p><strong>仍未證明實機螢幕已有可觸控的 App。</strong>這次由測試發出軟體訊號；一般頁面的掛接、佈局、啟用狀態、觸控捕捉與事件佇列、圖示／文字繪製及螢幕提交尚未完成。圖示字串仍為空白。記憶體配置、資料庫已開啟狀態、SQLite 底層和音訊端點由測試提供；WAV 解碼、音訊核心與喇叭沒有執行。物件、持有者與元件仍保留在記憶體，安全停止／釋放尚待驗證。</p><p>模擬環境提供浮點存取及韌體啟動時的零填記憶體，並明確呼叫原廠 GUI 計時器建構函式；實際開機順序、畫面執行緒與計時器事件仍未知。最後檢查確認原 GUI 函式只將一個 RAM 初始化旗標從 0 設為 1，其餘原程式與區域均核對；這版沒有 MAIN 修補。原語音記憶體與 40 個介面、所有配置邊界、十五格資料庫還原及備份雜湊皆通過。</p><p>初次測試誤用系統舊模擬器而發生主機崩潰；除錯確認發生在按鈕工廠階段，特定崩潰原因未確定。已改用驗證過的隔離版本、修正未初始化的按鈕持有者，並在釐清 RAM 旗標後完整重跑。封裝仍只供離線研究，沒有安裝到車機或發出聲音。下一步接真正頁面、圖示資源與觸控，再推進可接受的載入方式和手機直接藍牙音樂。</p></div>'
        player_selection=research.get('native_app_music',{}).get('static_findings',{}).get('native_player_menu_selection',{})
        if player_selection.get('all_passed'):
            document += '<div class="card"><h2>前輪紀錄：名稱欄位修正與原廠菜單選取</h2><p><strong>三組驗證通過，包含六項資料庫選取情境。</strong>先前只核對名稱字串，這次用填入特殊值的堆疊確認：原廠字串建構與複製處理 16 bytes，菜單名稱另有一個分開複製的 4-byte 附加欄位。舊原型沒有初始化它，會帶入測試填值。新的離線元件將該欄位設為零，保留原語音介面；尚未證明舊版本在實機造成畫面故障。</p><p>使用唯讀備份的圖示資料庫，複製到 Pi 記憶體中的 SQLite 引擎。原廠菜單寫入／讀取、SQL 格式化、字元轉換、綁定、結果狀態轉換與清理函式實際執行。六種情境包含原空白格、已登錄播放器、兩種非一般格大小、未知圖示編號及不存在的格子。原廠讀取函式能選中播放器、交出名稱與回呼參數，再由原廠回呼處理呼叫載入元件內的播放請求。記憶體中的十五格已還原，備份資料庫保持原樣。</p><p><strong>選取成功仍未證明按鈕已建立或畫面已顯示。</strong>SQLite 底層引擎、資料庫已開啟狀態及按鈕建立邊界由測試提供，按鈕物件沒有被製造；原廠讀取函式也不檢查按鈕工廠的回傳值。新增菜單的原篩選流程在其他分類會排除播放器；預設分類能走到真正建構函式，但測試停在建構前。這輪未完成完整新增菜單、畫面／觸控、實機載入或喇叭播放。</p><p>另修正測試程式對原清理函式的誤判：它處理參照計數持有者，現在執行原指令，完整重新驗證。下一步沿已找到的按鈕建構函式追圖示資源、事件與畫面，同時保留直接藍牙音樂主線。封裝仍只供離線研究，沒有修改車機或播放聲音。</p></div>'
        player_loaded=research.get('native_app_music',{}).get('static_findings',{}).get('native_player_menu_loaded',{})
        if player_loaded.get('all_passed'):
            document += '<div class="card"><h2>前輪紀錄：原廠載入器接上播放器功能清單</h2><p><strong>'+str(player_loaded['case_count'])+' 個載入整合案例通過。</strong>這次把播放器回呼放進保留原語音功能的元件，由原廠完整外層讀取、選取與 DLL 載入流程執行；新元件入口自動呼叫原廠私有登錄函式。原廠按鈕回呼複製與按下處理函式接著呼叫位於該元件內的播放器回呼，送出本機 WAV 播放請求，沒有由測試程式直接呼叫登錄入口。</p><p>原語音的 40 個介面與完整原語音記憶體保持一致，元件放在原廠 3 MiB 保留空間內。這版不改 MAIN，也沒有啟動音樂端點或工作程序；原有藍牙音樂整合證據繼續保留。另兩個案例確認既有清單項目在擴充後保留，以及相同編號會被拒絕、原有回呼不被取代。既有項目是明列的合成控制資料。</p><p><strong>自動登錄功能記錄尚未證明一般菜單已顯示新 App。</strong>菜單資料庫選取、完整按鈕事件、畫面與觸控仍未跑通；圖示資源目前是空白占位。實機修改包／SIG 接受、語音載入時是否屬於正確的畫面執行緒、重複播放與停止回收、安全重載／卸載仍待驗證。播放 API 邊界由測試記錄，這輪沒有音訊解碼、DAC 或喇叭播放；原廠 Play WAV 的實機成功另列。</p><p>初次檢查發現既有測試環境會設定平台啟用旗標，與原始韌體值不同；已將這一個 byte 明列為測試設定，再完整重跑三個案例。原 MAIN 與原程式區核對保持一致。下一步追功能清單到實際菜單的呈現與事件流程，再與直接藍牙音樂整合。研究封裝仍僅供離線使用，沒有傳入車機。</p></div>'
        player_menu=research.get('native_app_music',{}).get('static_findings',{}).get('native_player_menu',{})
        if player_menu.get('all_passed'):
            document += '<div class="card"><h2>前輪紀錄：自製播放器的菜單回呼已接通</h2><p><strong>'+str(player_menu['case_count'])+' 個菜單入口案例通過。</strong>已復原精確台灣 8.00 的私有圖示登錄方式：每筆功能記錄包含名稱、圖示資源、按下回呼與參數。新 ARMv6 原型呼叫原廠建構與加入清單函式，原廠按下處理函式能讀出記錄，執行自製播放器回呼，並送出本機 WAV 的登錄及開始播放請求。</p><p>測試包含中文字名稱、名稱來源覆寫後仍保存、十二筆記錄多次擴充後保留回呼、重複編號及異常輸入拒絕，以及原廠按鈕回呼複製和釋放。原韌體程式區保持逐 byte 相同，四組都使用原廠指令執行登錄、字串複製和派送。</p><p><strong>實機一般菜單顯示、觸控及 App 載入仍待完成。</strong>目前圖示資源是空白占位，尚未跑完整畫面／觸控流程或資料庫選取。這輪記憶體配置服務和播放 API 邊界由測試提供，沒有執行 WAV 解碼、DAC 或喇叭；先前 Play WAV 實機成功另有獨立證據。這是本台韌體的私有介面，正式安裝方式、畫面工作執行緒和安全卸載尚未驗證。</p><p>下一步追圖示清單到一般菜單呈現與按鈕事件的完整流程，再接可接受的原生載入方式及手機直接藍牙音樂。依最新指示，聲道與音質精修擱置；這輪只在 Pi 離線執行，沒有修改車機或發出聲音。</p></div>'
        native_wav=research.get('audio',{}).get('native_WAV_tests',[])
        if any(t.get('format',{}).get('sampling_hz')==16000 and t.get('speaker_confirmed') for t in native_wav):
            document += '<div class="card"><h2>最新實機測試：車機直接播放自製 WAV</h2><p>Pi 先提供音訊服務及配對代理，使用者由 Garmin 連線；這次模擬來電接聽後的短旋律再次有聲。接著核對精確台灣 8.00 韌體的診斷頁處理器，確認它讀取 <code>0:/Garmin/test.wav</code>。只新增測試音檔，讀回核對並安全卸載，沒有安裝研究程式或修改韌體。</p><p><strong>原廠 Audio Test Page 的 Play WAV 已播放自製 16 kHz、16-bit、單聲道音檔，使用者確認五個音符。</strong>這是車機本身播放本機檔案，沒有使用藍牙通話傳音。44.1 kHz 立體聲檔只確認聽到三個下降音符；另一段未確認，原因未查明，不能宣稱雙聲道或 DAC 取樣率已驗證。</p><p>依使用者最新指示，後續重點是新增原機功能：可從一般菜單開啟的播放器 App，以及手機直接藍牙音樂。聲道與音質精修不再列為目前優先；這次診斷播放仍不等於新增 App 或直接 A2DP 已完成。實機觀察與離線原型證據分開記錄。</p></div>'
        if research.get('ordered_priorities'):
            document += '<div class="card"><h2>目前主線：原生藍牙音樂與 GarminOS 播放器 App</h2><p>依使用者最新順序，先研究手機直接連 Garmin 的 A2DP 音樂端點、原生音訊及可從菜單開啟的自製播放器。現場配對與維持連線一律優先；Android Auto 保留在音訊與 App 之後，Google Maps 仍延後。麥克風／遠端擴音已依使用者指示取消。整體研究持續進行，不標記完成。</p><p>最近一次現場已再次確認：Garmin 收到模擬來電，接聽後聽到旋律；Pixel 經 Pi 轉送的音樂也持續有聲。音樂測試提示約 10 秒，180 秒是程式上限，不能當成整段時間都已聽音驗證。這仍使用單聲道 8 kHz 通話音訊，音質改善與手機直接音樂尚未完成。</p>'
            continuous = research.get('native_app_music',{}).get('static_findings',{}).get('native_music_continuous',{})
            if continuous.get('all_passed'):
                document += '<h3>最新：同一原廠音訊來源可持續接收 PCM</h3><p><strong>'+str(continuous['case_count'])+' 個持續來源整合案例通過。</strong>新原型維持同一個原廠記憶體音訊來源，只替換屬於自己來源的讀取回呼；四格 PCM 緩衝在複製讀取完成後即可重用，不再每個封包都建立新的播放來源。44.1 kHz 聯合立體聲及 48 kHz 立體聲使用不同工作優先序，有效 PCM 符合獨立參考。暫時缺資料時補靜音而不回報結束；緩衝滿時第五個封包保留在壓縮佇列，讀取釋放空間後喚醒解碼。後段 CRC 錯誤不發布部分音訊，下一個有效封包重新建立解碼／濾波狀態。</p><p>原廠計時器、核心與混音工作實際執行。測試每次虛擬輸出音框另提供 70 毫秒的時間輸入，讓原廠計時器到期後喚醒讀取；沒有直接要求解碼或混音工作強制讀取。兩個持續播放案例中，核對的音樂資料已送到原廠虛擬立體聲輸出，靜音部分也核對。暫停／斷線時先停止生產，等原廠停止、清理與刪除來源完整返回後才釋放持續來源並丟棄待播 PCM；恢復或同通道重連後建立新來源，40 個原語音介面與原語音記憶體保留。</p><p><strong>補靜音維持來源有效，尚未證明長時間無縫音樂、實際延遲或音質。</strong>這版仍使用單聲道 16 kHz 中間格式。這組刻意低供料的測試大部分輸出是靜音，尚未驗證手機正常封包節奏；還要檢查讀取中的取消與緩衝容量。封包到達、70 毫秒時間輸入、音訊通道、輸出事件、磁碟、記憶體權限與快取是測試配置；虛擬輸出仍只呼叫單一來源的原廠處理函式，沒有實機 IRQ、時脈、DAC、喇叭、導航共存或真實手機連線證據。完整外層檔案載入仍另有前輪證據，尚未與這版排程合成一次測試。修改包接受、獨立 App／菜單、失敗撤回及安全重新載入仍未完成；研究封裝沒有傳入導航機。證據：<code>native-music-continuous-emulation.json</code>。</p>'
            document += '<h3>這些離線測試怎麼做？</h3><p>使用這台台灣版 HWID 1352／8.00 的核對過韌體，以及 USB 備份中的語音元件，在 ARM CPU 模擬器執行原始程式指令，再把新寫的音樂程式編譯為 ARM 元件放進同一測試環境。原廠載入器、工作排程、部分藍牙協定與混音函式確實執行；測試提供封包、記憶體配置、虛擬時間及輸出事件，並將 PCM 與獨立參考逐 byte 比較。這是指定程式流程的執行驗證，沒有模擬整台導航機的導航畫面或所有硬體。</p><p>因此能核對程式邏輯、資料流與部分錯誤處理，不能用它證明導航機接受修改檔、手機無線連線成功、實體喇叭有聲或播放效能足夠。實機測試會在使用者通知回到現場後另行安排。</p>'
            music_ready = research.get('native_app_music',{}).get('static_findings',{}).get('native_music_ready',{})
            if music_ready.get('all_passed'):
                document += '<h3>前輪：初始化完成檢查、取消快照與 START 清單邊界已補齊</h3><p><strong>'+str(music_ready['case_count'])+' 個啟動／排程／輸出案例通過。</strong>新增五個控制案例，並重跑前輪九個播放、暫停、重連與損壞封包恢復案例。原型現在記錄原廠音訊初始化函式完整回傳的結果與所屬工作；只有初始化成功、工作仍有效且舊音訊沒有待回收時才接受設定或開始播放。工作尚未進入、已進入但初始化仍暫停，以及初始化失敗時，都會拒絕設定。恢復初始化後的有效音訊仍符合參考；失敗案例沒有發布音訊。</p><p>就緒與取消判斷使用同一份中斷保護範圍內的狀態快照；測試核對相關欄位的讀取範圍。另在原始 START 處理器發現 8 位元迴圈計數器，超過 255 筆有效項目可能繞回；新原型在進入原廠處理器前拒絕這種清單。四筆清單遇到舊音訊待回收也會拒絕，255 筆保留原廠處理結果，256 筆提早拒絕。仍保留 40 個原語音介面與原語音記憶體。</p><p><strong>這是模擬環境的啟動與邊界驗證，尚未安裝 App 或證明手機直連播放。</strong>初始化暫停由明示的測試事件觸發，工作切換執行原廠核心，沒有以 Python 還原 CPU 狀態；實機中斷、記憶體權限、硬體時脈與喇叭仍未驗證。初始化失敗後，已發布的藍牙服務、程式與工作資料仍保留，尚未完成撤回服務、解除掛接或重新啟動。該前輪版本以每個封包建立有限音訊；上方最新原型已改為持續來源，仍沒有長時間無縫播放證據。完整外層檔案載入與音訊排程尚未合成一次測試。研究封裝沒有傳入導航機。證據：<code>native-music-ready-emulation.json</code>。</p>'
            music_runtime = research.get('native_app_music',{}).get('static_findings',{}).get('native_music_runtime',{})
            if music_runtime.get('all_passed'):
                document += '<h3>前輪：原生藍牙端點、原廠排程與虛擬音訊輸出已接通</h3><p><strong>'+str(music_runtime['case_count'])+' 個排程／輸出整合案例通過。</strong>新元件由原廠 DLL 載入器讀入同一個已啟動核心的模擬環境，保留 40 個原語音介面及原語音記憶體。元件自行核對十一處原始資料後掛接藍牙控制、播放前讀取器與完整輸出完成通知，變更共 64 bytes；測試主機沒有在載入後另改派送或音訊掛接。工作由原廠核心建立、等待、喚醒與切換；封包保存並解鎖後才喚醒解碼，整包解碼發布後通知音訊工作，由原廠同步啟動、來源讀取、混音、完成與回收流程接手。</p><p>44.1 kHz 單聲道／聯合立體聲及 48 kHz 立體聲，各用兩種工作優先序，六個播放案例的原生 PCM 與虛擬立體聲輸出都符合參考。四格 PCM 滿時，第五個封包等待；原廠輸出完成回收後，自動喚醒並繼續解碼。較高優先序的音訊工作在同步啟動等待期間仍能收到發布通知。暫停或斷線後，舊音訊尚未回收時先拒絕重新開始／新設定；回收完成再恢复或建立新連線。後段音框 CRC 錯誤沒有發布部分音訊，下一個有效封包能恢復。私人回收函式拒絕已建立音訊工作者的使用；結束時兩個自製工作經原廠退出流程結束，程式、工作資料與堆疊仍保留。</p><p><strong>這仍是離線虛擬輸出，沒有原機喇叭或可安裝 App 的證據。</strong>硬體輸出要求、電源、音訊通道、藍牙接收、記憶體權限與快取仍由測試提供；不是實機 IRQ／DAC／導航共存。此輪使用 DLL 載入器的讀取測試介面，前輪完整外層檔案載入證據保留，但這版程式的外層載入與音訊排程尚未合成一次測試。仍以每個封包建立有限音訊，單聲道 16 kHz 是中間格式，尚未證明長時間連續、封包間無縫或最終音質。工作初始化失敗／完成就緒、跨工作取消狀態、實機通道保留、封裝接受、程式存活與安全解除仍待補齊；研究封裝沒有傳入導航機。證據：<code>native-music-runtime-emulation.json</code>。</p>'
            music_stream = research.get('native_app_music',{}).get('static_findings',{}).get('native_music_stream',{})
            if music_stream.get('all_passed'):
                document += '<h3>前輪：原生藍牙端點到封包檢查、解碼佇列與 PCM 已接通</h3><p><strong>'+str(music_stream['case_count'])+' 個串流整合案例通過。</strong>原廠完整載入流程讀入新元件後，在同一模擬環境接收設定與串流訊息；元件依連線世代、原生狀態、本機接收上限及每個 SBC 音框檢查封包，複製到四格有界佇列。消費端重新檢查連線與狀態，再執行 SBC 解碼與濾波，產生由元件持有的 PCM。8 種 44.1／48 kHz 單聲道、雙聲道、立體聲與聯合立體聲格式，共 24 個封包、48 個音框，轉成目前單聲道 16 kHz 中間格式後，4,280 bytes 與獨立參考逐 byte 相同。</p><p>測試包括借用的輸入記憶體在複製後覆寫、佇列滿時保留舊資料、斷線後重用相同通道仍區分新連線、入列後狀態變更、後段音框 CRC 錯誤不發布部分 PCM、暫停與重新開始，以及尚有舊 PCM 時先拒絕新設定。40 個原語音介面與原語音記憶體保留；新程式約 63 KB，整體 RAM 仍在原廠 3 MiB 保留區內。</p><p><strong>目前是記憶體中的 PCM，沒有喇叭播放證據。</strong>解碼佇列由測試逐步呼叫，PCM 讀回核對後以私人取消流程回收；這個回收案例假設沒有運行中的音訊輸出程序。尚未接入真正的作業排程、音訊輸出程序、喇叭驅動與時脈，也未證明手機實際 A2DP、導航共存、獨立 App 或菜單。實機載入接受、主程式可寫權限、快取同步及回呼存活仍待確認。研究封裝沒有傳入導航機。</p><p>舊版模擬器曾在主機上崩潰，失敗紀錄與當時程式已保留；改用隔離的 Unicorn 2.1.4 完成整輪 21 案例，系統套件與音訊服務維持原狀。具體崩潰原因尚未確認，也不能由新版通過推論真機可用。版本參考：<a href="https://github.com/unicorn-engine/unicorn/releases/tag/2.1.4">Unicorn 官方 2.1.4 發行紀錄</a>。證據：<code>native-music-stream-emulation.json</code>、<code>native-music-stream/emulator-runtime.json</code>。下一步接入真正的作業排程與音訊輸出程序。</p>'
            music_loaded = research.get('native_app_music',{}).get('static_findings',{}).get('native_music_loaded',{})
            if music_loaded.get('all_passed'):
                document += '<h3>前輪：原生音樂元件與原廠載入流程已離線整合</h3><p><strong>'+str(music_loaded['case_count'])+' 個載入整合案例通過。</strong>把既有藍牙端點、設定檢查、回覆修正及 SBC／音訊工作程式重新連結成同一元件，擴充程式約 60 KB，整體 RAM 使用約 2.35 MiB，仍在原廠 3 MiB 保留區內。原廠外層檔案與語音選取流程完整讀回新元件後，原入口回傳 11；40 個原語音介面及初始化後的原語音記憶體維持相同，12 個私有介面與 12 個音樂介面都指向這個保留區。</p><p>在同一個模擬環境中，載入元件自行核對八處原始資料，再掛接音樂派送、建立端點及發布 Audio Sink 服務；原廠收到訊息後確實呼叫新元件，完成能力回覆、錯誤設定拒絕、設定／開始串流、媒體回呼、斷線與重新設定。小回覆經原廠傳送配置與佇列保存。尚未完成啟動時不改主程式，稍後完成啟動可由同一元件開始；最後一處核對失敗也沒有先改前面的資料。端點被占用、鎖失敗及服務已啟用的控制案例保留錯誤狀態。</p><p><strong>這是離線整合，還沒有原機播放或 App。</strong>媒體封包已送達新元件，但目前明確丟棄；連線世代／接收上限檢查尚未接上解碼與音訊工作。主程式可寫權限及快取同步由模擬環境提供，唯讀控制會阻擋修改，因此不能推論真機可安全掛接。核心、無線連線資料、磁碟後端及目前語音設定也是測試資料；實機載入接受、回呼程式存活、語音重新載入／安全停止、真正排程、喇叭及 App 菜單仍待驗證。新語音封裝僅供離線研究，沒有傳入導航機。下一步優先接通媒體檢查、SBC 解碼與音訊工作。證據：<code>native-music-loaded-emulation.json</code>。</p>'
            capabilities = research.get('native_app_music',{}).get('static_findings',{}).get('avdtp_capabilities',{})
            if capabilities.get('all_passed'):
                document += '<p>新離線結果：原廠 AVDTP 能力查詢與回覆程式的 '+str(capabilities['case_count'])+' 個案例通過。未啟用端點會拒絕查詢，只開 SDP 也仍拒絕；提供合成端點與 SBC 資料後，原指令能產生音樂能力回覆，也能回覆另一組已配置資料。這縮小了協定回覆的缺口，但沒有執行真正端點註冊。資料由測試提供，不能據此宣稱原機已有 SBC 接收／解碼能力、手機已直連或播放器已安裝。下一步追端點註冊、原廠菜單 dispatch 與元件載入接受條件。<a href="https://www.bluetooth.com/specifications/specs/advanced-audio-distribution-profile/">Bluetooth SIG A2DP 規格入口</a>。本機證據：<code>avdtp-capabilities-emulation.json</code>。</p>'
            control = research.get('native_app_music',{}).get('static_findings',{}).get('avdtp_control',{})
            if control.get('all_passed'):
                document += '<p>原生串流控制再完成 '+str(control['case_count'])+' 個離線案例：原廠設定解析、內部媒體通道保留及回呼跳板已執行。合成端點接受 SBC 設定後進入 configured；Open 回覆接受後仍停在等待媒體連線，沒有假裝已完成 L2CAP。另一組明確提供 ready 狀態的控制案例才測開始與暫停，因此不是已接通的完整連線。</p><p>播放器必須自行驗證設定與啟動條件。受測 core 會先接受設定，再通知 App，App 回傳錯誤也不會撤回已送出的接受；只有傳輸項目而無 codec、或替換 codec ID 的測試資料也可能被 core 接受。異常狀態下 Start 即使回覆拒絕，若拒絕訊息送出成功，受測程式仍會更新狀態並通知開始回呼。因此不能只憑回呼開啟解碼，需另外確認 SBC 配置、真實媒體連線與 pending 狀態。這些是合成狀態下執行原指令的結果，尚未在實機重現。</p>'
            lifecycle = research.get('native_app_music',{}).get('static_findings',{}).get('avdtp_lifecycle',{})
            if lifecycle.get('all_passed'):
                document += '<p><strong>原廠媒體連線流程已在同一模擬系統中執行。</strong>新增 '+str(lifecycle['case_count'])+' 個離線案例，原廠程式依序完成設定、Open、媒體連線與雙向配置，再進入 ready／streaming，交出封包；暫停、恢復、斷線清理與重新連線也由原指令處理。沒有手動把端點狀態改成就緒。已註冊端點的起始狀態、已建立的信令連線與傳輸回覆仍由測試提供，尚未接上手機或喇叭。4 KiB 封包案例只驗證緩衝邊界，不能當成實機協商大小。</p><p>新增控制也確認：異常的提前 Start 雖被拒絕，仍可能把狀態設為 streaming，並以成功狀態交出媒體封包，Open pending 尚未清除。因此播放器需要同時檢查配置、通道就緒、待完成操作與連線世代，不能只看成功回呼。此為合成事件下的原指令結果，不是實機漏洞或已完成音樂播放。證據：<code>avdtp-lifecycle-emulation.json</code>。</p>'
            menu_action = research.get('native_app_music',{}).get('static_findings',{}).get('native_music_menu_action',{})
            if menu_action.get('all_passed'):
                document += '<p><strong>菜單按鈕的呼叫方式已離線驗證。</strong>'+str(menu_action['case_count'])+' 個案例執行原廠 16-byte 回呼資料建立、複製／移轉／釋放邊界，以及 virtual slot 60 的間接呼叫，能走到開啟音訊混音頁的原動作。實際頁面物件、按鈕事件佇列和螢幕尚未執行；頁面配置、建構與發布仍被攔截為測試邊界，沒有生成假的畫面或安裝入口。<strong>尚未找到任意自製 App 的註冊／安裝方式</strong>。證據：<code>native-music-menu-action-emulation.json</code>。</p>'
            music_policy = research.get('native_app_music',{}).get('static_findings',{}).get('native_music_policy',{})
            if music_policy.get('all_passed'):
                document += '<p><strong>新增 ARMv6 串流檢查原型，程式碼 '+str(music_policy['compiled_policy_code_bytes'])+' bytes。</strong>'+str(music_policy['case_count'])+' 個離線案例通過，涵蓋 128 種支援的 SBC 設定：44.1／48 kHz、各聲道模式與區塊／子頻帶／配置選擇。只有本原型支援的傳輸與 SBC 項目會被接受；缺少 codec、多重選擇、未知服務與不支援格式會拒絕，失敗不改寫輸出資料。這是本原型的支援範圍，不能當成整個 SBC 規格的限制。</p><p>已在同一模擬系統中使用原廠狀態測試編譯後的檢查：正常串流可通過，提前 Start 造成的成功媒體回呼仍被擋下。另驗證暫停／未就緒、codec 或端點不符、重連後舊世代、封包過大，以及音框與已協商格式／bitpool 不符。接收大小使用本機接收上限，與對端接收上限分開；音框長度與格式檢查後仍須由解碼器驗證 CRC。</p><p><strong>這組 208 案例由測試程式呼叫，未安裝原廠設定入口或媒體回呼，也未啟用實機 A2DP。</strong>目前由測試程式在原廠流程前後呼叫檢查；真正的端點註冊、加鎖取得一致狀態、回呼世代歸屬與解碼／輸出工作整合仍待完成。沒有原機 App、手機直連或喇叭實測證據。證據：<code>native-music-policy-emulation.json</code>。</p>'
            music_gate = research.get('native_app_music',{}).get('static_findings',{}).get('native_music_configuration_gate',{})
            if music_gate.get('all_passed'):
                document += '<p><strong>最新：設定攔截原型已編譯並呼叫原廠回覆函式。</strong>程式碼 '+str(music_gate['compiled_code_bytes'])+' bytes，另有 12 bytes 的端點接管紀錄；'+str(music_gate['case_count'])+' 個離線案例通過。對原型接管的端點，不支援的 codec、缺項、重複服務、錯誤長度、格式或超出宣告能力的設定，會先由原廠拒絕函式回覆，不會先接受或保留媒體通道。128 種支援設定交回未修改的原廠 handler；同一模擬系統繼續完成 Open、媒體連線、Start、收包與斷線後解除接管。一般未接管端點的設定及重新配置流程與原廠結果相同。</p><p>模擬另確認：原廠接受訊息若傳送失敗，仍可能留下已設定狀態、沒有回呼，handler 回傳 0 也不能證明訊息送達。需要另設恢復流程。接管端點目前明確拒絕 Reconfigure，尚未支援配置中途替換；檢查也只接受本原型支援且已宣告的 SBC 子集。協定服務／錯誤常數比對 <a href="https://github.com/bluez/bluez/blob/665f35180ff20ceb994f857bd11f1b31742faf80/profiles/audio/avdtp.h">固定版本 BlueZ 原始標頭</a>，並未假設 Garmin 使用 BlueZ API。</p><p><strong>這是由模擬器選擇入口執行的編譯原型，尚未安裝原生派送掛接。</strong>端點、能力資料與信令連線的起始狀態仍是測試資料，真正 SDP／SEP 註冊、能力指標配置與存活、原廠鎖／元件保留、媒體回呼整合及播放器菜單／可接受載入方式仍待完成。沒有實機手機直連或 App／喇叭的新驗證。證據：<code>native-music-gate-emulation.json</code>。</p>'
            music_endpoint = research.get('native_app_music',{}).get('static_findings',{}).get('native_music_endpoint',{})
            if music_endpoint.get('all_passed'):
                document += '<p><strong>最新：自製端點原型已由編譯程式建立，原廠流程能讀取它。</strong>程式碼 '+str(music_endpoint['compiled_code_bytes'])+' bytes，另有 28 bytes 的持續紀錄；'+str(music_endpoint['case_count'])+' 個離線案例通過。從原廠 AVDTP／SDP 初始化後的未註冊狀態出發，自製程式使用原廠鎖入口，填入自己的 SBC 能力與回呼、接管設定檢查，再分開呼叫原廠 Audio Sink 服務啟用。原廠 Discover 從空列表變成列出音訊接收端，原廠 SDP 屬性查詢回傳 Audio Sink（0x110B），能力序列化與設定／Open／媒體完成／收包／斷線重連也已執行。端點資料由編譯程式產生；這次沒有在測試起點先提供已註冊端點。</p><p>另發現原廠 GetCapabilities 固定宣告標頭壓縮（HeaderCompression），目前原型沒有實作它。新能力入口只對自己管理的端點移除這項宣告，仍呼叫原廠序列化函式；一般未接管端點及已協商設定查詢保持原流程。已核對六參數呼叫、第三端點與 transaction 15、無效請求／舊所有者／配置失敗及 SDP 查詢資料。原廠鎖解除失敗時，端點或服務可能已啟用；原型保留不確定狀態，不能當成已回復或可以卸載。</p><p><strong>這是使用精確私有資料結構的自製註冊原型，沒有找到或證明原廠註冊 API，也未裝到 Garmin。</strong>原廠鎖／核心物件、PSM 註冊與信令連線的傳輸仍是模擬邊界，實機排程／服務獨占、程式與回呼存活尚未驗證。能力與設定入口仍由模擬器選擇，真正訊息派送掛接、可接受的元件載入及 App 菜單、解碼／喇叭與手機連線仍待完成；目前沒有卸載／取消註冊流程。證據：<code>native-music-endpoint-emulation.json</code>。</p>'
            music_dispatch = research.get('native_app_music',{}).get('static_findings',{}).get('native_music_dispatch',{})
            if music_dispatch.get('all_passed'):
                document += '<p><strong>上一輪：原廠收到完整訊息後，已能在模擬中自行選擇編譯後的入口。</strong>'+str(music_dispatch['case_count'])+' 個離線案例執行原廠 L2CAP 接收、訊息解析、方法表選取及 ARM／Thumb 呼叫；不是由測試程式逐則指定能力／設定函式。模擬副本替換四項方法表指標，另修正兩處長度／範圍指令，合計 22 bytes 的欄位。正常設定、Open、媒體完成、Start、收包、暫停、斷線與重連已在同一系統中執行；兩段設定訊息由原廠重組後進入檢查，錯誤的交易編號則拒絕，回呼結束後重組緩衝由原廠釋放。</p><p>測試確認，原派送器把 handler 的資料長度縮成 8 位元。有效的 12 bytes 設定後面附加 256 bytes 時，只有換方法表的版本仍把長度當成 12 並接受；保留完整長度後能拒絕。另有未支援指令會通過原範圍檢查，但方法表只有十項，會讀到後方文字作為位址；模擬在跳轉前停止，縮小範圍的版本避免這個讀取。這些是特定備份程式與合成訊息的結果，沒有造成或證明實機崩潰。長度修正對其他原廠 handler 的完整回歸仍待研究。</p><p><strong>此為明確修改的模擬副本，原備份與實機韌體未改，也不是可刷入版本。</strong>編譯元件仍位在合成配置位址，真正配置／啟動、韌體接受、App 菜單與媒體檢查／解碼工作尚未接通。原廠未支援指令的資料在傳送函式入口擷取為 <code>1000</code>；與 <a href="https://github.com/bluez/bluez/blob/665f35180ff20ceb994f857bd11f1b31742faf80/profiles/audio/avdtp.c#L68">固定版本 BlueZ 的 GeneralReject 定義</a> 當時仍有格式疑問；本輪傳送與回覆修正結果列於下方，手機相容性仍待實測。主程式後方的 484 bytes 會搬到例外向量區，已確認不能當作空白區塞入新程式。證據：<code>native-music-dispatch-emulation.json</code>。</p>'
            music_send = research.get('native_app_music',{}).get('static_findings',{}).get('native_l2cap_send',{})
            music_reply = research.get('native_app_music',{}).get('static_findings',{}).get('native_music_reply',{})
            if music_send.get('all_passed'):
                document += '<p><strong>後續確認：原廠傳送佇列不會修正上述回覆。</strong>'+str(music_send['case_count'])+' 個離線案例使用有效動態通道的測試資料，執行原廠 L2CAP 傳送、紀錄配置、佇列串接及排程包裝；<code>1000</code> 原樣保留在佇列。小封包被複製到原廠傳送紀錄中，兩次回覆在呼叫堆疊重用後仍各自保存，已超過只在傳送入口擷取的範圍。複製服務、鎖與作業提交仍由模擬環境提供；尚未執行下層無線傳送，佇列插入與回傳長度都不能當作手機已收到。證據：<code>native-l2cap-send-emulation.json</code>。</p>'
            if music_reply.get('all_passed'):
                document += '<p><strong>最新：未支援指令的 GeneralReject 回覆修正原型已離線通過。</strong>'+str(music_reply['case_count'])+' 個案例驗證 5 種未支援指令、全部 16 個交易編號、原廠十項指令的接受／拒絕回覆、後續設定、短包及傳送失敗。新回覆保留原指令與交易編號，使用 type 1；格式比對 <a href="https://github.com/bluez/bluez/blob/665f35180ff20ceb994f857bd11f1b31742faf80/profiles/audio/avdtp.c#L1396">固定版本 BlueZ 的未支援指令處理</a>，並未假設 Garmin 使用 BlueZ。正常指令經搬移的 16 bytes 原廠前置指令返回原處理流程，回覆內容與對照組相同。入口轉接會保留四個暫存器參數與堆疊，第五參數仍依原方式讀取。</p><p>原型程式 '+str(music_reply['compiled_code_bytes'])+' bytes，這次另替換 18 bytes 欄位；加上先前派送修正，<strong>模擬副本共八處、40 bytes 欄位變更</strong>，其餘主程式維持原資料。原廠傳送、配置及佇列流程確實執行，作業排程提交與無線硬體仍是測試邊界。<strong>不是可載入或可刷入版本，也尚未驗證手機相容性。</strong>實際記憶體配置／啟動、可接受的載入方式、媒體檢查與解碼／喇叭輸出、App 菜單仍待接通；原廠收到 type 1 回覆的處理亦尚未修正。證據：<code>native-music-reply-emulation.json</code>。</p>'
            voice_selection = research.get('native_app_music',{}).get('static_findings',{}).get('native_voice_selection',{})
            if voice_selection.get('all_passed'):
                document += '<h3>前輪：原廠選取流程能在模擬中載入自製元件</h3><p>原廠掃描、語音資料檢查與排序登錄的 10 個離線案例通過；再由原廠選取程式查找元件、掛載內部檔案系統，透過原檔案讀取回呼交給載入器。'+str(voice_selection['case_count'])+' 個選取／載入案例通過。已編譯的自製元件在原廠 3 MiB 保留區內執行，使用約 2.35 MiB RAM，原載入器回傳 11；40 個原語音介面與直接載入對照相同，12 個私有介面已初始化。這次沒有呼叫音樂工作或顯示新頁面。</p><p>重新封裝時曾出現獨立解析正確、原廠讀回不同的情況。改為維持 DLL 連續區塊、移動後方簽章與結尾資料的配置後，原廠完整讀回的 2,353,068 bytes 已逐 byte 符合；其他檔案內容保留，舊版本已排除。這是特定測試封裝的結果，不能推論整個 Garmin 檔案系統存在缺陷。</p><p><strong>仍是離線載入證據，封裝僅供離線研究，尚未安裝到導航機。</strong>外層目錄／檔案映射、掛載包裝、平台快取、核心與診斷畫面仍由測試提供。未修改的原廠語言相容性檢查會產生代碼 409；提示提交在模擬中攔截，後續原流程繼續載入，尚未釐清真機相容性條件。舊校驗值及清空簽章也在此路徑載入，但不能證明其他地方沒有簽章檢查或實機會接受。真正外層掛載、完整封裝標頭語意、元件存活、App 菜單、手機直接音樂及喇叭仍待驗證。既有音樂端點／回覆原型仍在合成配置位置，尚未連入這個保留區。證據：<code>native-voice-registry-emulation.json</code>、<code>native-voice-package-read-emulation.json</code>、<code>native-voice-selection-emulation.json</code>。</p>'
            voice_outer = research.get('native_app_music',{}).get('static_findings',{}).get('native_voice_outer',{})
            voice_compatibility = research.get('native_app_music',{}).get('static_findings',{}).get('native_voice_compatibility',{})
            if voice_outer.get('all_passed') and voice_compatibility.get('all_passed'):
                document += '<h3>前輪：完整外層掛載與語音相容性檢查</h3><p><strong>'+str(voice_outer['case_count'])+' 個外層流程案例通過。</strong>這次執行原廠通用檔案 API、區域映射、讀取、解除、完整啟用包裝及路徑快取，再由原廠內部檔案系統與選取程式載入元件。三組原語音都能登錄；原語音與自製元件的載入結果、40 個原介面與直接載入對照相同，自製元件的 12 個私有介面也初始化。沒有改寫這些原廠函式。底層目錄列舉、磁碟驅動的開啟／讀取／關閉、檔案表、記憶體與核心仍由測試提供；還沒有使用真正 FAT 或板上驅動。</p><p>原廠控制涵蓋第二次開啟的唯讀回退、已占用映射、延後開啟、開啟失敗與 32 槽滿載。已登錄的區域再次綁定會回已占用狀態；因此驗證完整讀回後，先用原廠流程解除暫存掛載，再讓選取程式重新建立映射。初始化結束後核對檔案、路徑快取與暫存物件釋放；此時尚未啟動音樂工作，不能把這項清理當作有工作／回呼時可以安全卸載。</p><p><strong>'+str(voice_compatibility['case_count'])+' 個原廠相容性案例通過。</strong>原檢查依「目前語音」快取查找語音 ID 與版本，再比對 94 項原廠對照資料。先前空快取會產生代碼 409；提供原語音的選取快取後，未修改的原檢查通過、走成功分支並正常載入，自製元件同樣通過。原版 Mei-Ling 的 1.30 門檻及較低／相等／較高版本、未知 ID 與錄音語音類型控制已核對。</p><p><strong>目前語音快取仍是測試資料，真正設定初始化、磁碟驅動與實機接受尚未驗證。</strong>候選設定函式會提交持久儲存；完整初始化與快取更新尚未接通。此輪沒有安裝導航機、啟動原生音樂端點、建立 App 選單、連手機或播放喇叭。接著將既有音樂端點／設定檢查／回覆原型連入這個元件保留區，再處理實際載入條件、媒體回呼與介面。證據：<code>native-voice-outer-emulation.json</code>、<code>native-voice-compatibility-emulation.json</code>。</p>'
            availability = research.get('attended_testing',{})
            if availability.get('waiting_for_user_return'):
                document += '<p>使用者目前不在現場；現在只繼續本機離線研究，不發出來電、不播放聲音、不修改導航機。此階段不需要 USB 或持續藍牙，可正常關機。等使用者回來通知後，再安排必要的實機確認。</p>'
            music_ui = research.get('native_app_music',{}).get('static_findings',{}).get('native_music_ui',{})
            if music_ui.get('bounded_function_count'):
                document += '<p>較早的音訊設定／混音頁研究，方法表分別有 66／57 項，其中 10 個指標來自條件式程式區；先前僅列 24 項的候選表在這裡並不完整。已定位音訊設定的 virtual slot 60：selector 0 配置原廠混音頁、呼叫其建構與頁面提交函式；八個有界流程已盤點。最新另復原一般圖示清單的私有登錄與按下回呼，結果列在報告前方；完整新播放器畫面、事件生命週期及可接受的 App 載入仍待完成。</p>'
            document += '</div>'
        if research.get('native_android_auto', {}).get('USB_hub_power_plan'):
            document += '<div class="card"><h2>現場診斷與單一 microUSB 孔的供電問題</h2><p>使用者提供系統／電源／USB、版本資訊、記憶卡、音訊、TV 與藍牙測試頁，共七頁。版本頁的 More 為灰色，藍牙頁之後是觸控與顯色測試；目前這組選單未見可操作的 USB 主機切換。這是已查看頁面的結果，不能推論整個韌體沒有主機功能。USB TypeB 是本次線材分類；ID Volts 3.29V 和 500mA 輸入限制不能當成已量測的 VBUS 輸出能力。RAM／ROM 的 Ready、Voice／ASR 的 Checking... 都不是測試通過。</p><p><strong>一般有外接電源的 USB Hub 供電給下游手機，不能直接當成 Garmin 邊充電邊做主機的方案。</strong>標準 USB 2.0 上游埠不向主機回送電流；Hub 也不會把裝置模式的 Garmin 變成主機。主機端還要有 Hub 辨識、下游連接埠供電／重設／狀態與位址管理。現有 AOA 原型沒有 Hub 驅動，尚未接上實機 USB 主機後端。<a href="https://e2e.ti.com/cfs-file/__key/communityserver-discussions-components-files/196/usb_5F00_20.pdf">USB 2.0 §7.2.1／§7.2.1.2</a>、<a href="https://www.ti.com/lit/pdf/slva049">TI USB 供電說明</a>。</p><div class="scroll"><table><thead><tr><th>研究路徑</th><th>供電安排</th><th>尚需確認</th></tr></thead><tbody><tr><td>先用 Garmin 內建電池、直接 OTG 接手機</td><td>短時間把 Garmin 充電問題分開研究</td><td>Garmin 真正主機模式、VBUS 輸出、驅動與接收端；目前還不能直接試 Android Auto</td></tr><tr><td>內建電池、OTG、有外接電源的 Hub、手機</td><td>Hub 外接電源負責下游手機；Garmin 仍靠電池</td><td>原機主機能力、上游 VBUS／Hub 偵測、Hub 驅動及手機重新列舉；Hub 不能替代這些功能</td></tr><tr><td>同一 microUSB 孔邊充電邊連手機</td><td>需受支援的 ACA 或已核對的板上獨立供電路徑</td><td>Garmin 的 ID 偵測、充電與角色切換、電源電路和防回灌；一般 Y 線或 USB-C PD Hub 標示不等於相容</td></tr></tbody></table></div><p>USB-IF 有 ACA 充電配件的規範，但本台是否支援仍未知。原廠車架另有車充與攝影機接口；使用者目前沒有車架，而且手冊的分開標示不能證明可直接接手機或多出一個通用 USB 主機埠。接線與供電路徑核對前，尚未要求購買或連接新配件。<a href="https://www.usb.org/sites/default/files/USB_Battery_Charging_1.2.pdf">USB-IF ACA 測試文件</a>、<a href="https://download.garmin.com/tw/download/manuals/nuvi2555_2565T_2565RT_TW_0B.pdf">原廠台灣手冊第 18／133–135 頁</a>。</p><p>Audio Test 的 INCOMPATIBLE AUDIO 位於 Current Phrase 欄位，不能由此判定 WAV 播放或喇叭故障。TV Test 的 NTSC 欄位與零訊號鎖定也不是外部影像已成功的證據。這組診斷選單盤點未執行記憶卡寫入、射頻、音訊或電氣測試；後來的一般模式藍牙音訊實測另列在前方。</p></div>'
        if research.get('native_android_auto', {}).get('requested'):
            document += '<div class="card"><h2>後續研究：GarminOS 內建 Android Auto 接收端</h2><p><strong>依使用者指示繼續研究，goal 保持 active，不標記完成。</strong>Android App 在手機上執行，GarminOS 原生程式負責接收畫面、送回觸控及播放音訊。已保存並核對 OpenAuto／aasdk 固定 commit 的 376 個來源檔，並對精確台灣 8.00 韌體解析七個 GUI 候選類別與十個有界函式流程。這是移植前的介面研究，目前没有可安裝的 Android Auto 版本。<a href="https://github.com/f1xpl/aasdk">接收端原始碼</a>、<a href="https://developer.android.com/training/cars/platforms/android-auto">Google 平台說明</a>。</p><p>有線路徑要求 Garmin 提供 USB 主機角色及 AOA 控制／bulk 傳輸；已實測的 USB 隨身碟模式屬裝置角色。STA2064 原廠資料列 USB OTG，但本台的 VBUS 供電、ID 接線和主機驅動尚未驗證。無線 Android Auto 也需要 Wi-Fi 路徑，現有 HFP／SPP 藍牙連線不足以證明可以傳送投影畫面；本台 Wi-Fi 硬體尚未確認。<a href="https://developer.android.com/develop/connectivity/usb">USB 角色</a>、<a href="https://support.google.com/androidauto/answer/6348019?hl=en">無線需求</a>。</p><p>固定版本接收端使用 H.264／AVC，畫面設定為 800×480 起、30 或 60fps；這是該版本的設定，不能當作目前手機永遠不接受其他解析度的證據。本台螢幕是 480×272，需縮放與反向觸控座標映射。STA2064 資料表列的是 JPEG 解碼器；原機 MJPEG 回放不能證明有 H.264 解碼能力。尚未找到可用 H.264 路徑，也沒有測得實機解碼效能。<a href="https://github.com/f1xpl/openauto/blob/aa90412bf93b5a5078495ea85ac9270c6297d369/src/autoapp/Projection/OMXVideoOutput.cpp">影片後端</a>、<a href="https://mm.digikey.com/Volume0/opasdata/d220001/medias/docus/581/STA2064.pdf">ST 原始資料</a>。</p><p>六個新鮮離線案例讓原廠觸控線條測試頁真正執行事件處理、矩形讀取、原地紀錄建構及基底處理；按下／拖曳會保留 X、Y、其他兩個欄位與動作值，未知動作不新增紀錄。合成物件／事件／預配置容器和記錄 buffer 的 canary 均完整，原指令未改。診斷輸出及重畫排程仍是測試邊界；抬起事件、真正觸控驅動與新 App 入口未執行，不能當成已完成觸控投影。</p><p>音訊通道使用 PCM：該版本的媒體為雙聲道 48kHz／16-bit，提示／語音為單聲道 16kHz。可評估沿用已驗證的原生 PCM 轉換和輸出流程，不需要在這個通道再做 SBC 解碼；真實喇叭與導航語音共存仍待驗證。診斷頁顯示 128MB，但目前可用 heap 與 CPU 時脈尚未量測。現有保留語音元件的三 MiB 僅是一個配置範圍，依版本剩約 0.55～1.07 MiB；一張 800×480 YUV420 畫面約 563 KiB，尚需參考畫面、縮放輸出與 TLS。這只是配置估算，並非整台 RAM 上限或測得的解碼需求。恢復此項研究後，繼續追 USB 主機角色與畫面輸出，並評估 ARMv6 H.264 解碼、協定移植及原生 UI。<a href="https://github.com/f1xpl/openauto/blob/aa90412bf93b5a5078495ea85ac9270c6297d369/src/autoapp/Service/ServiceFactory.cpp">音訊與畫面設定來源</a>。</p></div>'
        if research.get('native_android_auto', {}).get('framing_prototype'):
            framing=research['native_android_auto']['framing_prototype']
            document += '<div class="card"><h2>原生封包與明文重組：資料流程已能離線串接</h2><p>新增不依賴 Linux 執行環境的 ARMv6 封包解析、單一封包編碼及明文訊息重組核心，程式碼 '+e(str(framing['code_bytes']))+' bytes；解析與重組狀態各 '+e(str(framing['frame_context_bytes']))+' bytes，資料工作區由呼叫端提供。'+e(str(framing['offline_cases_passed']))+' 個新鮮離線案例通過，涵蓋標頭及內容的不同切分位置、一次收到多個封包、未讀資料保留、取消、重複／舊序號與錯誤總長度。模擬工作區驗證至 65,535 bytes 封包內容與 256 KiB 明文訊息，原碼及邊界守護均完整；這些大小尚未在 Garmin 上配置或量測效能。</p><p>格式依固定版本 <a href="https://github.com/f1xpl/aasdk/blob/046b3b381595509d0939fa84b14a90978f46ff63/src/Messenger/MessageOutStream.cpp">aasdk 傳送流程</a>與 <a href="https://github.com/f1xpl/aasdk/blob/046b3b381595509d0939fa84b14a90978f46ff63/src/Messenger/MessageInStream.cpp">接收流程</a>建立，保留來源及 GPLv3-or-later 授權。該舊版本在訊息剛好達 16 KiB 時可能送空的最後分段，新原型已涵蓋；目前 Pixel 的實際格式、擴充旗標及相容性仍待驗證。明文重組另加總長度、連續序號與分段數量限制，錯誤會停止該狀態，需新連線重新開始。</p><p><strong>加密封包目前只保留原始內容，沒有 TLS 解密或認證。</strong>第一段標示的訊息總長度屬明文，不能拿來核對密文長度；明文組裝器會拒絕加密資料，避免把它當成可播放或顯示的內容。已在同一模擬系統串起握手、配件配置、雙向傳輸及封包重組，並核對編碼後經短寫入的資料逐 byte 正確。串接流程與控制器回覆由 Python 測試提供，目前尚無原生連續派送迴圈、完整傳送分段器或真正手機。</p><p><strong>Android Auto 尚未在 GarminOS 執行。</strong>接著需要真正 TLS／通道／Protobuf、主機與供電入口、H.264、畫面及 App 整合。本輪未操作 USB／藍牙或播放聲音；進度維持約 31%，原生 App／直接音樂及延後的 Google Maps 仍保留。</p></div>'
        if research.get('native_android_auto', {}).get('USB_role_helper_analysis'):
            role=research['native_android_auto']['USB_role_helper_analysis']
            document += '<div class="card"><h2>USB 主機入口查找：辨識電氣測試及未知擴充控制</h2><p>擴大到三個啟動載入區域的兩種位址載入方式，十個 Thumb 引用已由十三段有界函式流程核對。十七個只看數值像 USB 位址的原始資料仍未全部分類；目前分析沒有涵蓋所有位址組合、間接呼叫或內嵌元件，不能推論整台沒有 USB 主機功能。</p><p>原廠 0x1BB068 的四種選項分別對應 J、K、SE0 NAK 與測試封包。它傳送固定 53 bytes 電氣測試圖樣，與 <a href="https://raw.githubusercontent.com/torvalds/linux/v6.12/drivers/usb/musb/musb_core.c">Linux 上游 MUSB 測試圖樣</a>逐 byte 相同；此流程不設定 force-host 位元。它用到的部分狀態位元數值也會出現在 <a href="https://raw.githubusercontent.com/torvalds/linux/v6.12/drivers/usb/musb/musb_host.c">主機控制傳輸</a>，但角色與資料內容不同，所以不能據此稱已找到 Android Auto 握手入口。</p><p>另一段程式操作 0x10200204 的 32-bit 擴充控制與另一個開關，短暫開啟後進行兩次狀態取樣，再關閉 bit14。'+e(str(role['offline_cases_passed']))+' 個新鮮離線案例驗證相關欄位、選擇器、原 IRQ 保存／恢復及測試封包；時間與狀態由測試提供，沒有執行真正電氣測試。<strong>取樣程式不會完整還原先前擴充設定，而且原時間等待迴圈沒有局部次數上限；目前不適合直接在原機呼叫。</strong>該擴充暫存器及三個周邊區域的實體用途仍未知，不能直接當作 UART、ADC、DMA 或 VBUS 開關。</p><p><strong>仍未確認實際 USB 主機角色、供電或手機傳輸；本輪未操作實機或藍牙。</strong>這項結果縮小下一步的查找範圍，接著繼續追板上主機／供電入口，並建立資料分段、TLS 及投影通道。進度維持約 31%，原生 App／直接音樂研究仍保留。</p></div>'
        if research.get('native_android_auto', {}).get('AOA_bulk_prototype'):
            bulk=research['native_android_auto']['AOA_bulk_prototype']
            document += '<div class="card"><h2>雙向傳輸原型：收送緩衝區與停止流程已離線驗證</h2><p>新增 ARMv6 原型在同一模擬系統串起握手、配件介面選擇、配置及雙向傳輸，先前兩段程式保留。'+e(str(bulk['offline_cases_passed']))+' 個新鮮離線案例通過；程式碼 '+e(str(bulk['code_bytes']))+' bytes，每個連線狀態 '+e(str(bulk['context_bytes']))+' bytes，其中收送各有獨立 4 KiB 緩衝區。可同時收送並以任一順序回報完成；待送資料先複製，來源變動不會改到已提交內容。</p><p>成功短寫入後只送剩餘內容；收到較短或空回覆均有效，但未讀資料會阻止再次使用接收緩衝區。取消、斷線、錯誤或逾時後停止新增傳輸，仍保留每個在途緩衝區，直到其對應終結回覆。已核對舊票號、重複回覆、雙向逾時與時鐘繞回，並修正「讀到 2 bytes」和忙碌狀態可能混淆的介面。非同步取消的終結回覆模型可參考 <a href="https://libusb.sourceforge.io/api-1.0/group__libusb__asyncio.html">libusb 官方說明</a>；這是自製介面的契約，Garmin 控制器實際做法仍待確認。</p><p><strong>目前只有模擬器中的資料傳輸；尚未傳送真正的 USB 資料，也未在 GarminOS 執行。</strong>接收資料寫入與完成事件均由測試提供。真正控制器、DMA／快取、USB 短封包終結策略、主機供電、手機連線、TLS、投影畫面及實機音訊尚未接入。本輪未操作 USB／藍牙或播放聲音；研究進度維持約 31%，下一步接實際主機入口並完成資料分段與協定通道。</p></div>'
        if research.get('native_android_auto', {}).get('AOA_configuration_prototype'):
            aoa_config=research['native_android_auto']['AOA_configuration_prototype']
            document += '<div class="card"><h2>手機 USB 介面與配置：配件通道已能正確選擇</h2><p>新增 ARMv6 原型完成有界描述資料解析及 SET_CONFIGURATION 控制流程，程式碼 '+e(str(aoa_config['code_bytes']))+' bytes、每個配置狀態 '+e(str(aoa_config['context_bytes']))+' bytes。'+e(str(aoa_config['offline_cases_passed']))+' 個新鮮離線案例通過：配件介面可以排在 ADB 後面，輸入／輸出端點順序可以交換，音訊的其他介面與非預設 alternate setting 會略過。全速與高速封包大小分別驗證，配置值取自描述資料，未固定寫成 1。介面識別依固定版本的 <a href="https://android.googlesource.com/kernel/common/+/d2101e7384ec08fe13cc9faf5eccaa6a84048ac9/drivers/usb/gadget/function/f_accessory.c">Android 官方配件來源</a>；這份較舊核心來源不代表已確認目前 Pixel 的 USB 描述資料。</p><p>錯誤長度、描述資料越界、缺少／重複端點、兩個候選配件介面、配置值 0、介面數量不符和僅有 ADB 等控制均拒絕。解析失敗保留輸出不變；配置請求仍須等控制器回報完成或取消確認才能回收借用的 setup 資料。已在同一模擬系統串起先前握手、重新出現、選擇介面與設定配置，原握手程式及父狀態保留。</p><p><strong>目前完成的是離線解析與配置原型，尚未傳送真正的 bulk 資料，也沒有 Garmin 主機／手機實測。</strong>描述資料與完成事件皆由測試提供；實體連接埠綁定、介面使用權、USB 主機／VBUS、真正的控制傳輸和雙向資料仍待接入。雙向傳輸及停止／斷線原型已另行完成離線驗證，接著仍需真正主機入口與 TLS／投影通道；目前沒有可安裝 Android Auto 或 App。</p><p>原廠韌體的主機搜尋另找到十五個以同一組 Thumb 指令建立 USB 位址的線索，分析只走到各自第一個分支／呼叫；此範圍尚未找到主機切換證據。另確認 0x6F058C 的數值 0x10200080 是 ARM EORNE 指令編碼，<strong>不是 USB 暫存器指標</strong>。這是排除誤判的結果，不能推論其他指令形式、間接呼叫或元件中不存在主機功能。本輪未操作或改寫實機，研究仍持續。</p></div>'
        if research.get('native_android_auto', {}).get('AOA_negotiation_prototype'):
            aoa = research['native_android_auto']['AOA_negotiation_prototype']
            document += '<div class="card"><h2>原生 AOA 握手原型：第一段手機連線流程已能離線執行</h2><p>已新增不依賴 Linux 執行環境的 ARMv6 程式，程式碼 ' + e(str(aoa['code_bytes'])) + ' bytes、每個連線狀態 ' + e(str(aoa['context_bytes'])) + ' bytes。在 ARM1176 模擬器中執行編譯後的程式，' + e(str(aoa['offline_cases_passed'])) + ' 個測試通過：查詢協定版本、依序傳送六項裝置資訊、啟動配件模式，並等待手機以配件身分重新出現。控制請求 51／52／53 的實際封包與獨立參考一致；支援已公布的協定 1／2，未支援版本明確停止。<a href="https://source.android.com/docs/core/interaction/accessories/aoa">Google AOA 控制流程</a>、<a href="https://source.android.com/docs/core/interaction/accessories/aoa2">AOA 版本與介面</a>。</p><p>另驗證錯誤／短回覆、舊票號、重複完成、逾時、時鐘繞圈、UTF-8 與 256-byte 字串邊界。程式持有傳輸資料；<strong>逾時或取消不會立刻回收控制器可能仍在使用的緩衝區</strong>，必須等完成回呼或取消確認才釋放。單一工作者、連線世代不重用、同一實體連接埠的辨識，以及正確的 DMA／取消確認仍是控制器介面必須履行的條件。</p><p><strong>這是新增程式的離線原型，尚未接上 Garmin 的 USB 主機驅動。</strong>測試用 Python 提供傳輸完成及重新列舉事件；辨識配件 VID／PID 不等於已選好 bulk 端點，更不代表 Android Auto 已連線。介面／端點解析與配置的後續結果見上方；接下來需接上主機控制器及雙向資料傳輸，再建立 TLS／投影通道、影片、觸控與原生 App 入口。目前沒有實機手機連線或安裝候選，本輪沒有改寫 Garmin。</p><p>現有 USB-A → microUSB 線可以繼續讀取 Garmin 隨身碟；這個研究階段不需要換線或開藍牙。OTG 的問題是在確認將來 Garmin 直接接手機時能否當主機，目前不需使用者更動接線。原機 App／直接音樂／語音共存仍保留，Google Maps 依指示延後，研究保持 active。</p></div>'
        if research.get('native_android_auto', {}).get('USB_controller_peripheral_path'):
            document += '<div class="card"><h2>控制器與控制端點：已驗證的仍是 USB 裝置路徑</h2><p>原廠指令的 22 個新鮮離線案例通過：兩種端點初始化、五種重設／中斷條件、七個控制端點請求，以及八個 FIFO 大小檢查。實際執行原 ARM 位元計算與中斷遮罩保存／還原。高速與全速條件會產生不同的封包大小與 FIFO 配置，並重新建立 Garmin 專用／隨身碟描述資料。這些條件都是合成暫存器值，尚未測真正的中斷或資料吞吐量。</p><p>控制端點執行原廠八位元 FIFO 讀取、請求分派與輸出：GET_DESCRIPTOR 的請求長度 8／18／64 分別讀回正確長度的裝置描述資料；SET_ADDRESS 的 1／42／127 先保存待套用位址，等原完成流程執行才寫入位址。未支援的描述資料類型 6 會進入 stall 分支。真正 USB 回應／狀態階段、所有標準／類別／廠商請求，以及短封包或錯誤封包的處理均未驗證。</p><p>另完成十二個有界 Thumb 流程、三個 ARM 輔助函式及描述資料的六項跳轉表分析。原程式中的 0x10200060 常數在這條初始化路徑用於偏移 2／3／4／6 的 FIFO 配置欄位，沒有操作偏移 0 的 DEVCTL；<strong>不能把這個常數當成已找到主機切換</strong>。暫存器名稱與 MUSB 原始定義的比對仍是推論，實體控制器型號尚未讀出。<a href="https://raw.githubusercontent.com/torvalds/linux/v6.12/drivers/usb/musb/musb_regs.h">Linux MUSB 定義</a>。</p><p><strong>這條流程接收主機送給 Garmin 的控制請求；Android Auto 則需要 Garmin 向手機發送 AOA 請求。</strong>下一步沿控制器角色及驅動註冊繼續追查，並建立具有明確控制器介面的原生 AOA 傳輸原型。FIFO 輸入資料在原讀取指令前逐 byte 放進合成 RAM；中斷確認及可選的核心通知是測試替身，沒有完整模擬硬體 FIFO、索引暫存器或讀取即清除的中斷。本輪沒有實機操作或改寫 Garmin，Android Auto／新 App 仍未安裝，研究保持 active。</p></div>'
        if research.get('native_android_auto', {}).get('USB_transition_and_worker'):
            document += '<div class="card"><h2>USB 主機研究：類型名稱之後的實際動作</h2><p>已找到並串起原廠線材類型變更的判讀、訊息佇列入口、工作程序與接收分支。八個新鮮離線案例執行原廠指令，確認需三次相同候選值才進入穩定狀態；佇列未建立或尚未啟用時不接受變更。原包裝函式忽略底層佇列函式的回傳值，因此呼叫被接受仍不等於訊息已送達。佇列送出、通知與記錄輸出是明列的測試替身，真正排程與硬體處理尚未執行。</p><p>原廠初始化程式與 ARM 清零函式已實際執行，建立四個通道、十四種類型，共 56 組回呼設定。在這份預設表中，<strong>Type-A、USB Audio、USB Ethernet 的開啟／關閉回呼只執行 BX LR 返回</strong>。這些標籤不足以證明 USB 主機或直接音樂功能可用；也不能推論整個韌體的其他路徑都沒有相關驅動。</p><p>另已解析工作程序中的四個跳轉表，以及十六個有界函式流程；十三個局部流程完整，保留四個範圍外／間接出口。三個離線案例執行兩組原廠板上控制向量初始化，實際板號選擇與底層 I/O 用途仍未知，不能把這份向量稱為 USB 主機驅動。</p><p>原函式在位址 0x10200001 切換 bit 0x40 的四個合成暫存器案例通過。其 offset／mask 與 Linux MUSB 的 POWER.SOFTCONN 定義吻合；<strong>這是來源比對的推論，尚未確認實機控制器型號</strong>，不代表已控制 VBUS 供電或切換主機角色。<a href="https://raw.githubusercontent.com/torvalds/linux/v6.12/drivers/usb/musb/musb_regs.h">Linux 原始暫存器定義</a>。</p><p>先前的唯讀 USB 核對中，Garmin 以隨身碟連到 Pi，私下身分與 USB 描述資料一致；本輪離線研究未重新確認即時連線狀態。下一步追真正的主機初始化、控制端點與 bulk 傳輸，再接 Android Auto 協定。目前沒有 Android Auto 安裝包，也未改寫機內檔案；研究目標持續 active。</p></div>'
        if research.get('native_android_auto', {}).get('hardware_diagnostics'):
            document += '<div class="card"><h2>診斷頁與 USB／畫面介面的最新結果</h2><p>使用者已進入本台診斷頁，系統顯示 <strong>nuvi 26xx A V3 4GB 128MB</strong>、軟體 8.00、PCB Version 3。這確認的是原廠頁面的容量標籤，尚未量測可用 heap、實體 RAM 晶片或 CPU 時脈。頁面的 Freq 欄位用途未識別；RAM／ROM Test 的 Ready 表示準備狀態，不能當成測試通過。Voice／ASR 欄位為 Checking...，也尚未取得完成結果。</p><p>當時 USB Device 顯示 USB Type-B、USB ID Volts 為 3.29V，Mount Type 為 No Mount。現有 USB-A → microUSB 線已成功讓 Pi 讀取 Garmin 隨身碟；Pi 是主機，Garmin 是裝置。原廠 USB ID 查詢的十一個新鮮離線案例通過，含 Type-A／Type-B、區間邊界、空隙、錯誤通道及政策重分類。通道紀錄與樣本為合成資料，3.29V 如何換算仍未核對；表內的 USB Audio／Ethernet 名稱也不代表相關驅動已可用。<strong>USB 主機傳輸、VBUS 供電與 AOA 仍待驗證。</strong></p><p>圖形端已把條件式畫面初始化與提交函式連到原 SGA 驅動。八個 ARM 函式完成有界靜態分析，其中七個局部流程解析完成，另一個保留一條範圍外尾端跳轉。原提交函式建立 16-byte 影像描述資料，包含資料指標、寬、高、stride 與格式旗標；格式 4 對應每像素 2 bytes、stride 為寬度乘 2。<strong>RGB 位元排列、實際畫面緩衝區與螢幕呈現尚未確認。</strong>另外找到旗標 0x200 的一個分支只執行 BX LR 返回，不能把它視為可工作的軟體繪圖器。</p><p>下一步追 USB ID 變化後的工作程序與主機驅動，以及影像描述資料到真正螢幕的路徑，再建立 ARMv6 H.264 解碼原型。這些結果尚未形成可安裝 App 或 Android Auto；原機直接音樂與語音生命週期仍保留為待辦，Google Maps 依指示延後。</p></div>'
        if research.get('native_android_auto', {}).get('projection_io'):
            document += '<div class="card"><h2>USB 裝置模式與圖形驅動的新證據</h2><p>已用精確台灣 8.00 原廠指令確認：USB 描述資料是在 RAM 動態產生，具有 Garmin 專用與隨身碟兩種裝置模式；隨身碟的識別值與先前實機相符。模式旗標切換的是裝置呈現方式，<strong>USB 主機角色仍未證實</strong>。不能把改成另一種 USB 描述資料當作完成手機接收端。USB 類別與裝置角色的判讀參照 <a href="https://raw.githubusercontent.com/torvalds/linux/v6.12/include/uapi/linux/usb/ch9.h">USB Chapter 9 定義</a>、<a href="https://docs.kernel.org/driver-api/usb/gadget.html">USB 裝置端說明</a>。</p><p>七個 USB 離線案例通過：三種描述資料／封包大小配置、兩個傳送案例與兩個接收路徑。傳送實際執行原廠 ARM 複製、13-byte 隨身碟狀態包、佇列填入及忙碌拒絕；核心喚醒事件是明列的測試替身，尚未執行真正的 USB 中斷、工作程序或傳輸完成。封包大小與控制器暫存器均為合成資料，不代表測得實機速度。</p><p>圖形端找到原廠 SGA 驅動及其初始化呼叫鏈。十個離線案例實際執行原指令的記憶體位址轉換和硬體識別檢查，包含一次成功、八個各別識別值錯誤和空位址拒絕；另核對遮罩、啟用與狀態讀取。這些使用合成頁表和<strong>合成暫存器</strong>，並非實機晶片讀值，也未完成驅動配置、IRQ 或螢幕畫面輸出。</p><p>依啟動搬移關係再找到 DrawingBoard 與 PngImage 的條件式 GUI 類別表，以及原 Image 繪圖方法的三個虛擬輸出入口；十五個 Thumb 與六個 ARM 函式的有界流程已解析。下一步追真正的繪圖物件、像素格式和畫面呈現，並查 USB 主機／VBUS／ID 控制；H.264 解碼效能、手機協定連線和原生 App 入口仍未完成。目前沒有可安裝的 Android Auto 版本，goal 保持 active。</p></div>'
        if research.get('native_android_auto', {}).get('projection_io', {}).get('live_USB_verification'):
            live_usb = research['native_android_auto']['projection_io']['live_USB_verification']
            document += '<div class="card"><h2>實機核對：當前主機確實是 Raspberry Pi</h2><p>已由裝置樹與核心確認這裡是 Raspberry Pi 5；先前僅依主機名稱判斷是另一台主機，該結論已更正。使用者已把 Garmin 接到這台 Pi 的 USB 隨身碟模式，USB 與 XML 身分和備份一致。</p><p>實機的 50-byte USB 描述資料完全符合原廠描述產生器離線測試的隨身碟／512-byte 封包案例。Linux 回報 USB 連線速率 480Mbps，這不等於實測檔案吞吐量，也不代表導航機有 USB 主機／AOA 能力。新版 OSM 檔案已唯讀讀回，大小及完整雜湊都正確，剩餘空間約 ' + e(f"{live_usb['free_bytes']/1e9:.2f}") + ' GB；此次未改寫 Garmin 檔案，磁碟已卸載。</p><p>使用者已成功進入診斷頁，之後將 Garmin 接回隨身碟模式；再次唯讀核對 USB 身分及描述資料均一致。現有 USB-A → microUSB 資料線可以繼續供備份及檔案研究使用，另外的 OTG 轉接頭是否具備尚未確認；Android Auto 尚未在原機運行。</p></div>'
            usb_check = research.get('execution_environment', {}).get('latest_USB_check_utc')
            if usb_check:
                usb_check_time = dt.datetime.fromisoformat(usb_check).astimezone(dt.timezone(dt.timedelta(hours=8))).isoformat(timespec='seconds')
                usb_seen = research['execution_environment']['Garmin_USB_seen_at_latest_check']
                document += '<div class="card"><p><strong>以上 USB 身分、磁碟及速率是先前成功連線的歷史紀錄。</strong>最近一次 Pi sysfs 查看時間為 ' + e(usb_check_time) + '，當時' + ('看到 Garmin USB 裝置。' if usb_seen else '沒有看到 Garmin USB 裝置。') + '這不會自動確認原機所在模式或線材故障；本報告沒有持續輪詢即時狀態。</p></div>'
        if research.get('native_app_music', {}).get('requested'):
            document += '<div class="card"><h2>持續保留：原機 App 與手機直接播放音樂</h2><p><strong>仍在逆向研究，尚未安裝原生 App，也尚未啟用直接 A2DP 音樂。</strong>' + e(native_research_detail(research)) + '</p><p>原廠三個 TTS 語音包都有 DLLINFO、DLLIMG 與 72-byte SIG。分配表、檔案長度及 byte-sum 校驗已核對；SIG 的演算法、是否強制驗證、修改包是否接受仍未知。成功模擬原始元件並不能證明可安裝替換程式。</p><p>原廠音訊 callback 可能在回傳成功時仍略過資料；四次連續讀空會清除初始化旗標。後續須驗證真正初始化、音訊優先權、回壓與串流生命週期，再接上真實 A2DP 端點和自製 UI。</p><p>Audio Sink 範本初始化為停用；Discover 的 3 個端點槽與原始指令 6 項模擬已核對，只開 SDP 不會增加音訊端點。使用者休息期間用備份離線分析，不需要導航機插 USB 或維持藍牙，也不自動播放聲音。</p></div>'
        if research.get('map_update', {}).get('prepared'):
            map_status = ('檔案已寫入、讀回核對並卸載。' if map_installed else '檔案已準備並通過結構檢查，等待 USB 隨身碟模式安裝。')
            document += '<div class="card"><h2>台灣離線圖資更新</h2><p><strong>OSM 資料日期 2026-10-01，約 129 MiB、36 個區塊。</strong>' + map_status + '包含路由元件、地址索引與 UTF-8 繁中文字標。新增 <code>Map/Taiwan_OSM_20261001.img</code>，使用者已確認新地圖在清單可見；繁中顯示、搜尋與路線計算仍需實測。署名未顯示，依使用者要求取消後續修改。原廠 JCV 路口照片不會一起更新。</p><p>使用者先前在室內搜尋衛星；手冊已確認內建 GPS 天線，尚未做戶外收訊測試。</p></div>'
        document += '<div class="card"><h2>離線 Google Maps：依使用者要求延後</h2><p><strong>仍未在 Garmin 原機執行。</strong>官方離線地圖由 Google Maps App 使用；本台是 Garmin 韌體，尚未找到 Android 或可安裝任意程式的入口。Maps Go 官方列明無離線功能。韌體含 STA2064 平台路徑，該晶片的 ARM1176 核心屬 ARMv6；現代 Android NDK 的 ARMv7／ARM64 程式不能直接用於它。這是依韌體與原廠資料的條件式判斷，尚未拆機核對實體晶片，也未驗證任一 Google Maps APK。</p><p>手冊把車架的視訊輸入埠與 GDR10 microUSB 分開標示，接倒車攝影機的影像埠值得繼續核對；腳位、訊號及畫面啟用條件仍未知。目前沒有車架或線材。其他原機逆向與藍牙音樂研究照常繼續。</p></div>'
    audio_status = '實機已確認沒有公告 A2DP Audio Sink；目前正在測免持通話音訊的替代路徑。' if sdp_verified else '藍牙音樂目前仍待 A2DP 服務及實際聲音測試。'
    if audio_transmitted:
        audio_status = '實機沒有公告 A2DP Audio Sink；免持通話音訊已成功送出測試旋律，仍待使用者確認喇叭出聲。'
    if audio_heard:
        audio_status = '實機沒有公告 A2DP Audio Sink，但已透過免持通話音訊播放測試旋律，使用者確認喇叭出聲。音質受通話頻寬限制。'
        if research and research['audio'].get('current_speaker_confirmed') is False:
            audio_status += ' 此為先前成功紀錄；本次重新配對後雖可模擬來電與接聽，現場回報仍無聲，正在查復現失敗的原因。'
        elif research and research['audio'].get('current_speaker_confirmed'):
            audio_status += ' 本次重新配對後也已復現：暫時同步通話查詢狀態，使用者確認來電及接聽後旋律；正式 Pi 音訊服務修正版尚未部署。'
        if research and research['audio'].get('phone_a2dp_bridge_audible_verified'):
            audio_status += ' Pixel 手機音樂經 Pi 轉接也已通過 60 秒現場測試，但使用者回報音質差與音量起伏，尚未改善。'
    document += '<div class="card"><p><strong>隨身碟模式可以備份與改檔案；藍牙、觸控和影音效果需要一般模式才能驗證。</strong></p><p>地圖、POI、圖片、配色與原生功能已有明確介面；目前依使用者指示，主線是原生藍牙音樂與 GarminOS 播放器 App；Android Auto 排在後續。外部影像輸入方案仍保留為未驗證的另一項研究。' + audio_status + '</p></div>'
    document += f'<h2>實機與備份</h2><div class="card"><p>本次已透過 Raspberry Pi 的 USB 連線完成備份，之後切回一般模式進行藍牙測試。實機回報 nüvi 2565、軟體 8.00；內部 USB 邏輯磁碟 3,879,731,200 bytes。備份時導航機 SD LUN 沒有可讀媒體。現存 GUPDATE.GCD 與官方台灣版 8.00 完全一致，這證明更新檔匹配；不單憑它推論所有已執行的記憶體區域相同。</p><p><strong>{e(state)}。</strong>{e(files)}</p><p>範圍包含 USB 磁碟中的隱藏 .System、地圖、授權檔、語音、POI、設定與 GPX。未涵蓋 bootloader／USB 不曝光的晶片區域，也未涵蓋攝影機獨立 SD。</p><p>映像：<code>{e(str(BACKUP / "sda.img"))}</code><br>SHA-256：<code>{e(metadata.get("sha256", "尚未完成"))}</code></p><p>原始備份可能含定位紀錄與地圖授權資訊，保留於本機；本報告省略單機序號、座標與解鎖碼。</p></div>'
    if verification and verification['filesystem_check_returncode']:
        document += '<p>唯讀 FAT 檢查發現「剩餘叢集計數」與實際數量差 7 個叢集（28,672 bytes）。檢查使用 fsck.fat -n，明確回報未改動檔案系統；這是剩餘空間摘要的差異。本次 1,402 個檔案皆正常讀出，尚未對原機做修復。</p>'
    document += '<h2>玩法比較</h2><p>「已實測」包含實際操作確認的功能或限制；「已確認」表示精確型號文件或實機結構支持；「已準備」表示檔案已驗證，實機效果仍待測試。「可實驗」有具體入口；「待實測」依賴一般模式或配件。</p><p><label>狀態 <select id="state"><option value="">全部</option><option>已實測</option><option>已確認</option><option>已準備</option><option>已安裝</option><option>研究中</option><option>可實驗</option><option>待實測</option><option>缺乏支持</option></select></label> <input id="search" type="search" placeholder="搜尋玩法或限制" aria-label="搜尋玩法或限制"></p><div class="scroll"><table><thead><tr><th>證據狀態</th><th>玩法</th><th>實際能做的事與限制</th></tr></thead><tbody>' + rows + '</tbody></table></div>'
    theme_state = '已新增到導航機，檔案大小與 SHA-256 讀回校驗通過；原有主題未替換。尚未在實機螢幕驗證。' if installed else '目前只在樹莓派準備，尚未安裝。'
    if ui_verified:
        theme_state = '已新增到導航機並讀回校驗，原有主題未替換；使用者已在一般模式選取並確認正常顯示。'
    document += '<h2>已完成的改造與後續實驗</h2><div class="card"><p>Pi Contrast：<code>/root/garmin/staging/Themes/Map/Pi_Contrast.kmtf</code>。' + theme_state + '使用現有主題的欄位，保留日夜與不同地圖視圖；已驗證 XML、RGB 格式與欄位結構。在一般模式進入「工具 → 設定 → 導航 → 汽車 → 地圖主題」選取 Pi Contrast。刪除新增檔並選回原主題即可還原。</p>'
    if audio_heard:
        document += '<p>藍牙音源播放已實測成功：維持 Garmin-Pi 的 HFP Audio Gateway 連線，透過 <code>scripts/test_hfp_call_audio.py</code> 送出模擬通話狀態，再播放單聲道 8 kHz／16-bit PCM WAV。這是本機模擬狀態，不會撥打真實電話。</p>'
        if research:
            document += '<p>Pi 已安裝 FFmpeg，新增 <code>garmin_music_player.py</code>，自動轉檔、支援多首歌曲或資料夾、隨機播放與固定音量。現有舊版服務的現場實驗重播：<code>python3 scripts/garmin_music_player.py /path/to/music.mp3 --call-sequence incoming --live-cind-test</code>，需在 Garmin 接聽；暫時同步 Pi 的通話查詢格式並於結束還原。</p>'
            if research['audio'].get('phone_a2dp_bridge_audible_verified'):
                document += '<p>已完成 Android 手機音訊轉接：<code>python3 scripts/garmin_phone_audio_bridge.py --max-seconds 300 --volume 0.7 --live-cind-test</code>，在 Garmin 接聽模擬來電、於已配對的 Pixel 播音樂。60 秒測試使用者確認持續有聲；五分鐘指令為可設定上限，並非已完成五分鐘實測。音質仍為單聲道 8 kHz，使用者回報音量起伏；未啟用 Pi 降噪，原因仍待查。</p>'
    if research:
        document += '<h2>精確韌體逆向進度</h2><p>已解析 742 個 GCD 記錄，重新拼回的位元組與原檔完全相同，4 個 CheckPoint 累加校驗全部通過。主程式為 46,962,176 bytes，開機程式為 609,840 bytes；兩者載入基址 0x50000，HWID 指標讀出 1352、版本指標讀出 800，與實機及封裝描述一致。主程式末尾校驗及 LEND 指標已核對；開機區校驗規則與末尾 260 bytes 的用途仍未知。</p><p>韌體存在 STA2064 處理器驅動路徑；ST 原廠資料表描述此晶片為 ARM1176。這是韌體目標的證據，不能代替實體晶片、板上 RAM 或實際時脈的讀出。已定位 PageTestAudioList、PageAudioMixer、PageTestBluetooth 的 RTTI、虛擬函式表與 Thumb 函式指標，正在追蹤初始化及音訊入口，尚未部署韌體修改。</p><p>證據：<code>evidence/firmware-analysis/layout.json</code>、<code>platform.json</code>、<code>audio-ui-vtables.json</code>。原始實機韌體未改動。</p>'
    document += '<p>後續仍可實驗 OSM 地圖、圖片及自訂主畫面、藍牙 SPP 即時定位資料；若有原装車架／攝影機，再確認影像輸入、供電及接線，評估外部 Pi 顯示 Android Auto。這些項目依賴額外素材或配件，尚未驗證。</p></div>'
    document += '<h2>避免混用型號的三個重點</h2><div class="card"><p>2585 的 MP3、多媒體和數位電視資料不能套用到 2565RT；官網部分小站共用頁面標題，需看網址及內文的實際型號。Garmin Linux 原始碼清單的「nüvi 25xx」下載名是 nuvi_2585_tw，也不能證明本台採 Linux。國外 nüvi 2565／HWID 1371 的晶片或刷機資料，不能當成台灣 HWID 1352 的直接證據。</p><p>USB 目前只提供大容量儲存，沒有看到 ADB 或 shell。這份 USB 備份能救回原始檔案，不保證能救回刷壞的 bootloader。原生 Garmin 系統的任意程式執行與替代 OS 仍屬逆向研究。</p></div>'
    document += '<h2>主要來源與本機證據</h2><ul>' + sources + '</ul><p>本機證據：<code>evidence/device-identity-summary.json</code>、<code>device-firmware-comparison.json</code>、<code>device-storage-summary.json</code>、<code>supported-features-decoded.html</code>、<code>prepared-theme.json</code>，以及備份資料夾內的校驗與檔案清單。</p></main><script>const sel=document.getElementById("state"),search=document.getElementById("search");function filter(){for(const row of document.querySelectorAll("tbody tr[data-state]"))row.hidden=!!((sel.value&&row.dataset.state!==sel.value)||(search.value&&!row.textContent.toLowerCase().includes(search.value.toLowerCase())))}sel.addEventListener("change",filter);search.addEventListener("input",filter);</script></html>'
    (report / 'nuvi2565RT.html').write_text(document,encoding='utf-8')
    print(json.dumps({'report':str(report / 'nuvi2565RT.html'), 'backup_state':metadata['state'], 'file_verification':bool(verification)},ensure_ascii=False))


if __name__ == '__main__':
    main()
