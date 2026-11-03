本表為有限純檔案 review。11 個預先列出的小檔案均正常讀取、完整 SHA／前後 stat 相符；沒有 import／執行 producer、guest、firmware、編譯、patch、device 或 audio。舊 v1 partial 不變。

| ABI／驗收點 | 現有證據與界線 | 精確缺口 |
|---|---|---|
| Source 軟體 CONFIG grant | guest-only C 檢查 original CURRENT==MH_SOURCE_TCB、已初始化、msg13/channel8、Mixer+0x78 TCB、LR0x3B9C4F；MCS_HANDOFF(AAS_GUARD)==0 後才 original send0x37BCE5 | MCS_HANDOFF／AAS_GUARD 是該 loaded software binding；零回傳不證明 native reservation、all-writer 排除或硬體可播放。這輪未讀其 address header／函式 body |
| 原 Source READY | 新 READY contract 記錄 initializer 六個完整 helper returns、原 CURRENT／POST／WAIT、controller event0x400；wake 時 POST-return count0，Source 後續為1，分開記錄 | 是 warm logical Source ready；該 case 沒有媒體／factory／mixer pull。不可沿用舊 static runtime=false否定新 READY，也不可把 READY 當 hardware ready |
| source record／TCB／token | adapter 要 matching channel8、owner TCB、generation、cookie、actual source token；publication API 不接受 caller 指定 sample token | exact loaded address map、實際 record/provider/anchor、matching token的 register完整返回、retirement provenance，以及 source／mixer跨 actor 生命期未完整閉合 |
| ownership_snapshot epoch | 公開 witness：generation,cookie,channel,owner_tcb,source_token,epoch,native_writers_excluded,future_borrowing_callbacks_excluded；snapshot 在 observations 前後採樣 | 真實 native reservation／barrier API 未 recovered；epoch需非零且持續到 matching retirement，record/provider／generation／owner切換後失效。private cookie／IRQmask／callback count0不能代替 |
| all-writer／future callback 排除 | FIFO／READY contract 均 native witness−200；header 明列 ownership_snapshot、prepare_session仍NULL並 fail closed | 必須識別 Composer／Audio／導航及其他 writer 的合法 reservation／release，且屏障涵蓋尚未進入的 borrowing callback。沒有此證書就不能設定 exclusive=true |
| FIFO full-return／anchor | resident 4 frames／1024 PCM；FIFO private consumer核對896B，ticket16仍128B；stack／adapter／module／FIFO pinned | private controller不是原 mixer；recyclable FIFO ticket不能單獨證明長壽命 native source／anchor identity。實際 source→mixer所有 full-return leases與callback provenance仍缺 |
| mixer integration | 原 allocator software extent由原 API加入且原Mixer TCB可建立；admission receipt9eb25d EXIT1：native1792B vs fixtureexpected256B，failure serializer另KeyError，fullfailurestate未存 | 未完整核對1792布局、每byte PCM／silence、held leases／全returns；build-media-v2未執行屬 parent既有界線，不能算passed |
| Stop／STOP_DONE | local STOP關queue並留 partial PCM；trace含remove/release/cancel/pump baselines與original_cleanup_returned／owner_cancel_iteration_returned | matching cancel generation、原 Source iteration完整返回、原cleanup wholeframe完整返回及通知後ref釋放、list removal/release實際返回、futurecallback屏障都需同時成立。request0／FIFO空／callback count0不等STOP_DONE；不可free/unload |
| direct phone／App入口 | adapter的 prepare_session／admission為 proposed glue；document明列 config/START/event17/F1/consumer callsites未接線 | 真SEP／SDP啟用、authorized Pixel直接協商／media、AV-locked session、合法原生GUI/menu launch、preserving package／VPM接受性尚未完成。這輪未重新核對SEP／marker或完整TTS包 |

在任何未來原生 live test 前，先取得上表缺失的實際 binding／ownership／barrier／return 證書，明列 frozen-warm、controller/idle、software heap/MMU/driver與loader fixtures；保持module／TCB／stack pinned。不得把host shim、software grant或synthetic hardware-ready當原機完成。此表不授權或要求執行測試；中止的guest仍不重試。

下一個安全方向是從小型已存資料列出 all-writer reservation 和 future-callback barrier 的 exact missing signatures／lifetimes，並檢查 source／provider replacement 的 epoch失效要求；只讀檔案，不製造success shim。直接手機／App／speaker／STOP_DONE／install／fullgoal仍 false。
