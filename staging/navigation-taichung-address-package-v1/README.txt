Garmin 台灣 nüvi 2565RT（HWID1352／軟體8.00）台中原生門牌擴大測試包 v1

本包在原廠 Address Point 搜尋架構補入11,002筆整數門牌，涵蓋1,693條既有台中街道。
來源日期2026-10-01；這不是全台完整新版門牌，亦尚未實機驗收。
原廠已有的門牌位置、街道／區／縣市階層、其他地圖元件及授權資訊保留。
圖資清單名稱可能仍顯示原廠2016，新增資料的範圍以本包說明與manifest為準。

內容：
- candidate/gmapprom1.img：100,945,920 bytes較大地址補充候選。
- roadmap/Taiwan_OSM_SearchRepair_v2.img：既有新版台灣OSM道路圖，方便一包保存。
- manifest.json、restore-layout.json.gz：精確單機／檔案校驗及原廠還原資料。
- install_taichung_addresses.py、device_support.py、native_address_layout_restore_v1.py：Linux安裝／還原工具。
- validation/：候選讀回、獨立合併審查、有限原廠指令與交易工具的驗證。

已驗證：
實際IMG完整讀回，各1693街道重寫群組、47870筆街道欄位及其他五個元件核對通過。
新增11002筆的來源ID／原文字ref／欄位／台中市邊界由另一代理獨立審查。
原廠指令有限讀取四條街／14筆新增門牌及標籤通過；完整搜尋UI仍須實機測。
864491 bytes還原配方可串流重建原廠96,739,328 bytes與完整SHA，沒有另一份完整備份。
先前民權路九筆包已實機接受；這個較大的候選需要另外驗證。

未納入：
之號／其他子號、本來源座標矛盾、原廠未有的新街道／行政區及next5／next6門牌。
舊門牌若同名存在會保留舊位置；不把本批補充稱為所有地址已刷新。
沒有韌體改寫、效能修復或GarminOS重新編譯。

安裝：
此工具針對已授權的同一台2565RT及8.00，Search v2需已安裝且雜湊符合manifest。
Garmin接Pi USB，選隨身碟模式；勿手動覆蓋原檔。
只唯讀預檢：python3 -B install_taichung_addresses.py --bundle .
安裝：sudo python3 -B install_taichung_addresses.py --bundle . --install
只接受原廠原檔、已驗收民權路九筆包或本包的精確檔案雜湊。
工具以新暫存檔、完整讀回及原子替換更新AP，成功後同步、安全卸載。
roadmap/供整包保存，本工具不再次安裝或覆蓋Search v2。

實機驗證：
完成安全卸載才拔USB，完整關機再開機。
保持Address Point＋Search v2勾選；原CN道路圖可保留供回退。
先測民權路6／150／184號，再測北屯區一新一街1號、沙鹿區台灣大道六段488號、石岡區豐勢路9號。
後三者是此次來源新增候選，需依上述原廠區域搜尋；查到後確認位置與路線合理。
每次最多60秒；無相符或逾時請回報，無需實際開車。

還原：
sudo python3 -B install_taichung_addresses.py --bundle . --rollback
以配方重建原廠檔至暫存檔，校驗完整SHA後原子替換；不直接截短現行地圖。
還原至最初原廠AP，Search v2及其他檔案保留。

來源與授權：
新增門牌座標：2026-10-01T20:22:06Z台灣OpenStreetMap快照。
© OpenStreetMap contributors，資料依ODbL提供：https://www.openstreetmap.org/copyright
原廠地圖及作者／授權資訊保留；本包供已授權的單一導航機實驗。
