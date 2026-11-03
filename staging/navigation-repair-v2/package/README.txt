Garmin nüvi 2565RT 導航搜尋修復候選 v2

這包修正編譯器的漢字排序鍵與 SRT 16/10/6 欄位封裝，保留城市／道路歸屬調整。
包內離線證據包含原始函式有限對照、實際新版 MDR 索引及道路／城市檢查。
尚未確認原機地址 UI 搜尋與導航正常，不能視為已完成修復。
OSM 資料日期為 2026-10-01；它是 OSM 地圖，不是 Garmin 官方 NT 更新。

Linux／原 Raspberry Pi 上解壓縮後：
  python3 install.py --bundle .
預設只做唯讀預檢。安裝時 Garmin 必須 USB 隨身碟模式，執行：
  python3 install.py --bundle . --install
還原：
  python3 install.py --bundle . --rollback

只新增 Map/Taiwan_OSM_SearchRepair_v2.img；原已驗證的專案 OSM 20261001 改為
.img.disabled 並保留。rollback 只刪完全符合本包雜湊的新 IMG 並還原舊專案圖。
身份、原廠圖、授權與配套檔皆需核對；檔案異動、空間不足、USB 不符時拒絕安裝。
原廠 CN 道路＋Address Point 門牌層本來互補；所有原廠檔只保留、不放進下載包。
v1 封存候選未安裝；此工具不會移除任何來歷不明或其他候選圖資。

請依 device-ab-checklist.txt 實測。排序對照與檔案讀回不等於地址搜尋成功。
OSM 可能缺門牌；高雄來源邊界缺段等限制見 manifest.json 與 verification。
tests/road-anchors.gpx 只用於位置比對，不自動匯入、也不證明地址命中。
這包未包含 GarminOS、新 App、原廠私有圖資／資料庫或藍牙音樂程式。
導航實機修復確認後才恢復其他改造研究。
