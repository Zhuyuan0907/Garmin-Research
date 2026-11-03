# Garmin 報告網頁

目前網址：<http://172.16.60.187:8765/>，供可連到這台主機的區網使用。
`/report.html` 與 `/nuvi2565RT.html` 也會顯示同一份報告。

常駐服務為 `garmin-report-web.service`，已設定開機自動啟動。每次瀏覽都讀取
`/root/garmin/reports/nuvi2565RT.html`，並送出 `Cache-Control: no-store`。
更新研究報告後，瀏覽器重新整理即可，不需重啟服務。

服務以 systemd 臨時使用者執行，報告資料夾唯讀掛載。
HTTP 只允許上述三個固定路徑；備份、JSON 證據及資料夾清單沒有網頁路由。
沒有設定對外轉發或修改防火牆。

檢查或停止服務：

```sh
systemctl status garmin-report-web.service
journalctl -u garmin-report-web.service -n 20 --no-pager
systemctl disable --now garmin-report-web.service
```

伺服器程式來源為 `scripts/serve_report.py`，部署位置是
`/usr/local/lib/garmin-report-web/server.py`；unit 來源在本資料夾，
部署位置是 `/etc/systemd/system/garmin-report-web.service`。
若主機的區網 IP 改變，修改 unit 的 `--host` 並重新部署、重啟服務。
