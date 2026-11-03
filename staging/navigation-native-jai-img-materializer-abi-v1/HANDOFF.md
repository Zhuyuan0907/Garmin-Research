# One-source query materializer and actual 4K IMG linkage

實際執行 `d103bd` EXIT 0。Actual new disabled IMG SHA inherited
`26a47f00fc84de49cf107df5b50504ff62849cb61d384e2d97b236aca400b8f9`、132173824 B。
只讀75,956 B（真raw FS、one rb open/close）；新增原MAIN61,440 B（含initial page
`e5d4e5` 4,096 B），重用前scope保存JAI兩頁8,192 B。Cache不重讀原pages。
完整離線DB也只one readonly open/close；exact syscalls與bytes見actual receipt。
來源stat未變，source handles全部closed，沒有wholehash重跑或IMG/DB修改。

這輪跨過前scope stop：新完整敦富六街 token query在真 `0x04425726` consumer
缺prefix→FTSfallback支線實際執行 `0x04425304` materializer。原SQL family查詢
與原vectorcopy產生一個3項結果鏈（每項12 B）：
`[3,48312,0] → [2,74,FFFFFFFF] → [1,8,FFFFFFFF]`，原caller返回0。
其中第3word是這次觀察到的match offset／sentinel，不泛稱其全部語義。
0x3000BCB8 native record轉成level3/low48312不是host預先寫出的native結果。

SQL底層使用完整實際readonly prototype DB，是明示外部fixture；ASCII encoded
token compare/advance、JAI object ready/statement handles與预配vector/chain buffers
也明示fixtures。原JAI caller/materializer/parentloop/vectorcopy全部真指令，沒有
hook原函式return，也沒有执行allocator。不是原nativeSQLite或UI成功。

實際IMG由真DSKIMG/FAT讀出header/DIR。原header field-store/division fragment
`0x002CD480..0x002CD49E`接受實際header600..616 stack seam，接到原DIR decoder
`0x044B209E`。不是完整header FS/parser/startup。原packed prefix `0x044B10E4`
使用真未realign的record span及真following4 B，readonly tail後為unmapped page：

- L2 74：next3、first47871、count442，因此最後一筆為48312。
- L3 48312：next4、first3781595、count1、street textref475679。
- L4 3781595：leaf、house textref2967、source/raw24 `[1127253,5625400]`。

三筆皆從這個actual新容器讀，不重播先前v3 proposed-payload suite。packed prefix
停止在metadata `0x0448F740`前，未偽造metadata/registry成功。

Actual GMP指出LBL header，新header原field-store片段回label_start3812824、
label_size3805448、shift3、encoding10、CP950。由原address/bytecopy片段分別
讀出真容器「敦富六街」（ref475679）及「368號」（ref2967）。這是實際LBL
文字，仍是分段执行，並非完整map-registry getter返回。

最小下一缺口：接原query result-vector consumer至MDR provider/context，再跨
`0x0448F740`真metadata/map-registry與完整LBL getter。前sealed static bridge可
引用 `navigation-stock-jai-reader-bridge-v1` 的query→record topnibble/lowID片段；
不得把這輪以同ID連結的分開CPU結果當成 uninterrupted query/provider/getter。
需要先準備source/container一致的metadata context，未知初始化／callback／registry
須明示或保留停點，不直接提供假success。

機器入口為query-to-container-binding.json、actual-native-materializer-case.json、
proof.json及actual-execution-receipts.json。Root另外查到官方路名primary資料；
本scope只封舊source pins與query/IMG結果，不改舊alias/official held證據、不混成
全部alias通過。Source OSM北屯區/source/raw24 gate引用獨立sealed geometry。
UI、device/install acceptance、完整provider/getter及全台完成仍false；沒有包裝
可安裝檔、USB、report或舊sealed scope修改。封存後停止，不重跑case。
