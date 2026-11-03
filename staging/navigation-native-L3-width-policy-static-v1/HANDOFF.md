# L3 profile 與高層 policy：有限靜態結果

**未在本輪核對的原 callsites 找到明確 reject。這是有界負結果，不是 renderer
接受證明，也沒有判定道路顯示回歸原因。**

先更正 scope 的 profile 假設：原 stock 是 first_child width22／stride111；
已封存的 country-v2 **128,356,352 B／SHA925a515b…** 已經是 width23／stride112。
lane-v3 **153,346,048 B／SHA1f468e…** 沿用相同 L3 profile，街數都 **47,870**。
因此不能將22→23視為v3特有變化。這項 erratum 已保存在候選事實檔。

真正變化包括 L4 count **3,781,594→4,896,236**，跨原22-bit最大值4,194,303；
MDR component **124,255,307→149,220,356 B**；container4K→8K。本輪只把它們作
靜態輸入事實，沒有製造22／23對照、重跑CPU或推論哪項造成道路消失。

`candidate-layout-and-CPU-facts.json` 保存：

- 兩版先前 actual MDR header／120-byte DIR rawbytes與其來源SHA。
- 兩版六個 table profiles；L3共同23／112，L4分別3781594／4896236。
- 原CPU scope：v2共45 prefixes；v3共23 prefixes（含7新lane leaves）及23獨立LBL
  fragments，均停在metadata0448F740之前。沒有重跑，也未升級成完整UI／renderer證據。
- v3已凍結選樣 root13865 first4194360，另actualraw witness root26718
  first4499618。這些只引用舊封存結果，不是本輪實際讀IMG／CPU。

五份 witness 在 `width-policy-witnesses.json`：

- W1：上述候選 pins、相同profile與不同數值範圍。
- W2：MDR header parser 的原 signature／header-length／IO guards與動態DIR metadata；
  所讀 spans沒有 width22／23、stride111／112或149MB component-size compare。
- W3：原完整DIR parser044B209E..219E動態載入stride，解開6-bit width；loop count來自
  ctx+2C0。它的nonnull／count0／entryreadsize≤20 guards與L3特定profile不同。
- W4：原packed reader用dynamic stride計算record offset，檢查level、非零lowID及
  table byte範圍；first_child動態width寫入32-bit欄位，所讀span未見22-bit固定mask。
  v3L4末recordend=626,718,208 bits，MDR149,220,356 B均落在u32範圍。
- W5：原selected query DIR cache callsite呼叫動態parser／reader，保存first/count。
  未見上述profile／2²²／149MB明確拒絕；其後relationship/iteration仍未追。

剩餘缺口是未核對的 mount、metadata、relationship/iteration、maploader與renderer
policy。不能由 generic parser／prefix接受，宣稱全部高層没有 guard。registry key
producer／授权metadata／token线没有继续，heap／mutex／音樂admission也沒有執行。

新 MAIN **0 B**（上限24KiB）、IMG **0 B**、CPU **0 cases**、witness **5**。
只重用五個sealed code pages與small metadata；兩份大型舊CPU proof各只讀64KiB
prefix提取完整指定top fields，未全檔scan／重hash／執行。每份來源stat與hash／
partial-read範圍均在ledger。沒有MAIN／IMG／裝置／audio／canonical／舊seal修改。
達五份後封存停止。實機renderer、UI、App、安裝與全台更新均未因本輪變true。
