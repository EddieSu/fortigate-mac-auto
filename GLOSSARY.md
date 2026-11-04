# FortiGate MAC auto Add（FortiGate MAC 設定自動化工具）

在一台電腦上執行、替這台電腦的網路介面維護 FortiGate 設定的小工具：掃描本機每個網路介面的 MAC，到 FortiGate 查出對應的 MAC 位址物件，再新增、改名、刪除物件，或把物件加入、移出位址群組。全程經 SSH 下 FortiGate 的 CLI 指令，不使用 REST API。

術語寫法是「中文術語（程式識別字）」。識別字是程式或 FortiGate CLI 裡實際出現的寫法，只為了對照；文件和畫面一律用中文術語，程式裡沒有對應識別字的術語不加括號。每條底下的 _Avoid_ 列的是同一件事在程式或畫面裡出現過的其他說法：意思相同，但寫文件和介面時不要用；有例外就寫在括號裡。

## FortiGate 物件

**MAC 位址物件**（`macaddr`）：
FortiGate 防火牆設定裡類型為 MAC 的位址物件（`config firewall address` 底下 `set type mac` 的那種），一個物件記一個 MAC。本工具只處理這一類，其他類型的位址物件一律忽略；沒宣告類型但帶 MAC 的也當成這一類。
_Avoid_: 地址物件、地址（程式訊息裡的寫法）、address（CLI 指令與程式識別字除外）

**位址群組**（`addrgrp`）：
把多個位址物件歸成一組的 FortiGate 設定。防火牆規則可以引用群組，所以把一台電腦的 MAC 位址物件加進哪些群組，就決定它適用哪些規則。
_Avoid_: 地址群組（程式訊息裡的寫法）

**群組成員**（`member`）：
位址群組裡列的位址物件。加入群組是在群組上追加成員（`append member`），移出群組是取消選取成員（`unselect member`），兩者都不會動到其他成員。本工具要求位址物件先移出所有群組才能刪除。

**自動建立註記**（`comment`）：
本工具新增 MAC 位址物件時固定寫進備註欄的「Auto created by MAC automation tool」，用來分辨哪些物件是工具建的、哪些是人工建的。

## 本機與查詢

**本機裝置**（`network_devices`）：
執行本工具那台電腦上的一個網路介面，帶介面名稱和 MAC。工具一啟動就掃描全部本機裝置，主選單以裝置為單位，列出每個裝置在 FortiGate 上對應的位址物件與它所屬的群組。
_Avoid_: 網路裝置（主選單的寫法）

**MAC 正規化**（`normalize_mac`）：
把 MAC 統一寫成冒號分隔的大寫格式，例如 `AA:BB:CC:DD:EE:FF`。本機掃到的 MAC 和 FortiGate 讀回的 MAC 都先正規化再比對，所以來源寫成小寫或用減號分隔都對得上。

**設備端查詢**（`find_addresses_by_mac_remote`）：
在 FortiGate 上直接執行 `show firewall address | grep <MAC>`，只取回含有這個 MAC 的位址物件，不把整張位址表抓回來，因為整張表輸出太長會被截斷。grep 試三種寫法都查不到時，才退回抓整張表在本機解析（`find_addresses_by_mac`）。

---
🤖 opus · effort: xhigh · 2026-11-04
