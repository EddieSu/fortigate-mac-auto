# FortiGate MAC 設定自動化工具

以 SSH 自動化維護 FortiGate 的 MAC Address 與 Address Group。支援以「裝置 MAC」為條件在設備端 grep 查詢目標 address，避免一次抓全表造成輸出截斷。

## 版本
- 程式內版本：`utils.APP_NAME / APP_VERSION`
- 執行時會顯示：`FortiGate MAC Auto vX.Y.Z`
- 編譯（PyInstaller）會內嵌 Windows 檔案版本（`version_info.txt`）

## 功能特色
- 以本機掃描之裝置 MAC，遠端 grep 找出對應的 FortiGate MAC address 物件（a1/a2/...）
- 新增/改名/加入群組/移除群組/刪除 address
- 列出群組與其成員（僅抓群組清單；address 按需查詢）
- 日誌檔輸出至 `logs/`，可切換精簡或完整 dump（見 Debug）

## 系統需求
- Python 3.8 或更高
- 可 SSH 連線至 FortiGate（不使用 REST API）

## 安裝
```bash
pip install -r requirements.txt
```

## 設定 `config.ini`
```ini
[FortiGate]
host = https://172.18.118.194
ssh_username = admin
ssh_password = your_password
ssh_port = 22

[Security]
timeout = 10

[Debug]
enable_test = false        ; 顯示 t.Test 與啟動時的本機介面清單
debug = false              ; false: 精簡紀錄；true: 完整 dump 指令與回覆

[Display]
scroll_output = true       ; 等待動畫是否換行滾動
```

## 執行
```bash
python fortigate_mac_auto.py
```
流程：
- 顯示版本與系統資訊
- 掃描本機裝置 MAC
- 抓取群組（address 按需查詢）
- 主選單列出「每個裝置」與其對應 MAC address 物件（以設備端 grep 查得）

## 主選單指令
- `name <索引>`：
  - `name N` 為裝置 N 新增 address（詢問名稱）
  - `name i.j` 修改既有 address 名稱
  - `name i.j.k` 修改既有 group 名稱
- `joingroup <索引>`：
  - `joingroup N` 若已存在 address，直接詢問要加入哪些群組；無則詢問名稱後建立並加入
  - `joingroup i.j` 將該 address 加入尚未加入的群組
  - `joingroup i.j.k` 將成員加入該群組
- `leavegroup <索引>`：
  - `leavegroup i.j` 列出該 address 已加入的群組並移除
  - `leavegroup i.j.k` 列出該群組成員並移除
- `del <索引>`：
  - `del i.j` 若 address 隸屬群組，先詢問欲自哪些群組移除（可輸入 `all`）；若已無群組，才詢問是否刪除 address
  - `del i.j.k` 群組無成員時可刪除，否則先移除成員
- `t`：在 `enable_test=true` 時可用，顯示原始 dump
- `q`：離開

提示：純數字輸入（例如 `1`）不被接受，請使用上述指令格式。

## 等待動畫
- 呼叫：`show_spinner(seconds=1.0, message="同步設備狀態...")`
- 每 0.1 秒更新一次，frames 為 `| / - \`；`scroll_output=true` 時結束換行

## 日誌（Debug）
- `debug=false`（預設）：
  - 僅記錄精簡摘要，如：
    - `get_address_groups: count=N`
    - `find_addresses_by_mac_remote: mac=... results=N via attempt=M`
    - `query_by_mac: device=... mac=... results=N`
- `debug=true`：
  - 完整 dump 每次送出的 SSH 指令（含 `config system console` 前置）與 stdout/stderr 回覆
  - 記錄所有 grep 嘗試與解析結果

## 檔案結構（節選）
```
FortiGate MAC auto Add/
├── fortigate_mac_auto.py        # 入口（互動選單/流程）
├── fortigate_client.py          # FortiGate SSH 客戶端與查寫
├── address_parser.py            # 解析 address/addrgrp CLI 輸出
├── utils.py                     # 共用工具（版本/日誌/MAC 正規化）
├── simple_mac_scanner.py        # 本機 MAC 掃描
├── fortigate_mac_auto.spec      # PyInstaller 設定（含 version_info.txt）
├── version_info.txt             # Windows 檔案版本資訊
├── config.ini                   # 設定
└── logs/                        # 日誌
```

## 編譯（PyInstaller）
```bash
pyinstaller -y "FortiGate MAC auto Add/fortigate_mac_auto.spec"
```
編譯出的 exe 會內嵌版本（`version_info.txt`）。如要更新版本，請同步修改：
- `utils.py` 的 `APP_VERSION`
- `version_info.txt` 的 `FileVersion/ProductVersion`

## 注意
- 未使用 VDOM（若需支援可擴充）
- 另一視圖（another）已移除；如需跨裝置搜尋可另加 `search` 指令

## 授權
本工具僅供內部使用，請遵守組織政策。

## 開發工具
- Cursor
- ChatGPT 5.0
- FortiGate VM
