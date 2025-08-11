@echo off
chcp 65001 >nul
echo FortiGate MAC 自動化工具 - 打包程式
echo ======================================

echo.
echo 正在打包成 exe...
python -m PyInstaller fortigate_mac_auto.spec

echo.
echo 打包完成！
echo 執行檔位置: dist\FortiGate_MAC_Auto.exe
echo.
