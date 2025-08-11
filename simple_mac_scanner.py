#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
簡化的 MAC 地址掃描器
只獲取本機網路介面的 MAC 地址
"""

import subprocess
import re
import platform
import socket
import uuid
from typing import List, Dict

class SimpleMACScanner:
    def __init__(self):
        self.system = platform.system()
    
    def get_local_mac_addresses(self) -> List[Dict]:
        """獲取本機所有網路介面的 MAC 地址"""
        interfaces = []
        
        try:
            if self.system == "Windows":
                interfaces = self._get_windows_mac_addresses()
            elif self.system == "Linux":
                interfaces = self._get_linux_mac_addresses()
            elif self.system == "Darwin":  # macOS
                interfaces = self._get_macos_mac_addresses()
            else:
                interfaces = self._get_fallback_mac_addresses()
        except Exception as e:
            print(f"獲取 MAC 地址失敗: {e}")
            interfaces = self._get_fallback_mac_addresses()
        
        return interfaces
    
    def _get_windows_mac_addresses(self) -> List[Dict]:
        """Windows 系統獲取 MAC 地址"""
        interfaces = []
        
        try:
            # 使用 getmac 命令，這個命令更可靠
            result = subprocess.run(['getmac', '/fo', 'csv', '/v'], 
                                  capture_output=True, text=True, encoding='utf-8', errors='ignore')
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines[1:]:  # 跳過標題行
                    if line.strip():
                        parts = line.split(',')
                        if len(parts) >= 3:
                            name = parts[0].strip('"')
                            mac = parts[2].strip('"')
                            if mac and mac != "N/A":
                                # 清理名稱，移除特殊字符
                                clean_name = self._clean_interface_name(name)
                                interfaces.append({
                                    'name': clean_name,
                                    'mac': mac,
                                    'type': 'Local'
                                })
            
            # 如果 getmac 失敗，嘗試使用 wmic
            if not interfaces:
                result = subprocess.run(['wmic', 'nic', 'get', 'name,macaddress', '/format:csv'], 
                                      capture_output=True, text=True, encoding='utf-8', errors='ignore')
                
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if line.strip() and ',' in line and 'Name' not in line:
                            parts = line.split(',')
                            if len(parts) >= 2:
                                name = parts[0].strip()
                                mac = parts[1].strip()
                                if mac and mac != "" and mac != "N/A":
                                    # 清理名稱，移除特殊字符
                                    clean_name = self._clean_interface_name(name)
                                    interfaces.append({
                                        'name': clean_name,
                                        'mac': mac,
                                        'type': 'Local'
                                    })
        
        except Exception as e:
            print(f"Windows MAC 掃描失敗: {e}")
        
        return interfaces
    
    def _get_linux_mac_addresses(self) -> List[Dict]:
        """Linux 系統獲取 MAC 地址"""
        interfaces = []
        
        try:
            # 使用 ip link 命令
            result = subprocess.run(['ip', 'link'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                current_name = None
                
                for line in lines:
                    if ':' in line and 'link' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            current_name = parts[1].strip()
                    
                    elif current_name and 'link/ether' in line:
                        mac_match = re.search(r'([0-9a-f]{2}:){5}[0-9a-f]{2}', line)
                        if mac_match:
                            mac = mac_match.group(0)
                            interfaces.append({
                                'name': current_name,
                                'mac': mac,
                                'type': 'Local'
                            })
                            current_name = None
        
        except Exception as e:
            print(f"Linux MAC 掃描失敗: {e}")
        
        return interfaces
    
    def _get_macos_mac_addresses(self) -> List[Dict]:
        """macOS 系統獲取 MAC 地址"""
        interfaces = []
        
        try:
            # 使用 ifconfig 命令
            result = subprocess.run(['ifconfig'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                current_name = None
                
                for line in lines:
                    if line and not line.startswith('\t') and ':' in line:
                        current_name = line.split(':')[0].strip()
                    
                    elif current_name and 'ether' in line:
                        mac_match = re.search(r'([0-9a-f]{2}:){5}[0-9a-f]{2}', line)
                        if mac_match:
                            mac = mac_match.group(0)
                            interfaces.append({
                                'name': current_name,
                                'mac': mac,
                                'type': 'Local'
                            })
                            current_name = None
        
        except Exception as e:
            print(f"macOS MAC 掃描失敗: {e}")
        
        return interfaces
    
    def _get_fallback_mac_addresses(self) -> List[Dict]:
        """備用方法獲取 MAC 地址"""
        interfaces = []
        
        try:
            # 使用 Python 內建方法
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                           for elements in range(0,2*6,2)][::-1])
            
            interfaces.append({
                'name': 'Default Interface',
                'mac': mac,
                'type': 'Local'
            })
        
        except Exception as e:
            print(f"備用 MAC 掃描失敗: {e}")
        
        return interfaces
    
    def _clean_interface_name(self, name: str) -> str:
        """清理網路介面名稱，移除特殊字符和亂碼"""
        if not name:
            return "Unknown Interface"
        
        # 移除常見的特殊字符
        import re
        # 移除控制字符和特殊 Unicode 字符
        cleaned = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', name)
        # 移除非 ASCII 字符（保留基本英文字母、數字和常用符號）
        cleaned = re.sub(r'[^\x20-\x7e]', '', cleaned)
        # 移除多餘的空格
        cleaned = re.sub(r'\s+', ' ', cleaned).strip()
        
        # 如果清理後為空，使用預設名稱
        if not cleaned:
            return "Network Interface"
        
        # 限制長度
        if len(cleaned) > 50:
            cleaned = cleaned[:47] + "..."
        
        return cleaned
