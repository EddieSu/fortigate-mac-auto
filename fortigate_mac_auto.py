#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FortiGate MAC 設定自動化工具
用於自動化設定 FortiGate 防火牆的 MAC 地址和群組
"""

import requests
import json
import sys
import os
import configparser
from typing import Dict, List, Tuple, Optional
import urllib3
import logging
from datetime import datetime
from simple_mac_scanner import SimpleMACScanner
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlparse
import getpass
import paramiko
import time
from urllib.parse import quote
import sys
import re
from fortigate_client import FortiGateManager as FGClient
from utils import normalize_mac, setup_logging, APP_NAME, APP_VERSION
from fortigate_client import FortiGateManager

# normalize_mac 已移至 utils.normalize_mac

def extract_mac_list(mac_field) -> List[str]:
    """將 API 回傳的 macaddr 欄位標準化為字串列表。"""
    try:
        if mac_field is None:
            return []
        if isinstance(mac_field, list):
            return [normalize_mac(str(x)) for x in mac_field if str(x).strip()]
        # 單一字串
        val = normalize_mac(str(mac_field))
        return [val] if val else []
    except Exception:
        return []

# setup_logging 已移至 utils.setup_logging

# 初始化日誌
logger = setup_logging()

# 禁用 SSL 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 測試模式支援 (已停用)
# TEST_MODE = False
MockFortiGateManager = None

class FortiGateManager:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        api_token: str = None,
        verify_ssl: bool = False,
        timeout: int = 10,
        max_retries: int = 0,
        ssh_username: str = None,
        ssh_password: str = None,
        ssh_port: int = 22,
    ):
        self.host = host.rstrip('/')
        self.username = username
        self.password = password
        self.api_token = api_token
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.timeout = timeout
        # SSH-only 或 API 皆可（本版本走 SSH-only）
        self.pending_tasks = []
        # SSH 設定（可選）
        self.ssh_username = ssh_username
        self.ssh_password = ssh_password
        self.ssh_port = ssh_port
        
        # 重試機制
        if max_retries and max_retries > 0:
            retry_strategy = Retry(
                total=max_retries,
                backoff_factor=0.5,
                status_forcelist=[429, 500, 502, 503, 504],
                # 僅對 GET 啟用重試，避免寫入操作重試造成 500 疊加
                allowed_methods=["GET"],
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            self.session.mount("https://", adapter)
            self.session.mount("http://", adapter)

    def _cli_ok(self, stdout_data: bytes, stderr_data: bytes) -> bool:
        """粗略判斷 FortiGate CLI 是否成功。"""
        try:
            out = (stdout_data or b'').decode(errors='ignore')
            err = (stderr_data or b'').decode(errors='ignore')
        except Exception:
            out = str(stdout_data)
            err = str(stderr_data)
        text = f"{out}\n{err}".lower()
        # FortiGate 失敗訊息常見關鍵字
        failure_markers = [
            'command fail',
            'error',
            'unknown action',
            'invalid',
        ]
        return not any(marker in text for marker in failure_markers)

    def _extract_hostname(self) -> str:
        try:
            parsed = urlparse(self.host)
            return parsed.hostname or self.host.replace('https://', '').replace('http://', '')
        except Exception:
            return self.host

    def _ssh_set_macaddr(self, name: str, mac: str) -> bool:
        if not (self.ssh_username and self.ssh_password):
            return False

    def ssh_unselect_member(self, group_name: str, address_name: str) -> bool:
        """SSH 從群組移除成員"""
        try:
            host = self._extract_hostname()
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, port=self.ssh_port, username=self.ssh_username, password=self.ssh_password,
                           look_for_keys=False, allow_agent=False, timeout=self.timeout)
            cmd = f"config firewall addrgrp\nedit \"{group_name}\"\nunselect member \"{address_name}\"\nnext\nend\n"
            stdin, stdout, stderr = client.exec_command(cmd, timeout=self.timeout)
            _ = stdout.read()
            client.close()
            return True
        except Exception as e:
            print(f"SSH 群組移除失敗: {e}")
            return False

    def ssh_rename_address(self, old_name: str, new_name: str) -> bool:
        """SSH 重新命名地址物件"""
        try:
            host = self._extract_hostname()
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, port=self.ssh_port, username=self.ssh_username, password=self.ssh_password,
                           look_for_keys=False, allow_agent=False, timeout=self.timeout)
            cmd = f"config firewall address\nrename \"{old_name}\" to \"{new_name}\"\nend\n"
            stdin, stdout, stderr = client.exec_command(cmd, timeout=self.timeout)
            _ = stdout.read()
            client.close()
            return True
        except Exception as e:
            print(f"SSH 重新命名失敗: {e}")
            return False
    
    def ssh_rename_group(self, old_name: str, new_name: str) -> bool:
        """SSH 重新命名地址群組物件"""
        try:
            host = self._extract_hostname()
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=host,
                port=self.ssh_port,
                username=self.ssh_username,
                password=self.ssh_password,
                look_for_keys=False,
                allow_agent=False,
                timeout=self.timeout,
            )
            cmd = f"config firewall addrgrp\nrename \"{old_name}\" to \"{new_name}\"\nend\n"
            stdin, stdout, stderr = client.exec_command(cmd, timeout=self.timeout)
            _ = stdout.read()
            client.close()
            return True
        except Exception as e:
            print(f"SSH 重新命名群組失敗: {e}")
            return False
        host = self._extract_hostname()
        print(f"[SSH] 連線至 {host}:{self.ssh_port} 設定 macaddr...")
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, port=self.ssh_port, username=self.ssh_username, password=self.ssh_password, look_for_keys=False, allow_agent=False, timeout=self.timeout)
            chan = client.invoke_shell()
            def send(cmd: str):
                chan.send(cmd + "\n")
                time.sleep(0.3)
            send("config firewall address")
            send(f"edit \"{name}\"")
            send("set type mac")
            send(f"set macaddr {mac}")
            send("next")
            send("end")
            time.sleep(0.5)
            client.close()
            print("[SSH] 已嘗試設定 macaddr")
            return True
        except Exception as e:
            print(f"[SSH] 設定失敗: {e}")
            return False
        
    def login(self) -> bool:
        """SSH-only：測試 SSH 連線"""
        if not (self.ssh_username and self.ssh_password):
            print("✗ 未提供 SSH 憑證，請設定或於執行時輸入")
            return False
        host = self._extract_hostname()
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, port=self.ssh_port, username=self.ssh_username, password=self.ssh_password, look_for_keys=False, allow_agent=False, timeout=self.timeout)
            client.close()
            print("✓ SSH 連線成功")
            return True
        except Exception as e:
            print(f"✗ SSH 連線失敗: {e}")
            return False
    
    def get_system_status(self) -> Dict:
        """SSH-only：嘗試取得 hostname 與版本"""
        host = self._extract_hostname()
        info = {"hostname": host}
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, port=self.ssh_port, username=self.ssh_username, password=self.ssh_password, look_for_keys=False, allow_agent=False, timeout=self.timeout)
            # 讀 hostname
            stdin, stdout, stderr = client.exec_command("get system status\n", timeout=self.timeout)
            out = stdout.read().decode(errors='ignore')
            client.close()
            info['raw'] = out
            for line in out.splitlines():
                s = line.strip()
                if s.lower().startswith('hostname:'):
                    info['hostname'] = s.split(':',1)[1].strip()
                if s.lower().startswith('version:'):
                    info['version'] = s.split(':',1)[1].strip()
            return info
        except Exception:
            return info
    
    def get_network_interfaces(self) -> List[Dict]:
        """SSH-only：不掃描設備介面（本工具僅需本機 MAC）"""
        return []
    
    def get_address_objects(self) -> List[Dict]:
        """SSH-only：解析 config firewall address 輸出（簡化且更穩定的解析）。"""
        host = self._extract_hostname()

        def parse_output(text: str) -> Dict[str, Dict]:
            result: Dict[str, Dict] = {}
            if not text:
                return result
            # 以 edit "name" ... next 為區塊解析
            for m in re.finditer(r'^\s*edit\s+"([^"]+)"\s*([\s\S]*?)^\s*next\b', text, re.MULTILINE):
                name = m.group(1)
                block = m.group(2)
                item: Dict[str, str] = {"name": name}
                mt = re.search(r'^\s*set\s+type\s+(\S+)', block, re.MULTILINE)
                if mt:
                    item['type'] = mt.group(1)
                mmac = re.search(r'^\s*set\s+macaddr\s+"?([0-9A-Fa-f:]+)"?', block, re.MULTILINE)
                if mmac:
                    item['macaddr'] = normalize_mac(mmac.group(1))
                mcomment = re.search(r'^\s*set\s+comment\s+"([^"]*)"', block, re.MULTILINE)
                if mcomment:
                    item['comment'] = mcomment.group(1)
                minter = re.search(r'^\s*set\s+interface\s+"?([^"\s]+)"?', block, re.MULTILINE)
                if minter:
                    item['interface'] = minter.group(1)
                result[name] = item
            return result

        try:
            # 先取 full-configuration
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, port=self.ssh_port, username=self.ssh_username, password=self.ssh_password, look_for_keys=False, allow_agent=False, timeout=self.timeout)
            stdin, stdout, stderr = client.exec_command("config firewall address\nshow full-configuration\nend\n", timeout=self.timeout)
            out_full = stdout.read().decode(errors='ignore')
            client.close()
        except Exception as e:
            print(f"SSH 取得地址物件失敗(full): {e}")
            out_full = ''

        try:
            # 再取 show（非 full），有時某些欄位/物件會僅在此呈現
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, port=self.ssh_port, username=self.ssh_username, password=self.ssh_password, look_for_keys=False, allow_agent=False, timeout=self.timeout)
            stdin, stdout, stderr = client.exec_command("config firewall address\nshow\nend\n", timeout=self.timeout)
            out_show = stdout.read().decode(errors='ignore')
            client.close()
        except Exception as e:
            print(f"SSH 取得地址物件失敗(show): {e}")
            out_show = ''

        # 合併解析結果（以名稱為鍵，補欄位的方式合併）
        merged: Dict[str, Dict] = parse_output(out_full)
        show_map: Dict[str, Dict] = parse_output(out_show)
        for name, item in show_map.items():
            if name not in merged:
                merged[name] = item
            else:
                # 逐欄位補齊
                for key in ('type', 'macaddr', 'comment', 'interface'):
                    if key not in merged[name] or not merged[name].get(key):
                        if item.get(key):
                            merged[name][key] = item[key]
        return list(merged.values())
    
    def get_address_groups(self) -> List[Dict]:
        """SSH-only：解析 config firewall addrgrp 輸出"""
        host = self._extract_hostname()
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, port=self.ssh_port, username=self.ssh_username, password=self.ssh_password, look_for_keys=False, allow_agent=False, timeout=self.timeout)
            stdin, stdout, stderr = client.exec_command("config firewall addrgrp\nshow\nend\n", timeout=self.timeout)
            out = stdout.read().decode(errors='ignore')
            client.close()
            results = []
            current = None
            for line in out.splitlines():
                s = line.strip()
                if s.startswith('edit '):
                    remainder = s[5:].strip()
                    if '"' in remainder:
                        name = remainder.split('"')[1]
                    else:
                        name = remainder.split()[0] if remainder else ''
                    current = {"name": name, "member": []}
                elif s.startswith('set member '):
                    buf = s[len('set member '):]
                    parts = buf.split('"')
                    if len(parts) > 1:
                        for i in range(1, len(parts), 2):
                            mname = parts[i]
                            if mname:
                                current["member"].append({"name": mname})
                    else:
                        # 無引號情況：以空白切分
                        tokens = buf.split()
                        for tok in tokens:
                            if tok:
                                current["member"].append({"name": tok})
                elif s == 'next' and current is not None:
                    results.append(current)
                    current = None
            return results
        except Exception as e:
            print(f"SSH 取得地址群組失敗: {e}")
            return []

    def dump_raw_addresses(self) -> str:
        """SSH：回傳 address 的原始輸出（full-configuration）"""
        host = self._extract_hostname()
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, port=self.ssh_port, username=self.ssh_username, password=self.ssh_password, look_for_keys=False, allow_agent=False, timeout=self.timeout)
            cmd = "config firewall address\nshow full-configuration\nend\n"
            stdin, stdout, stderr = client.exec_command(cmd, timeout=self.timeout)
            out = stdout.read().decode(errors='ignore')
            client.close()
            return out
        except Exception as e:
            return f"(dump address failed: {e})"

    def dump_raw_groups(self) -> str:
        """SSH：回傳 addrgrp 的原始輸出（full-configuration）"""
        host = self._extract_hostname()
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, port=self.ssh_port, username=self.ssh_username, password=self.ssh_password, look_for_keys=False, allow_agent=False, timeout=self.timeout)
            cmd = "config firewall addrgrp\nshow full-configuration\nend\n"
            stdin, stdout, stderr = client.exec_command(cmd, timeout=self.timeout)
            out = stdout.read().decode(errors='ignore')
            client.close()
            return out
        except Exception as e:
            return f"(dump groups failed: {e})"
    
    def create_address(self, name: str, mac: str) -> bool:
        """SSH-only：創建 MAC 地址物件"""
        try:
            mac = normalize_mac(mac)
            host = self._extract_hostname()
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, port=self.ssh_port, username=self.ssh_username, password=self.ssh_password, look_for_keys=False, allow_agent=False, timeout=self.timeout)
            cmd = f"config firewall address\nedit \"{name}\"\nset type mac\nset macaddr \"{mac}\"\nset comment \"Auto created by MAC automation tool\"\nnext\nend\n"
            stdin, stdout, stderr = client.exec_command(cmd, timeout=self.timeout)
            out = stdout.read()
            err = stderr.read()
            client.close()
            time.sleep(1.0)
            return self._cli_ok(out, err)
        except Exception as e:
            print(f"SSH 創建地址物件失敗: {e}")
            return False
    
    def delete_address(self, name: str) -> bool:
        """SSH-only：刪除地址物件"""
        try:
            host = self._extract_hostname()
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, port=self.ssh_port, username=self.ssh_username, password=self.ssh_password, look_for_keys=False, allow_agent=False, timeout=self.timeout)
            cmd = f"config firewall address\ndelete \"{name}\"\nend\n"
            stdin, stdout, stderr = client.exec_command(cmd, timeout=self.timeout)
            out = stdout.read()
            err = stderr.read()
            client.close()
            time.sleep(1.0)
            return self._cli_ok(out, err)
        except Exception as e:
            print(f"SSH 刪除地址物件失敗: {e}")
            return False

    def delete_group(self, name: str) -> bool:
        """SSH-only：刪除地址群組物件"""
        try:
            host = self._extract_hostname()
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, port=self.ssh_port, username=self.ssh_username, password=self.ssh_password, look_for_keys=False, allow_agent=False, timeout=self.timeout)
            cmd = f"config firewall addrgrp\ndelete \"{name}\"\nend\n"
            stdin, stdout, stderr = client.exec_command(cmd, timeout=self.timeout)
            _ = stdout.read()
            client.close()
            time.sleep(1.0)
            return True
        except Exception as e:
            print(f"SSH 刪除群組失敗: {e}")
            return False
    
    def add_to_group(self, group_name: str, address_name: str) -> bool:
        """SSH-only：將地址加入群組（append member）"""
        try:
            host = self._extract_hostname()
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, port=self.ssh_port, username=self.ssh_username, password=self.ssh_password, look_for_keys=False, allow_agent=False, timeout=self.timeout)
            cmd = f"config firewall addrgrp\nedit \"{group_name}\"\nappend member \"{address_name}\"\nnext\nend\n"
            stdin, stdout, stderr = client.exec_command(cmd, timeout=self.timeout)
            out = stdout.read()
            err = stderr.read()
            client.close()
            time.sleep(1.0)
            return self._cli_ok(out, err)
        except Exception as e:
            print(f"SSH 加入群組失敗: {e}")
            return False

class MACAutomationTool:
    def __init__(self):
        self.fortigate = None
        self.network_devices = []
        self.existing_addresses = []
        self.existing_groups = []
        self.pending_tasks = []
        # 主選單索引對照表：{ device_index: { 'addresses': {j: addr_name}, 'groups': { 'j.k': {address_name, group_name} } } }
        self.menu_index_map: Dict[int, Dict[str, Dict]] = {}
        self.enable_test = False
        self.show_another = False
        self.scroll_output = True
        # 移除 another 功能（不再使用）
        self.another_index_map: Dict[str, Dict] = {}
    
    def parse_menu_target(self, idx: str) -> Optional[Dict]:
        """解析目標索引：支援 N | i.j | i.j.k，回傳目標資訊字典。"""
        try:
            if not idx:
                return None
            # N -> 裝置
            if idx.isdigit():
                device_index = int(idx)
                if 1 <= device_index <= len(self.network_devices):
                    return {"type": "device", "device_index": device_index}
                return None
            parts_idx = idx.split('.')
            # i.j -> 現有地址
            if len(parts_idx) == 2 and all(p.isdigit() for p in parts_idx):
                i_idx, j_idx = int(parts_idx[0]), int(parts_idx[1])
                mapping = self.menu_index_map.get(i_idx, {}).get('addresses', {})
                addr_name = mapping.get(j_idx)
                if addr_name:
                    return {"type": "address", "device_index": i_idx, "address_name": addr_name}
                return None
            # i.j.k -> 現有群組（掛在某地址下）
            if len(parts_idx) == 3 and all(p.isdigit() for p in parts_idx):
                i_idx, j_idx, k_idx = int(parts_idx[0]), int(parts_idx[1]), int(parts_idx[2])
                mapping = self.menu_index_map.get(i_idx, {}).get('groups', {})
                target = mapping.get(f"{j_idx}.{k_idx}")
                if target:
                    return {
                        'type': 'group',
                        'device_index': i_idx,
                        'group_name': target.get('group_name'),
                        'address_name': target.get('address_name')
                    }
                return None
            return None
        except Exception:
            return None
        
    def show_spinner(self, seconds: float = 1.0, message: str = "請稍候") -> None:
        """簡易等待動畫"""
        spinner = ['|', '/', '-', '\\']
        steps = max(1, int(seconds / 0.1))
        for i in range(steps):
            sys.stdout.write(f"\r{message} {spinner[i % len(spinner)]}")
            sys.stdout.flush()
            time.sleep(0.1)
        # 根據設定決定是換行滾動，或清除同一行
        if self.scroll_output:
            sys.stdout.write("\n")
        else:
            sys.stdout.write("\r" + " " * (len(message) + 2) + "\r")
        
    def get_network_devices(self) -> List[Dict]:
        """獲取本機 MAC 地址"""
        scanner = SimpleMACScanner()
        return scanner.get_local_mac_addresses()
    
    def match_existing_configs(self, mac: str) -> Tuple[List[Dict], List[Dict]]:
        """比對現有設定"""
        addresses = []
        groups = []
        
        # 轉為統一格式
        if isinstance(mac, list):
            mac = mac[0] if mac else ''
        mac_str = normalize_mac(str(mac))
        
        # 僅比對 type=mac 且有 macaddr 的地址
        for addr in self.existing_addresses:
            if str(addr.get('type','')).lower() != 'mac':
                continue
            addr_mac_raw = addr.get('macaddr', '')
            addr_mac = normalize_mac(str(addr_mac_raw)) if addr_mac_raw else ''
            if addr_mac == mac_str:
                addresses.append(addr)
        
        for group in self.existing_groups:
            # 檢查群組成員中是否有匹配的 MAC
            members = group.get('member', [])
            for member in members:
                member_addr = next((a for a in self.existing_addresses if a.get('name') == member.get('name')), None)
                if member_addr:
                    member_mac_raw = member_addr.get('macaddr', '')
                    member_mac = normalize_mac(str(member_mac_raw)) if member_mac_raw else ''
                    if member_mac == mac_str:
                        groups.append(group)
                        break
        
        return addresses, groups
    
    def get_allow_groups(self) -> List[Dict]:
        """獲取以 'Allow' 開頭的群組"""
        return [group for group in self.existing_groups if group.get('name', '').startswith('Allow')]
    
    def get_groups_for_address(self, address_name: str) -> List[Dict]:
        """取得某個地址物件所屬的群組清單"""
        groups: List[Dict] = []
        for group in self.existing_groups:
            members = group.get('member', [])
            for member in members:
                if isinstance(member, dict) and member.get('name') == address_name:
                    groups.append(group)
                    break
                if isinstance(member, str) and member == address_name:
                    groups.append(group)
                    break
        return groups
    
    def get_another_addresses_for_device(self, device_index: int) -> List[Tuple[str, str]]:
        """回傳與指定裝置 MAC 不同的 address 清單 (名稱, MAC)。"""
        others: List[Tuple[str, str]] = []
        if not (1 <= device_index <= len(self.network_devices)):
            return others
        dev = self.network_devices[device_index - 1]
        dev_mac = normalize_mac(str(dev.get('mac', '')))
        for addr in self.existing_addresses:
            mac_raw = addr.get('macaddr', '')
            mac_norm = normalize_mac(str(mac_raw)) if mac_raw else ''
            if mac_norm and mac_norm != dev_mac:
                others.append((addr.get('name', ''), mac_norm))
        return others
    
    def display_main_menu(self):
        """顯示主選單"""
        print("\n" + "="*60)
        print("FortiGate MAC 設定自動化工具")
        print("="*60)
        # 每次顯示主選單前重建索引對照
        self.menu_index_map = {}
        self.another_index_map = {}
        
        if not self.network_devices:
            print("未找到網路裝置")
            return
        
        print("\n要設定哪個網路裝置?")
        print()
        
        for i, device in enumerate(self.network_devices, 1):
            mac = normalize_mac(str(device.get('mac', '')))
            name = str(device.get('name', 'Unknown'))
            
            print(f"{i}. {name} [MAC] {mac}")
            
            # 改為目標查詢：直接以 MAC 在防火牆端查詢匹配的 address
            try:
                if not self.fortigate.debug_commands:
                    logger.info(f"query_by_mac: device={name} mac={mac}")
                addresses = self.fortigate.find_addresses_by_mac_remote(mac)
                if not self.fortigate.debug_commands:
                    logger.info(f"query_by_mac: device={name} mac={mac} results={len(addresses)}")
            except Exception:
                if not self.fortigate.debug_commands:
                    logger.warning("query_by_mac: remote failed; fallback to local match")
                addresses, _ = self.match_existing_configs(mac)
            # 建立裝置索引結構
            self.menu_index_map[i] = { 'addresses': {}, 'groups': {} }
            for j, addr in enumerate(addresses, 1):
                addr_name = addr.get('name')
                addr_mac = addr.get('macaddr')
                print(f"{i}.{j}. ADDRESS [Name] {addr_name} [MAC] {addr_mac}")
                self.menu_index_map[i]['addresses'][j] = addr_name
                # 在每個 ADDRESS 底下列出其所屬群組（不帶索引，僅顯示）
                addr_groups = self.get_groups_for_address(addr_name)
                for k, g in enumerate(addr_groups, 1):
                    group_name = g.get('name')
                    # 顯示 j.k 群組索引
                    print(f"      └─ {i}.{j}.{k} GROUP [Name] {group_name}")
                    self.menu_index_map[i]['groups'][f"{j}.{k}"] = {
                        'address_name': addr_name,
                        'group_name': group_name
                    }
            
            # 顯示待辦工作（已移除：使用即時執行，不再顯示待辦）
        
        # 空一行後顯示功能表
        print()
        if self.enable_test:
            print("t. Test")
        # 新指令選單
        print("name")
        print("joingroup")
        print("leavegroup")
        print("del")
        print("q. Exit")

    def test_dump(self):
        """測試功能：不解析，直接 dump address 與 group"""
        try:
            print("\n===== RAW DUMP (address) =====")
            addr_raw = self.fortigate.dump_raw_addresses()
            print(addr_raw)
        except Exception as e:
            print(f"(address dump error: {e})")
        try:
            print("\n===== RAW DUMP (addrgrp) =====")
            grp_raw = self.fortigate.dump_raw_groups()
            print(grp_raw)
        except Exception as e:
            print(f"(group dump error: {e})")

    def show_another_list(self):
        print("(another 功能已移除)")

    def existing_address_menu(self, device_index: int, address_index: int):
        """針對 i.j（現有地址）進行改名與加入群組（排除已在群組）。"""
        device = self.network_devices[device_index - 1]
        mac = str(device.get('mac', ''))
        addresses, _ = self.match_existing_configs(mac)
        if not (1 <= address_index <= len(addresses)):
            print("錯誤：無效的地址索引")
            input("按任意鍵繼續...")
            return
        addr_obj = addresses[address_index - 1]
        address_name = addr_obj.get('name', '')

        # 改名
        rename_choice = input(f"是否修改地址名稱 '{address_name}'？(y/n): ").strip().lower()
        if rename_choice == 'y':
            existing_names = {str(a.get('name', '')) for a in self.existing_addresses}
            while True:
                new_name = input("請輸入新名稱: ").strip()
                if not new_name:
                    print("名稱保持不變")
                    break
                if new_name == address_name:
                    print("名稱未變更")
                    break
                if new_name in existing_names:
                    print("✗ 名稱已存在，請重新輸入")
                    continue
                if self.fortigate.ssh_rename_address(address_name, new_name):
                    print("✓ 已修改名稱")
                    address_name = new_name
                    self.show_spinner(1.0, "同步設備狀態...")
                    self.refresh_existing_configs()
                else:
                    print("✗ 修改名稱失敗")
                break

        # 加入群組，排除已在群組
        current_groups = {g.get('name') for g in self.get_groups_for_address(address_name)}
        candidate_groups = [g for g in self.existing_groups if g.get('name') not in current_groups]
        if not candidate_groups:
            print("(沒有可加入的群組)")
            input("按任意鍵繼續...")
            return
        print("\n可加入的群組:")
        for i, g in enumerate(candidate_groups, 1):
            print(f"({i}). [Group Name] {g.get('name')}")
        sel = input("\n要加入哪些群組?（以逗號分隔，空白略過）: ").strip()
        if sel:
            try:
                indices = [int(x.strip()) - 1 for x in sel.split(',')]
                targets = [candidate_groups[i].get('name') for i in indices if 0 <= i < len(candidate_groups)]
            except ValueError:
                print("輸入格式錯誤")
                input("按任意鍵繼續...")
                return
            for gname in targets:
                ok = self.fortigate.add_to_group(gname, address_name)
                print(f"加入群組 {gname}:", "✓" if ok else "✗")
            self.show_spinner(1.0, "同步設備狀態...")
            self.refresh_existing_configs()

    def another_address_menu(self, z_index: int):
        """針對 z.N 進行改名與刪除；z.N.k 由一般解析流程處理移除群組。"""
        mapping = self.another_index_map.get('addresses', {})
        addr_name = mapping.get(z_index)
        if not addr_name:
            print("錯誤：找不到對應的 another 索引")
            input("按任意鍵繼續...")
            return
        # 改名
        rename_choice = input(f"是否修改地址名稱 '{addr_name}'？(y/n): ").strip().lower()
        if rename_choice == 'y':
            existing_names = {str(a.get('name', '')) for a in self.existing_addresses}
            while True:
                new_name = input("請輸入新名稱: ").strip()
                if not new_name:
                    print("名稱保持不變")
                    break
                if new_name == addr_name:
                    print("名稱未變更")
                    break
                if new_name in existing_names:
                    print("✗ 名稱已存在，請重新輸入")
                    continue
                if self.fortigate.ssh_rename_address(addr_name, new_name):
                    print("✓ 已修改名稱")
                    addr_name = new_name
                    self.show_spinner(1.0, "同步設備狀態...")
                    self.refresh_existing_configs()
                else:
                    print("✗ 修改名稱失敗")
                break
        # 刪除（若不在任何群組中）
        in_groups = []
        for g in self.existing_groups:
            for m in g.get('member', []):
                mname = m.get('name') if isinstance(m, dict) else (m if isinstance(m, str) else '')
                if mname == addr_name:
                    in_groups.append(g.get('name',''))
                    break
        if in_groups:
            print(f"✗ 無法刪除：地址 '{addr_name}' 仍在群組中: {', '.join(in_groups)}")
            input("按任意鍵繼續...")
            return
        del_choice = input(f"是否刪除地址 '{addr_name}'？(y/n): ").strip().lower()
        if del_choice == 'y':
            ok = self.fortigate.delete_address(addr_name)
            print("刪除地址:", "✓" if ok else "✗")
            self.show_spinner(1.0, "同步設備狀態...")
            self.refresh_existing_configs()
    
    def work_menu(self, device_index: int):
        """工作選單"""
        device = self.network_devices[device_index - 1]
        mac = str(device.get('mac', ''))
        name = str(device.get('name', 'Unknown'))
        
        print(f"\n{device_index}. {name} [MAC] {mac}")
        
        # 詢問要設定的名字（避免重複名稱）
        existing_names = {str(a.get('name', '')) for a in self.existing_addresses}
        pending_names = {str(t.get('name', '')) for t in self.pending_tasks if t.get('type') == 'create_address'}
        while True:
            address_name = input("\nInput Define Name (empty for skip): ").strip()
            # 允許在名稱輸入階段直接使用快捷鍵
            if not address_name:
                return
            lower_name = address_name.lower()
            if lower_name in ("r", "reset"):
                return self.work_menu(device_index)
            if lower_name in ("c", "cancel", "q", "quit"):
                return
            
            if address_name in existing_names:
                print(f"✗ 名稱已存在於防火牆地址物件：{address_name}")
                print("請輸入新名稱，或按 c 取消 / r 重來")
                continue
            if address_name in pending_names:
                print(f"✗ 名稱已存在於待辦清單：{address_name}")
                print("請輸入新名稱，或按 c 取消 / r 重來")
                continue
            break
        
        # 顯示所有可用的群組供選擇
        all_groups = self.existing_groups
        selected_groups = []
        
        if all_groups:
            print(f"\n>1. update [Name] {address_name}")
            print("\n可用的群組:")
            for i, group in enumerate(all_groups, 1):
                group_name = group.get('name', 'Unknown')
                member_count = len(group.get('member', []))
                print(f"({i}). [Group Name] {group_name} (成員: {member_count})")
            
            group_input = input("\nWhich groups should I join (Enter multiple options with commas|empty for skip)? ").strip()
            
            if group_input:
                try:
                    indices = [int(x.strip()) - 1 for x in group_input.split(',')]
                    selected_groups = [all_groups[i].get('name') for i in indices if 0 <= i < len(all_groups)]
                except ValueError:
                    print("輸入格式錯誤")
                    return
        
        # 顯示結果
        print(f"\n{device_index}. {name} [MAC] {mac}")
        print(f">1. update [Name] {address_name}")
        
        for i, group in enumerate(selected_groups, 2):
            print(f">{i}. add to Group [Group Name] {group}")
        
        print("\nr. Reset")
        print("x. Execute")
        print("c. Cancel")
        
        while True:
            choice = input("\n請選擇: ").strip().lower()
            if choice == 'r':
                return self.work_menu(device_index)
            elif choice == 'x':
                # 立刻執行：建立地址與加入群組
                created = self.fortigate.create_address(address_name, mac)
                print("建立地址:", "✓" if created else "✗")
                for group in selected_groups:
                    ok = self.fortigate.add_to_group(group, address_name)
                    print(f"加入群組 {group}:", "✓" if ok else "✗")
                self.show_spinner(1.0, "同步設備狀態...")
                self.refresh_existing_configs()
                break
            elif choice == 'c':
                break
            elif choice == '1':
                # 重新輸入地址名稱，亦要檢查重複
                existing_names = {str(a.get('name', '')) for a in self.existing_addresses}
                pending_names = {str(t.get('name', '')) for t in self.pending_tasks if t.get('type') == 'create_address'}
                while True:
                    new_address_name = input(f"請輸入新的地址名稱 (目前: {address_name}): ").strip()
                    if not new_address_name:
                        print("地址名稱保持不變")
                        break
                    lower_new = new_address_name.lower()
                    if lower_new in ("r", "reset"):
                        return self.work_menu(device_index)
                    if lower_new in ("c", "cancel", "q", "quit"):
                        return
                    if new_address_name in existing_names:
                        print(f"✗ 名稱已存在於防火牆地址物件：{new_address_name}")
                        continue
                    if new_address_name in pending_names:
                        print(f"✗ 名稱已存在於待辦清單：{new_address_name}")
                        continue
                    address_name = new_address_name
                    print(f"地址名稱已更新為: {address_name}")
                    break
            elif choice == '2' and len(selected_groups) >= 1:
                # 重新選擇群組
                print("\n重新選擇群組:")
                for i, group in enumerate(all_groups, 1):
                    group_name = group.get('name', 'Unknown')
                    member_count = len(group.get('member', []))
                    print(f"({i}). [Group Name] {group_name} (成員: {member_count})")
                
                group_input = input("\nWhich groups should I join (Enter multiple options with commas|empty for skip)? ").strip()
                
                if group_input:
                    try:
                        indices = [int(x.strip()) - 1 for x in group_input.split(',')]
                        selected_groups = [all_groups[i].get('name') for i in indices if 0 <= i < len(all_groups)]
                        print(f"已選擇 {len(selected_groups)} 個群組")
                    except ValueError:
                        print("輸入格式錯誤")
                else:
                    selected_groups = []
                    print("已清除所有群組選擇")
            else:
                print("無效選擇")
                print("可用選項: r(重置), n(下一步), c(取消), 1(修改地址名稱), 2(修改群組選擇)")
    
    def delete_existing_item(self, device_index: int, item_index: int):
        """刪除現有項目"""
        device = self.network_devices[device_index - 1]
        mac = str(device.get('mac', ''))
        addresses, groups = self.match_existing_configs(mac)
        
        all_items = addresses + groups
        if 1 <= item_index <= len(all_items):
            item = all_items[item_index - 1]
            
            if item in addresses:
                item_type = "ADDRESS"
                item_name = item.get('name')
            else:
                item_type = "GROUP"
                item_name = item.get('name')
            
            if item in addresses:
                # 先詢問是否修改名稱
                rename_choice = input(f"是否修改地址名稱 '{item_name}'？(y/n): ").strip().lower()
                if rename_choice == 'y':
                    new_name = input("請輸入新名稱: ").strip()
                    if new_name and new_name != item_name:
                        if self.fortigate.ssh_rename_address(item_name, new_name):
                            print("✓ 已修改名稱")
                            self.show_spinner(1.0, "同步設備狀態...")
                            self.refresh_existing_configs()
                            item_name = new_name
                        else:
                            print("✗ 修改名稱失敗")
                # 再詢問是否刪除，若該地址仍在任何群組中，禁止刪除
                in_groups = []
                for g in self.existing_groups:
                    for m in g.get('member', []):
                        mname = m.get('name') if isinstance(m, dict) else (m if isinstance(m, str) else '')
                        if mname == item_name:
                            in_groups.append(g.get('name',''))
                            break
                if in_groups:
                    print(f"✗ 無法刪除：地址 '{item_name}' 仍在群組中: {', '.join(in_groups)}")
                    return
                del_choice = input(f"是否刪除地址 '{item_name}'？(y/n): ").strip().lower()
                if del_choice == 'y':
                    self.pending_tasks.append({'type': 'delete_address', 'mac': mac, 'name': item_name})
                    print(f"已排入刪除工作: {item_name}")
            else:
                # GROUP 項目不在這裡刪除，由 i.j.k 直接執行移除
                print("提示：選取群組請用 i.j.k 直接移除該地址出群組")
        
    def remove_address_from_group_prompt(self, group_name: str, address_name: str):
        """詢問並將地址自群組移除（立即執行，SSH）"""
        confirm = input(f"\n將 ADDRESS '{address_name}' 自 GROUP '{group_name}' 移除？(y/n): ").strip().lower()
        if confirm != 'y':
            return
        ok = self.fortigate.ssh_unselect_member(group_name, address_name)
        if ok:
            self.show_spinner(1.0, "同步設備狀態...")
            print("✓ 已自群組移除")
        else:
            print("✗ 自群組移除失敗")
        input("按任意鍵繼續...")

    def refresh_existing_configs(self):
        """重新讀取現有的地址與群組資料，確保主選單最新"""
        try:
            self.show_spinner(1.0, "讀取設備位址物件...")
            self.existing_addresses = self.fortigate.get_address_objects()
            self.show_spinner(1.0, "讀取設備群組物件...")
            self.existing_groups = self.fortigate.get_address_groups()
        except Exception as e:
            print(f"重新整理現有設定失敗: {e}")
    
    def execute_tasks(self):
        """執行所有待辦工作"""
        print("\n(即時模式) 沒有可執行的待辦。請透過工作選單 x 直接執行。")
    
    def load_config(self) -> Dict:
        """載入 config.ini 設定檔"""
        config = configparser.ConfigParser()
        config_file = 'config.ini'
        
        if os.path.exists(config_file):
            try:
                config.read(config_file, encoding='utf-8')
                return {
                    'host': config.get('FortiGate', 'host', fallback=''),
                    'username': config.get('FortiGate', 'username', fallback=''),
                    'api_token': config.get('FortiGate', 'api_token', fallback=''),
                    'ssh_username': config.get('FortiGate', 'ssh_username', fallback=''),
                    'ssh_password': config.get('FortiGate', 'ssh_password', fallback=''),
                    'ssh_port': config.getint('FortiGate', 'ssh_port', fallback=22),
                    'enable_test': config.getboolean('Debug', 'enable_test', fallback=False),
                    'verify_ssl': config.getboolean('Security', 'verify_ssl', fallback=False),
                    'timeout': config.getint('Security', 'timeout', fallback=10),
                    'max_retries': config.getint('Security', 'max_retries', fallback=3)
                }
            except Exception as e:
                print(f"讀取設定檔失敗: {e}")
                return {}
        return {}
    
    def validate_config(self, config: Dict) -> bool:
        """驗證配置設定"""
        logger.info("驗證配置設定")
        
        # 檢查必要的設定：必須有 host，且需二擇一 (api_token 或 username)
        if not config.get('host'):
            logger.warning("缺少必要設定: host")
            return False
        
        has_token = bool(config.get('api_token'))
        has_username = bool(config.get('username'))
        if not (has_token or has_username):
            logger.warning("缺少必要設定：需提供 api_token 或 username 其中之一")
            return False
        
        # 驗證網址格式
        host = config.get('host', '')
        if not host.startswith(('http://', 'https://')):
            logger.warning("網址格式不正確，應包含 http:// 或 https://")
            return False
        
        # 驗證超時設定
        timeout = config.get('timeout', 10)
        if timeout < 1 or timeout > 60:
            logger.warning("超時設定應在 1-60 秒之間")
            return False
        
        logger.info("配置驗證通過")
        return True
    
    def run(self):
        """主程式執行"""
        print("FortiGate MAC 設定自動化工具")
        print("="*40)
        print(f"{APP_NAME} v{APP_VERSION}")
        
        # 載入設定檔
        config = self.load_config()
        
        # SSH-only：僅檢查 host 存在與格式
        if not config.get('host') or not str(config.get('host')).startswith(('http://','https://')):
            print("配置驗證失敗，請在 config.ini 設定正確的 host (http/https)")
            input("按任意鍵退出...")
            return
        
        # 從設定檔獲取連線資訊
        host = config.get('host', '').strip()
        username = config.get('ssh_username', '').strip()  # 顯示用
        api_token = ''  # SSH-only 不使用
        ssh_username = config.get('ssh_username', '').strip()
        ssh_password = config.get('ssh_password', '').strip()
        ssh_port = int(config.get('ssh_port', 22))
        verify_ssl = bool(config.get('verify_ssl', False))
        timeout = int(config.get('timeout', 10))
        max_retries = int(config.get('max_retries', 3))
        self.enable_test = bool(config.get('enable_test', False))
        # 讀取 debug 設定
        try:
            debug_flag = config.getboolean('Debug', 'debug', fallback=False)
        except Exception:
            debug_flag = False
        # 從 Display 讀取是否讓訊息向下流動
        try:
            self.scroll_output = config.getboolean('Display', 'scroll_output', fallback=True)
        except Exception:
            self.scroll_output = True
        
        # 顯示從設定檔讀取的資訊
        print(f"從 config.ini 讀取設定:", flush=True)
        print(f"  網址: {host if host else '(未設定)'}", flush=True)
        print(f"  使用者: {username if username else '(未設定)'} ", flush=True)
        print(flush=True)
        
        # 如果設定檔中沒有，則詢問使用者
        if not host:
            host = input("請輸入 FortiGate 網址: ").strip()
            if not host:
                print("錯誤：未輸入網址")
                print("請檢查 config.ini 檔案中的 host 設定，或手動輸入網址")
                input("按任意鍵退出...")
                return
        
        # 互動式輸入 SSH 憑證（優先於 config.ini）
        if not ssh_username:
            ssh_username = input("請輸入 SSH 使用者名稱: ").strip()
        if not ssh_password:
            ssh_password = getpass.getpass("請輸入 SSH 密碼: ")
        
        # 建立連線
        self.fortigate = FGClient(
            host=host,
            ssh_username=ssh_username or '',
            ssh_password=ssh_password or '',
            ssh_port=ssh_port,
            timeout=timeout,
        )
        # 傳遞 debug 設定到客戶端，控制是否 dump 指令與回覆
        try:
            self.fortigate.debug_commands = bool(debug_flag)
            logger.info(f"debug_commands={'on' if self.fortigate.debug_commands else 'off'}")
        except Exception:
            pass
        
        # 登入
        print(f"\n正在登入 {host}...")
        if not self.fortigate.login():
            input("按任意鍵退出...")
            return
        
        print("✓ 登入成功!")
        
        # 系統資訊：僅輸出第一行包含 Version 的原始行
        try:
            status = self.fortigate.get_system_status()
            if status:
                raw = (status.get('raw') or '').splitlines()
                version_line = next((ln for ln in raw if 'Version:' in ln), '').strip()
                if version_line:
                    print(version_line)
                else:
                    print(f"Hostname: {status.get('hostname', 'Unknown')}")
            else:
                print("(無法獲取系統資訊)")
        except Exception as e:
            print(f"(獲取系統資訊錯誤: {e})")
        
        # 獲取本機 MAC 地址
        print("\n正在獲取本機 MAC 地址...")
        try:
            self.network_devices = self.get_network_devices()
            if not self.network_devices:
                print("警告：未找到本機網路介面")
                print("可能的原因：")
                print("1. 需要管理員權限")
                print("2. 網路介面未啟用")
                print("3. 系統不支援")
            else:
                print(f"找到 {len(self.network_devices)} 個網路介面")
        except Exception as e:
            print(f"錯誤：獲取本機 MAC 地址時發生錯誤: {e}")
            self.network_devices = []
        
        # 獲取現有設定
        print("正在獲取現有設定...")
        try:
            # 僅抓群組；地址改為按裝置 MAC on-demand 查詢
            self.existing_groups = self.fortigate.get_address_groups()
            print(f"找到 {len(self.existing_groups)} 個地址群組")
            # Debug: dump 本機網路介面詳細資訊
            if self.enable_test and self.network_devices:
                print("\n[Local Interfaces]")
                for idx, dev in enumerate(self.network_devices, 1):
                    dn = str(dev.get('name','Unknown'))
                    dmac = normalize_mac(str(dev.get('mac','')))
                    dtyp = str(dev.get('type',''))
                    print(f"- ({idx}) name={dn} | mac={dmac} | type={dtyp}")
        except Exception as e:
            print(f"錯誤：獲取現有設定時發生錯誤: {e}")
            self.existing_groups = []
        
        # 主選單循環
        while True:
            try:
                self.display_main_menu()
                raw = input("\n請選擇: ")
                if raw is None:
                    raw = ''
                choice = raw.strip().lower()
                # 指令模式解析：name / joingroup / leavegroup
                if choice.startswith('name') or choice.startswith('joingroup') or choice.startswith('leavegroup'):
                    parts = raw.strip().split()
                    if not parts:
                        continue
                    cmd = parts[0].lower()
                    arg = parts[1] if len(parts) >= 2 else ''

                    def cmd_name_handler(target_str: str):
                        tgt = self.parse_menu_target(target_str)
                        if not tgt:
                            print("錯誤：name 指令需要有效的目標（N 或 i.j 或 i.j.k）")
                            input("按任意鍵繼續...")
                            return
                        if tgt['type'] == 'device':
                            dev = self.network_devices[tgt['device_index'] - 1]
                            mac = str(dev.get('mac', ''))
                            existing_names = {str(a.get('name', '')) for a in self.existing_addresses}
                            while True:
                                new_name = input(f"為 [網路裝置{tgt['device_index']}] 新建立 ADDRESS 物件，請問名稱? ").strip()
                                if not new_name:
                                    print("(取消)")
                                    return
                                if new_name in existing_names:
                                    print("✗ 名稱已存在，請重新輸入")
                                    continue
                                ok = self.fortigate.create_address(new_name, mac)
                                print("建立地址:", "✓" if ok else "✗")
                                self.show_spinner(1.0, "同步設備狀態...")
                                # 立即在本地快取加入，確保下一輪主選單可見
                                if ok:
                                    try:
                                        mac_n = normalize_mac(str(mac))
                                        if not any(str(a.get('name','')) == new_name for a in self.existing_addresses):
                                            self.existing_addresses.append({
                                                'name': new_name,
                                                'type': 'mac',
                                                'macaddr': mac_n
                                            })
                                    except Exception:
                                        pass
                                self.refresh_existing_configs()
                                # 若新物件尚未出現，額外再等待一次並重整
                                if not any(str(a.get('name','')) == new_name for a in self.existing_addresses):
                                    time.sleep(1.0)
                                    self.refresh_existing_configs()
                                return
                        if tgt['type'] == 'address':
                            old = tgt['address_name']
                            existing_names = {str(a.get('name', '')) for a in self.existing_addresses}
                            while True:
                                new_name = input(f"是否修改地址名稱 '{old}'，請輸入新名稱（空白取消）: ").strip()
                                if not new_name:
                                    print("(取消)")
                                    return
                                if new_name == old:
                                    print("名稱未變更")
                                    return
                                if new_name in existing_names:
                                    print("✗ 名稱已存在，請重新輸入")
                                    continue
                                ok = self.fortigate.ssh_rename_address(old, new_name)
                                print("修改地址名稱:", "✓" if ok else "✗")
                                self.show_spinner(1.0, "同步設備狀態...")
                                self.refresh_existing_configs()
                                return
                        if tgt['type'] == 'group':
                            old = tgt['group_name']
                            existing_group_names = {str(g.get('name', '')) for g in self.existing_groups}
                            while True:
                                new_name = input(f"是否修改群組名稱 '{old}'，請輸入新名稱（空白取消）: ").strip()
                                if not new_name:
                                    print("(取消)")
                                    return
                                if new_name == old:
                                    print("名稱未變更")
                                    return
                                if new_name in existing_group_names:
                                    print("✗ 群組名稱已存在，請重新輸入")
                                    continue
                                ok = self.fortigate.ssh_rename_group(old, new_name)
                                print("修改群組名稱:", "✓" if ok else "✗")
                                self.show_spinner(1.0, "同步設備狀態...")
                                self.refresh_existing_configs()
                                return

                    def cmd_joingroup_handler(target_str: str):
                        tgt = self.parse_menu_target(target_str)
                        if not tgt:
                            print("錯誤：joingroup 指令需要有效的目標（N 或 i.j 或 i.j.k）")
                            input("按任意鍵繼續...")
                            return
                        # 取得所有群組清單
                        all_groups = self.existing_groups
                        if tgt['type'] == 'device':
                            dev = self.network_devices[tgt['device_index'] - 1]
                            mac = str(dev.get('mac', ''))
                            # 先檢查是否已有對應此裝置 MAC 的 address
                            addrs, _ = self.match_existing_configs(mac)
                            if len(addrs) >= 1:
                                # 如有現有 address：若多個，先讓使用者選擇一個
                                if len(addrs) > 1:
                                    print("\n此裝置對應多個 ADDRESS，請選擇:")
                                    for i, a in enumerate(addrs, 1):
                                        print(f"({i}). [Name] {a.get('name','')} [MAC] {normalize_mac(str(a.get('macaddr','')))}")
                                    sel = input("選擇一個 ADDRESS（數字，空白取消）: ").strip()
                                    if not sel.isdigit():
                                        print("(取消)")
                                        return
                                    idx = int(sel) - 1
                                    if idx < 0 or idx >= len(addrs):
                                        print("(取消)")
                                        return
                                    target_addr_name = addrs[idx].get('name')
                                else:
                                    target_addr_name = addrs[0].get('name')
                                # 列出尚未加入的群組
                                current_groups = {g.get('name') for g in self.get_groups_for_address(target_addr_name)}
                                candidate_groups = [g for g in self.existing_groups if g.get('name') not in current_groups]
                                if not candidate_groups:
                                    print("(沒有可加入的群組)")
                                    input("按任意鍵繼續...")
                                    return
                                print("\n可加入的群組:")
                                for i, g in enumerate(candidate_groups, 1):
                                    print(f"({i}). [Group Name] {g.get('name')}")
                                sel = input("\n要加入哪些群組?（以逗號分隔，空白略過）: ").strip()
                                if sel:
                                    try:
                                        idxs = [int(x.strip()) - 1 for x in sel.split(',')]
                                        targets = [candidate_groups[i].get('name') for i in idxs if 0 <= i < len(candidate_groups)]
                                    except ValueError:
                                        print("輸入格式錯誤")
                                        input("按任意鍵繼續...")
                                        return
                                    for gname in targets:
                                        ok = self.fortigate.add_to_group(gname, target_addr_name)
                                        print(f"加入群組 {gname}:", "✓" if ok else "✗")
                                    self.show_spinner(1.0, "同步設備狀態...")
                                    self.refresh_existing_configs()
                                else:
                                    print("(未選擇群組)")
                                return
                            # 沒有現有 address：詢問新名稱 -> 建立 address -> 問要加入的群組
                            existing_names = {str(a.get('name', '')) for a in self.existing_addresses}
                            while True:
                                addr_name = input(f"為 [網路裝置{tgt['device_index']}] 新建立 ADDRESS 名稱（空白取消）: ").strip()
                                if not addr_name:
                                    print("(取消)")
                                    return
                                if addr_name in existing_names:
                                    print("✗ 名稱已存在，請重新輸入")
                                    continue
                                break
                            targets = []
                            if all_groups:
                                print("\n可用的群組:")
                                for i, g in enumerate(all_groups, 1):
                                    print(f"({i}). [Group Name] {g.get('name')}")
                                sel = input("\n要加入哪些群組?（以逗號分隔，空白略過）: ").strip()
                                if sel:
                                    try:
                                        idxs = [int(x.strip()) - 1 for x in sel.split(',')]
                                        targets = [all_groups[i].get('name') for i in idxs if 0 <= i < len(all_groups)]
                                    except ValueError:
                                        print("輸入格式錯誤")
                                        return
                            created = self.fortigate.create_address(addr_name, mac)
                            print("建立地址:", "✓" if created else "✗")
                            self.show_spinner(1.0, "同步設備狀態...")
                            # 立即在本地快取加入，確保下一輪主選單可見
                            if created:
                                try:
                                    mac_n = normalize_mac(str(mac))
                                    if not any(str(a.get('name','')) == addr_name for a in self.existing_addresses):
                                        self.existing_addresses.append({
                                            'name': addr_name,
                                            'type': 'mac',
                                            'macaddr': mac_n
                                        })
                                except Exception:
                                    pass
                            self.refresh_existing_configs()
                            # 若新物件尚未出現，額外再等待一次並重整
                            if not any(str(a.get('name','')) == addr_name for a in self.existing_addresses):
                                time.sleep(1.0)
                                self.refresh_existing_configs()
                            for gname in targets:
                                ok = self.fortigate.add_to_group(gname, addr_name)
                                print(f"加入群組 {gname}:", "✓" if ok else "✗")
                            self.show_spinner(1.0, "同步設備狀態...")
                            self.refresh_existing_configs()
                            return
                        if tgt['type'] == 'address':
                            addr_name = tgt['address_name']
                            current_groups = {g.get('name') for g in self.get_groups_for_address(addr_name)}
                            candidate_groups = [g for g in self.existing_groups if g.get('name') not in current_groups]
                            if not candidate_groups:
                                print("(沒有可加入的群組)")
                                input("按任意鍵繼續...")
                                return
                            print("\n可加入的群組:")
                            for i, g in enumerate(candidate_groups, 1):
                                print(f"({i}). [Group Name] {g.get('name')}")
                            sel = input("\n要加入哪些群組?（以逗號分隔，空白略過）: ").strip()
                            if sel:
                                try:
                                    idxs = [int(x.strip()) - 1 for x in sel.split(',')]
                                    targets = [candidate_groups[i].get('name') for i in idxs if 0 <= i < len(candidate_groups)]
                                except ValueError:
                                    print("輸入格式錯誤")
                                    input("按任意鍵繼續...")
                                    return
                                for gname in targets:
                                    ok = self.fortigate.add_to_group(gname, addr_name)
                                    print(f"加入群組 {gname}:", "✓" if ok else "✗")
                                self.show_spinner(1.0, "同步設備狀態...")
                                self.refresh_existing_configs()
                            else:
                                print("(未選擇群組)")
                            return
                        if tgt['type'] == 'group':
                            group_name = tgt['group_name']
                            # 群組當前成員
                            group_obj = next((g for g in self.existing_groups if g.get('name') == group_name), None)
                            current_members = set()
                            if group_obj:
                                for m in group_obj.get('member', []):
                                    if isinstance(m, dict):
                                        current_members.add(m.get('name'))
                                    elif isinstance(m, str):
                                        current_members.add(m)
                                # 可加入成員（尚未在群組中的 address，且 type=mac）
                                candidates = [
                                    a for a in self.existing_addresses
                                    if a.get('name') not in current_members and str(a.get('type','')).lower() == 'mac'
                                ]
                            if not candidates:
                                print("(沒有可加入的成員)")
                                input("按任意鍵繼續...")
                                return
                            print(f"\n可加入到群組 '{group_name}' 的成員:")
                            for i, a in enumerate(candidates, 1):
                                nm = a.get('name','')
                                mac = a.get('macaddr','')
                                print(f"({i}). [Name] {nm} [MAC] {mac}")
                            sel = input("\n要加入哪些成員?（以逗號分隔，空白略過）: ").strip()
                            if sel:
                                try:
                                    idxs = [int(x.strip()) - 1 for x in sel.split(',')]
                                    targets = [candidates[i].get('name') for i in idxs if 0 <= i < len(candidates)]
                                except ValueError:
                                    print("輸入格式錯誤")
                                    input("按任意鍵繼續...")
                                    return
                                for addr_name in targets:
                                    ok = self.fortigate.add_to_group(group_name, addr_name)
                                    print(f"加入 {addr_name} 至群組 {group_name}:", "✓" if ok else "✗")
                                self.show_spinner(1.0, "同步設備狀態...")
                                self.refresh_existing_configs()
                            else:
                                print("(未選擇成員)")
                            return

                    def cmd_leavegroup_handler(target_str: str):
                        tgt = self.parse_menu_target(target_str)
                        if not tgt:
                            print("錯誤：leavegroup 指令需要有效的目標（N 或 i.j 或 i.j.k）")
                            input("按任意鍵繼續...")
                            return
                        if tgt['type'] == 'device':
                            print("(ng)")
                            input("按任意鍵繼續...")
                            return
                        if tgt['type'] == 'address':
                            addr_name = tgt['address_name']
                            groups = self.get_groups_for_address(addr_name)
                            if not groups:
                                print("(此地址未加入任何群組)")
                                input("按任意鍵繼續...")
                                return
                            print(f"\n地址 '{addr_name}' 已加入的群組:")
                            for i, g in enumerate(groups, 1):
                                print(f"({i}). {g.get('name')}")
                            sel = input("\n要離開哪些群組?（以逗號分隔，空白略過）: ").strip()
                            if sel:
                                try:
                                    idxs = [int(x.strip()) - 1 for x in sel.split(',')]
                                    targets = [groups[i].get('name') for i in idxs if 0 <= i < len(groups)]
                                except ValueError:
                                    print("輸入格式錯誤")
                                    input("按任意鍵繼續...")
                                    return
                                for gname in targets:
                                    ok = self.fortigate.ssh_unselect_member(gname, addr_name)
                                    print(f"自群組 {gname} 移除 {addr_name}:", "✓" if ok else "✗")
                                self.show_spinner(1.0, "同步設備狀態...")
                                self.refresh_existing_configs()
                            else:
                                print("(未選擇群組)")
                            return
                        if tgt['type'] == 'group':
                            group_name = tgt['group_name']
                            group_obj = next((g for g in self.existing_groups if g.get('name') == group_name), None)
                            if not group_obj:
                                print("(找不到群組)")
                                input("按任意鍵繼續...")
                                return
                            members = []
                            for m in group_obj.get('member', []):
                                if isinstance(m, dict):
                                    members.append(m.get('name'))
                                elif isinstance(m, str):
                                    members.append(m)
                            if not members:
                                print("(群組沒有成員)")
                                input("按任意鍵繼續...")
                                return
                            print(f"\n群組 '{group_name}' 的成員:")
                            for i, nm in enumerate(members, 1):
                                print(f"({i}). {nm}")
                            sel = input("\n要移出哪些成員?（以逗號分隔，空白略過）: ").strip()
                            if sel:
                                try:
                                    idxs = [int(x.strip()) - 1 for x in sel.split(',')]
                                    targets = [members[i] for i in idxs if 0 <= i < len(members)]
                                except ValueError:
                                    print("輸入格式錯誤")
                                    input("按任意鍵繼續...")
                                    return
                                for addr_name in targets:
                                    ok = self.fortigate.ssh_unselect_member(group_name, addr_name)
                                    print(f"自群組 {group_name} 移除 {addr_name}:", "✓" if ok else "✗")
                                self.show_spinner(1.0, "同步設備狀態...")
                                self.refresh_existing_configs()
                            else:
                                print("(未選擇成員)")
                            return

                    if cmd == 'name':
                        cmd_name_handler(arg)
                        continue
                    if cmd == 'joingroup':
                        cmd_joingroup_handler(arg)
                        continue
                    if cmd == 'leavegroup':
                        cmd_leavegroup_handler(arg)
                        continue
                # del 指令解析
                if choice.startswith('del'):
                    parts = raw.strip().split()
                    if not parts:
                        continue
                    cmd = parts[0].lower()
                    arg = parts[1] if len(parts) >= 2 else ''

                    def cmd_del_handler(target_str: str):
                        tgt = self.parse_menu_target(target_str)
                        if not tgt:
                            print("錯誤：del 指令需要有效的目標（N 或 i.j 或 i.j.k）")
                            input("按任意鍵繼續...")
                            return
                        if tgt['type'] == 'device':
                            print("(ng)")
                            input("按任意鍵繼續...")
                            return
                        if tgt['type'] == 'address':
                            addr_name = tgt['address_name']
                            # 檢查是否在群組
                            in_groups = self.get_groups_for_address(addr_name)
                            if in_groups:
                                print(f"\n地址 '{addr_name}' 隸屬群組:")
                                for i, g in enumerate(in_groups, 1):
                                    print(f"({i}). {g.get('name')}")
                                sel = input("\n要自哪些群組移除?（以逗號分隔；輸入 all 代表全部；空白取消）: ").strip().lower()
                                if sel:
                                    try:
                                        if sel == 'all':
                                            targets = [g.get('name') for g in in_groups]
                                        else:
                                            idxs = [int(x.strip()) - 1 for x in sel.split(',')]
                                            targets = [in_groups[i].get('name') for i in idxs if 0 <= i < len(in_groups)]
                                    except ValueError:
                                        print("輸入格式錯誤")
                                        input("按任意鍵繼續...")
                                        return
                                    for gname in targets:
                                        ok = self.fortigate.ssh_unselect_member(gname, addr_name)
                                        print(f"自群組 {gname} 移除 {addr_name}:", "✓" if ok else "✗")
                                    self.show_spinner(1.0, "同步設備狀態...")
                                    self.refresh_existing_configs()
                                    # 若已不在任何群組，可再詢問是否一併刪除地址
                                    remaining = self.get_groups_for_address(addr_name)
                                    if not remaining:
                                        confirm_del = input(f"地址 '{addr_name}' 已無隸屬群組，是否刪除？(y/n): ").strip().lower()
                                        if confirm_del == 'y':
                                            ok = self.fortigate.delete_address(addr_name)
                                            print("刪除地址:", "✓" if ok else "✗")
                                            self.show_spinner(1.0, "同步設備狀態...")
                                            self.refresh_existing_configs()
                                else:
                                    print("(已取消)")
                            else:
                                # 沒有隸屬群組：直接詢問刪除
                                confirm = input(f"地址 '{addr_name}' 未隸屬任何群組，是否刪除？(y/n): ").strip().lower()
                                if confirm == 'y':
                                    ok = self.fortigate.delete_address(addr_name)
                                    print("刪除地址:", "✓" if ok else "✗")
                                    self.show_spinner(1.0, "同步設備狀態...")
                                    self.refresh_existing_configs()
                                else:
                                    print("(已取消)")
                            return
                        if tgt['type'] == 'group':
                            group_name = tgt['group_name']
                            group_obj = next((g for g in self.existing_groups if g.get('name') == group_name), None)
                            members = []
                            if group_obj:
                                for m in group_obj.get('member', []):
                                    if isinstance(m, dict):
                                        members.append(m.get('name'))
                                    elif isinstance(m, str):
                                        members.append(m)
                            if members:
                                print(f"\n群組 '{group_name}' 的成員:")
                                for i, nm in enumerate(members, 1):
                                    print(f"({i}). {nm}")
                                sel = input("\n要移出哪些成員?（以逗號分隔，空白略過）: ").strip()
                                if sel:
                                    try:
                                        idxs = [int(x.strip()) - 1 for x in sel.split(',')]
                                        targets = [members[i] for i in idxs if 0 <= i < len(members)]
                                    except ValueError:
                                        print("輸入格式錯誤")
                                        input("按任意鍵繼續...")
                                        return
                                    for addr_name in targets:
                                        ok = self.fortigate.ssh_unselect_member(group_name, addr_name)
                                        print(f"自群組 {group_name} 移除 {addr_name}:", "✓" if ok else "✗")
                                    self.show_spinner(1.0, "同步設備狀態...")
                                    self.refresh_existing_configs()
                                else:
                                    print("(未選擇成員)")
                                return
                            # 沒有成員：詢問刪除群組
                            confirm = input(f"群組 '{group_name}' 沒有成員，是否刪除群組？(y/n): ").strip().lower()
                            if confirm == 'y':
                                ok = self.fortigate.delete_group(group_name)
                                print("刪除群組:", "✓" if ok else "✗")
                                self.show_spinner(1.0, "同步設備狀態...")
                                self.refresh_existing_configs()
                            else:
                                print("(已取消)")
                            return

                    cmd_del_handler(arg)
                    continue
                
                # 空輸入：不做任何處置，重新顯示主選單
                if choice == '':
                    continue
                
                if choice == 'q':
                    print("再見!")
                    break
                elif choice == 'y':
                    print("(即時模式) 請使用各操作入口，如 i.j / i.j.k 或進入裝置工作選單 x 執行。")
                elif choice == 't' and self.enable_test:
                    self.test_dump()
                # 移除 another/z 指令
                # 直接在主選單輸入 i.j 或 i.j.k
                elif '.' in choice:
                    parts = choice.split('.')
                    if all(p.isdigit() for p in parts):
                        try:
                            if len(parts) == 2:
                                i_idx, j_idx = int(parts[0]), int(parts[1])
                                if 1 <= i_idx <= len(self.network_devices):
                                    # 直接進入現有地址選單（改名與加入群組）
                                    self.existing_address_menu(i_idx, j_idx)
                                else:
                                    print("錯誤：無效的裝置索引")
                                    input("按任意鍵繼續...")
                            elif len(parts) == 3:
                                i_idx, j_idx, k_idx = int(parts[0]), int(parts[1]), int(parts[2])
                                mapping = self.menu_index_map.get(i_idx, {}).get('groups', {})
                                key = f"{j_idx}.{k_idx}"
                                target = mapping.get(key)
                                if target:
                                    self.remove_address_from_group_prompt(target['group_name'], target['address_name'])
                                    self.refresh_existing_configs()
                                else:
                                    print("錯誤：找不到對應的群組索引")
                                    input("按任意鍵繼續...")
                            else:
                                print("錯誤：索引格式應為 i.j 或 i.j.k")
                                input("按任意鍵繼續...")
                        except Exception as _e:
                            print("錯誤：解析索引失敗")
                            input("按任意鍵繼續...")
                    else:
                        # 處理 z.* 與 z.*.*
                        if len(parts) in (2,3) and parts[0] == 'z' and parts[1].isdigit():
                            try:
                                if len(parts) == 2:
                                    z_idx = int(parts[1])
                                    self.another_address_menu(z_idx)
                                else:
                                    # z.i.k -> 只支援移除群組
                                    j_idx = int(parts[1])
                                    k_idx = int(parts[2])
                                    zmapping = self.another_index_map.get('groups', {})
                                    key = f"{j_idx}.{k_idx}"
                                    target = zmapping.get(key)
                                    if target:
                                        self.remove_address_from_group_prompt(target['group_name'], target['address_name'])
                                        self.refresh_existing_configs()
                                    else:
                                        print("錯誤：找不到對應的 another 群組索引")
                                        input("按任意鍵繼續...")
                            except Exception:
                                print("錯誤：解析 z.* 索引失敗")
                                input("按任意鍵繼續...")
                        else:
                            print("錯誤：無效選擇")
                            input("按任意鍵繼續...")
                elif choice.isdigit():
                    # 主選單僅接受指令開頭，單獨輸入數字（非指令）一律視為錯誤
                    print("錯誤：請使用指令開頭（例如 name/joingroup/leavegroup/del）")
                    input("按任意鍵繼續...")
                else:
                    print("錯誤：無效選擇")
                    input("按任意鍵繼續...")
            except KeyboardInterrupt:
                print("\n\n程式被使用者中斷")
                break
            except Exception as e:
                print(f"\n程式執行時發生錯誤: {e}")
                input("按任意鍵繼續...")


if __name__ == "__main__":
    tool = MACAutomationTool()
    try:
        tool.run()
    except KeyboardInterrupt:
        print("\n\n程式被使用者中斷")
        input("按任意鍵退出...")
    except Exception as e:
        print(f"\n程式執行錯誤: {e}")
        print("\n詳細錯誤資訊:")
        import traceback
        traceback.print_exc()
        input("\n按任意鍵退出...")
