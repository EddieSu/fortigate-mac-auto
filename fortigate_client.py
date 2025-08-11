#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Dict, List, Optional
from urllib.parse import urlparse
import time
import paramiko

from utils import normalize_mac
import logging
from address_parser import parse_address_output, parse_group_output
import re


class FortiGateManager:
    def __init__(
        self,
        host: str,
        ssh_username: str,
        ssh_password: str,
        ssh_port: int = 22,
        timeout: int = 10,
    ):
        self.host = host.rstrip('/')
        self.ssh_username = ssh_username
        self.ssh_password = ssh_password
        self.ssh_port = ssh_port
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        # 是否將送出的指令與回覆完整寫入日誌
        self.debug_commands: bool = False

    def _extract_hostname(self) -> str:
        try:
            parsed = urlparse(self.host)
            return parsed.hostname or self.host.replace('https://', '').replace('http://', '')
        except Exception:
            return self.host

    def _cli_ok(self, out: bytes, err: bytes) -> bool:
        text = f"{(out or b'').decode(errors='ignore')}\n{(err or b'').decode(errors='ignore')}".lower()
        for marker in ('command fail', 'error', 'unknown action', 'invalid'):
            if marker in text:
                return False
        return True

    def _exec(self, cmd: str) -> str:
        host = self._extract_hostname()
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=host, port=self.ssh_port, username=self.ssh_username, password=self.ssh_password,
                       look_for_keys=False, allow_agent=False, timeout=self.timeout)
        # 關閉分頁輸出，避免 show 被截斷
        full_cmd = (
            "config system console\n"
            "set output standard\n"
            "end\n" + cmd
        )
        # 僅在 debug_commands 為真時才輸出指令與回覆
        if self.debug_commands:
            self.logger.info("SSH exec (raw):\n" + full_cmd.strip())
        stdin, stdout, stderr = client.exec_command(full_cmd, timeout=self.timeout)
        out_bytes = stdout.read()
        err_bytes = stderr.read()
        out = out_bytes.decode(errors='ignore') if out_bytes is not None else ''
        err = err_bytes.decode(errors='ignore') if err_bytes is not None else ''
        client.close()
        if self.debug_commands:
            self.logger.info("SSH stdout dump:\n" + out)
            if err.strip():
                self.logger.info("SSH stderr dump:\n" + err)
        return out

    # Auth / status
    def login(self) -> bool:
        try:
            host = self._extract_hostname()
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, port=self.ssh_port, username=self.ssh_username, password=self.ssh_password,
                           look_for_keys=False, allow_agent=False, timeout=self.timeout)
            client.close()
            return True
        except Exception:
            return False

    def get_system_status(self) -> Dict:
        host = self._extract_hostname()
        info = {"hostname": host}
        try:
            out = self._exec("get system status\n")
            info['raw'] = out
            for line in out.splitlines():
                s = line.strip()
                if s.lower().startswith('hostname:'):
                    info['hostname'] = s.split(':', 1)[1].strip()
                if s.lower().startswith('version:'):
                    info['version'] = s.split(':', 1)[1].strip()
        except Exception:
            pass
        return info

    # Data fetch
    def get_address_objects(self) -> List[Dict]:
        try:
            out_full = self._exec("config firewall address\nshow full-configuration\nend\n")
        except Exception:
            out_full = ''
        try:
            out_show = self._exec("config firewall address\nshow\nend\n")
        except Exception:
            out_show = ''
        merged = parse_address_output(out_full)
        show_map = parse_address_output(out_show)
        for name, item in show_map.items():
            if name not in merged:
                merged[name] = item
            else:
                for key in ('type', 'macaddr', 'comment', 'interface'):
                    if not merged[name].get(key) and item.get(key):
                        merged[name][key] = item[key]
        # 以全域 fallback 正則再掃一遍，確保任何含 macaddr 的物件都被納入
        fallback_text = f"{out_full}\n{out_show}"
        for m in re.finditer(r'edit\s+"([^"]+)"[\s\S]*?set\s+macaddr\s+"?([0-9A-Fa-f:]+)"?', fallback_text, re.IGNORECASE):
            nm = m.group(1)
            mac = m.group(2)
            if nm not in merged:
                merged[nm] = {'name': nm}
            if not merged[nm].get('macaddr'):
                merged[nm]['macaddr'] = normalize_mac(mac)
            if not merged[nm].get('type'):
                merged[nm]['type'] = 'mac'
        # 僅保留 type=mac；若未宣告 type 但有 macaddr 也視為 mac
        filtered = []
        for it in merged.values():
            typ = str(it.get('type','')).lower()
            mac = str(it.get('macaddr',''))
            if typ == 'mac' or mac:
                filtered.append(it)
        return filtered

    def get_address_groups(self) -> List[Dict]:
        try:
            out_full = self._exec("config firewall addrgrp\nshow full-configuration\nend\n")
        except Exception:
            out_full = ''
        try:
            out_show = self._exec("config firewall addrgrp\nshow\nend\n")
        except Exception:
            out_show = ''
        merged = parse_group_output(out_full)
        show_map = parse_group_output(out_show)
        for name, item in show_map.items():
            if name not in merged:
                merged[name] = item
            else:
                if not merged[name].get('member') and item.get('member'):
                    merged[name]['member'] = item['member']
        groups_list = list(merged.values())
        if not self.debug_commands:
            try:
                self.logger.info(f"get_address_groups: count={len(groups_list)}")
            except Exception:
                pass
        return groups_list

    # Mutations
    def create_address(self, name: str, mac: str) -> bool:
        mac = normalize_mac(mac)
        out = ''
        err = b''
        try:
            host = self._extract_hostname()
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, port=self.ssh_port, username=self.ssh_username, password=self.ssh_password,
                           look_for_keys=False, allow_agent=False, timeout=self.timeout)
            cmd = f"config firewall address\nedit \"{name}\"\nset type mac\nset macaddr \"{mac}\"\nset comment \"Auto created by MAC automation tool\"\nnext\nend\n"
            stdin, stdout, stderr = client.exec_command(cmd, timeout=self.timeout)
            out_b = stdout.read()
            err = stderr.read()
            client.close()
            time.sleep(1.0)
            return self._cli_ok(out_b, err)
        except Exception:
            return False

    # Targeted queries
    def find_addresses_by_mac(self, mac: str) -> List[Dict]:
        """回傳與指定 MAC 完全相符的 address 物件列表。"""
        target = normalize_mac(str(mac))
        try:
            out_full = self._exec("config firewall address\nshow full-configuration\nend\n")
        except Exception:
            out_full = ''
        try:
            out_show = self._exec("config firewall address\nshow\nend\n")
        except Exception:
            out_show = ''
        merged = parse_address_output(out_full)
        show_map = parse_address_output(out_show)
        for name, item in show_map.items():
            if name not in merged:
                merged[name] = item
            else:
                for key in ('type', 'macaddr', 'comment', 'interface'):
                    if not merged[name].get(key) and item.get(key):
                        merged[name][key] = item[key]
        # 再跑 fallback 正則，確保不漏
        fallback_text = f"{out_full}\n{out_show}"
        for m in re.finditer(r'edit\s+"([^"]+)"[\s\S]*?set\s+macaddr\s+"?([0-9A-Fa-f:]+)"?', fallback_text, re.IGNORECASE):
            nm = m.group(1)
            maddr = normalize_mac(m.group(2))
            if nm not in merged:
                merged[nm] = {'name': nm, 'type': 'mac', 'macaddr': maddr}
            else:
                if not merged[nm].get('macaddr'):
                    merged[nm]['macaddr'] = maddr
                if not merged[nm].get('type'):
                    merged[nm]['type'] = 'mac'
        # 過濾完全相符的 MAC
        results: List[Dict] = []
        for it in merged.values():
            mac_val = normalize_mac(str(it.get('macaddr','')))
            if mac_val and mac_val == target:
                results.append(it)
        if not self.debug_commands:
            try:
                self.logger.info(f"find_addresses_by_mac(full): mac={target} results={len(results)}")
            except Exception:
                pass
        return results

    def find_addresses_by_mac_remote(self, mac: str) -> List[Dict]:
        """使用設備端 grep 以 MAC 為條件直接查詢，避免抓全表。"""
        target = normalize_mac(str(mac))
        cmds = [
            f"show firewall address | grep -f \"{target}\"\n",
            f"show firewall address | grep -e \"{target}\"\n",
            f"show firewall address | grep \"{target}\"\n",
        ]
        for attempt, cmd in enumerate(cmds, 1):
            try:
                if self.debug_commands:
                    self.logger.info(f"grep attempt {attempt}: cmd='{cmd.strip()}'")
                out = self._exec(cmd)
                parsed = parse_address_output(out)
                results: List[Dict] = []
                for item in parsed.values():
                    mac_val = normalize_mac(str(item.get('macaddr','')))
                    if mac_val and mac_val == target:
                        if not item.get('type'):
                            item['type'] = 'mac'
                        results.append(item)
                if self.debug_commands:
                    self.logger.info(f"grep attempt {attempt}: parsed {len(results)} results for {target}")
                if results:
                    if not self.debug_commands:
                        try:
                            self.logger.info(f"find_addresses_by_mac_remote: mac={target} results={len(results)} via attempt={attempt}")
                        except Exception:
                            pass
                    return results
            except Exception as e:
                if self.debug_commands:
                    self.logger.warning(f"grep attempt {attempt} failed: {e}")
                continue
        if self.debug_commands:
            self.logger.info("grep attempts yielded no results; falling back to full parse")
        return self.find_addresses_by_mac(target)

    def delete_address(self, name: str) -> bool:
        try:
            host = self._extract_hostname()
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, port=self.ssh_port, username=self.ssh_username, password=self.ssh_password,
                           look_for_keys=False, allow_agent=False, timeout=self.timeout)
            cmd = f"config firewall address\ndelete \"{name}\"\nend\n"
            stdin, stdout, stderr = client.exec_command(cmd, timeout=self.timeout)
            out = stdout.read()
            err = stderr.read()
            client.close()
            time.sleep(1.0)
            return self._cli_ok(out, err)
        except Exception:
            return False

    def add_to_group(self, group_name: str, address_name: str) -> bool:
        try:
            host = self._extract_hostname()
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, port=self.ssh_port, username=self.ssh_username, password=self.ssh_password,
                           look_for_keys=False, allow_agent=False, timeout=self.timeout)
            cmd = f"config firewall addrgrp\nedit \"{group_name}\"\nappend member \"{address_name}\"\nnext\nend\n"
            stdin, stdout, stderr = client.exec_command(cmd, timeout=self.timeout)
            out = stdout.read()
            err = stderr.read()
            client.close()
            time.sleep(1.0)
            return self._cli_ok(out, err)
        except Exception:
            return False

    def ssh_unselect_member(self, group_name: str, address_name: str) -> bool:
        try:
            host = self._extract_hostname()
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, port=self.ssh_port, username=self.ssh_username, password=self.ssh_password,
                           look_for_keys=False, allow_agent=False, timeout=self.timeout)
            cmd = f"config firewall addrgrp\nedit \"{group_name}\"\nunselect member \"{address_name}\"\nnext\nend\n"
            stdin, stdout, stderr = client.exec_command(cmd, timeout=self.timeout)
            out = stdout.read()
            err = stderr.read()
            client.close()
            return self._cli_ok(out, err)
        except Exception:
            return False

    def ssh_rename_address(self, old_name: str, new_name: str) -> bool:
        try:
            host = self._extract_hostname()
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, port=self.ssh_port, username=self.ssh_username, password=self.ssh_password,
                           look_for_keys=False, allow_agent=False, timeout=self.timeout)
            cmd = f"config firewall address\nrename \"{old_name}\" to \"{new_name}\"\nend\n"
            stdin, stdout, stderr = client.exec_command(cmd, timeout=self.timeout)
            out = stdout.read()
            err = stderr.read()
            client.close()
            return self._cli_ok(out, err)
        except Exception:
            return False

    def ssh_rename_group(self, old_name: str, new_name: str) -> bool:
        try:
            host = self._extract_hostname()
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, port=self.ssh_port, username=self.ssh_username, password=self.ssh_password,
                           look_for_keys=False, allow_agent=False, timeout=self.timeout)
            cmd = f"config firewall addrgrp\nrename \"{old_name}\" to \"{new_name}\"\nend\n"
            stdin, stdout, stderr = client.exec_command(cmd, timeout=self.timeout)
            out = stdout.read()
            err = stderr.read()
            client.close()
            return self._cli_ok(out, err)
        except Exception:
            return False


