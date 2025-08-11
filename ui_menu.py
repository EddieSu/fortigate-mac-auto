#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Dict, List, Tuple, Optional
import sys
import time
from getpass import getpass

from utils import normalize_mac


class MACAutomationTool:
    def __init__(self, fortigate, enable_test: bool = False, scroll_output: bool = True):
        self.fortigate = fortigate
        self.enable_test = enable_test
        self.scroll_output = scroll_output
        self.network_devices: List[Dict] = []
        self.existing_addresses: List[Dict] = []
        self.existing_groups: List[Dict] = []
        self.menu_index_map: Dict[int, Dict[str, Dict]] = {}
        self.another_index_map: Dict[str, Dict] = {}
        self.show_another = False

    # UI helpers
    def show_spinner(self, seconds: float = 1.0, message: str = "請稍候") -> None:
        spinner = ['|', '/', '-', '\\']
        steps = max(1, int(seconds / 0.1))
        for i in range(steps):
            sys.stdout.write(f"\r{message} {spinner[i % len(spinner)]}")
            sys.stdout.flush()
            time.sleep(0.1)
        if self.scroll_output:
            sys.stdout.write("\n")
        else:
            sys.stdout.write("\r" + " " * (len(message) + 2) + "\r")

    # Data helpers
    def get_groups_for_address(self, address_name: str) -> List[Dict]:
        groups: List[Dict] = []
        for group in self.existing_groups:
            for member in group.get('member', []):
                mname = member.get('name') if isinstance(member, dict) else member
                if mname == address_name:
                    groups.append(group)
                    break
        return groups

    def get_another_addresses_for_device(self, device_index: int) -> List[Tuple[str, str]]:
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

    def match_existing_configs(self, mac: str):
        if isinstance(mac, list):
            mac = mac[0] if mac else ''
        mac_str = normalize_mac(str(mac))
        addresses = []
        for addr in self.existing_addresses:
            mac_raw = addr.get('macaddr', '')
            mac_norm = normalize_mac(str(mac_raw)) if mac_raw else ''
            if mac_norm == mac_str:
                addresses.append(addr)
        groups = []
        for group in self.existing_groups:
            for member in group.get('member', []):
                mname = member.get('name') if isinstance(member, dict) else member
                ref = next((a for a in self.existing_addresses if a.get('name') == mname), None)
                if ref and normalize_mac(str(ref.get('macaddr',''))) == mac_str:
                    groups.append(group)
                    break
        return addresses, groups

    # Rendering
    def display_main_menu(self):
        print("\n" + "="*60)
        print("FortiGate MAC 設定自動化工具")
        print("="*60)
        self.menu_index_map = {}
        self.another_index_map = {}
        if not self.network_devices:
            print("未找到網路裝置")
            return
        print("\n要設定哪個網路裝置?\n")
        for i, device in enumerate(self.network_devices, 1):
            mac = normalize_mac(str(device.get('mac', '')))
            name = str(device.get('name', 'Unknown'))
            print(f"{i}. {name} [MAC] {mac}")
            addrs, _ = self.match_existing_configs(mac)
            self.menu_index_map[i] = {'addresses': {}, 'groups': {}}
            for j, addr in enumerate(addrs, 1):
                addr_name = addr.get('name')
                addr_mac = addr.get('macaddr')
                print(f"{i}.{j}. ADDRESS [Name] {addr_name} [MAC] {addr_mac}")
                self.menu_index_map[i]['addresses'][j] = addr_name
                # groups under address
                for k, g in enumerate(self.get_groups_for_address(addr_name), 1):
                    gname = g.get('name')
                    print(f"      └─ {i}.{j}.{k} GROUP [Name] {gname}")
                    self.menu_index_map[i]['groups'][f"{j}.{k}"] = {
                        'address_name': addr_name,
                        'group_name': gname,
                    }

        print()
        print(f"a. another = {'on' if self.show_another else 'off'}")
        print("name")
        print("joingroup")
        print("leavegroup")
        print("del")
        print("q. Exit")


