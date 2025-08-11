#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
解析 FortiGate CLI 的 address 與 addrgrp 輸出。
"""

import re
from typing import Dict, List, Optional
from utils import normalize_mac


def parse_address_output(text: str) -> Dict[str, Dict]:
    """以區塊解析 address：edit "name" ... next。"""
    result: Dict[str, Dict] = {}
    if not text:
        return result
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
            if not item.get('type'):
                # 若未宣告 type，但存在 macaddr，視為 MAC 類型
                item['type'] = 'mac'
        mcomment = re.search(r'^\s*set\s+comment\s+"([^"]*)"', block, re.MULTILINE)
        if mcomment:
            item['comment'] = mcomment.group(1)
        minter = re.search(r'^\s*set\s+interface\s+"?([^"\s]+)"?', block, re.MULTILINE)
        if minter:
            item['interface'] = minter.group(1)
        result[name] = item
    return result


def parse_group_output(text: str) -> Dict[str, Dict]:
    """以區塊解析 addrgrp：edit "name" ... next。"""
    result: Dict[str, Dict] = {}
    if not text:
        return result
    for m in re.finditer(r'^\s*edit\s+"([^"]+)"\s*([\s\S]*?)^\s*next\b', text, re.MULTILINE):
        name = m.group(1)
        block = m.group(2)
        item: Dict[str, object] = {"name": name, "member": []}
        # set member "a" "b" 或 set member a b
        mmem = re.search(r'^\s*set\s+member\s+(.+)$', block, re.MULTILINE)
        if mmem:
            buf = mmem.group(1).strip()
            if '"' in buf:
                parts = buf.split('"')
                for i in range(1, len(parts), 2):
                    nm = parts[i].strip()
                    if nm:
                        item['member'].append({"name": nm})
            else:
                for tok in buf.split():
                    if tok:
                        item['member'].append({"name": tok})
        result[name] = item
    return result


