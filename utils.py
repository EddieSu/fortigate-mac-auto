#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
通用工具：日誌、字串正規化、版本資訊
"""
APP_NAME = "FortiGate MAC Auto"
APP_VERSION = "1.0.0"


import os
import logging
from datetime import datetime


def normalize_mac(mac: str) -> str:
    """將 MAC 正規化為冒號分隔的大寫 AA:BB:CC:DD:EE:FF。"""
    try:
        if not mac:
            return ''
        hex_only = ''.join(ch for ch in str(mac) if ch.isalnum()).upper()
        if len(hex_only) == 12 and all(c in '0123456789ABCDEF' for c in hex_only):
            return ':'.join(hex_only[i:i+2] for i in range(0, 12, 2))
        return str(mac).replace('-', ':').upper()
    except Exception:
        return str(mac).upper()


def setup_logging() -> logging.Logger:
    """設定日誌輸出至檔案與終端。"""
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    log_file = os.path.join(log_dir, f"fortigate_mac_auto_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
        ]
    )
    # 降低 paramiko 噪音
    try:
        logging.getLogger("paramiko").setLevel(logging.WARNING)
        logging.getLogger("paramiko.transport").setLevel(logging.WARNING)
    except Exception:
        pass
    return logging.getLogger(__name__)


