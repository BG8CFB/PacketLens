"""Npcap 安装检测与管理"""

import ctypes
import os
import subprocess
import sys
import webbrowser
from pathlib import Path


def is_npcap_installed() -> bool:
    """检测 Npcap 是否已安装（检查核心 DLL）"""
    system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"

    # 检查 Npcap 目录下的 wpcap.dll
    npcap_dll = system32 / "Npcap" / "wpcap.dll"
    if npcap_dll.exists():
        return True

    # 检查注册表（备选）
    try:
        import winreg

        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\WOW6432Node\Npcap",
        )
        winreg.CloseKey(key)
        return True
    except (OSError, ImportError):
        pass

    return False


def get_npcap_dll_path() -> str | None:
    """获取 Npcap DLL 路径"""
    system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    dll = system32 / "Npcap" / "wpcap.dll"
    if dll.exists():
        return str(dll)

    # 回退到 System32 根目录
    dll = system32 / "wpcap.dll"
    if dll.exists():
        return str(dll)

    return None


def open_npcap_download():
    """打开 Npcap 下载页面"""
    url = "https://npcap.com/#download"
    webbrowser.open(url)
    return url


def check_admin_privilege() -> bool:
    """检查是否以管理员权限运行"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except (AttributeError, OSError):
        return False
