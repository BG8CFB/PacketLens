"""Npcap 安装检测与管理"""

import ctypes
import logging
import os
import sys
import webbrowser
from pathlib import Path

logger = logging.getLogger(__name__)


def is_npcap_installed() -> bool:
    """检测 Npcap 是否已安装（优先检查核心 DLL 存在性）"""
    if sys.platform != "win32":
        return False

    system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"

    # 主检测：Npcap 目录下的 wpcap.dll
    npcap_dll = system32 / "Npcap" / "wpcap.dll"
    if npcap_dll.exists():
        return True

    # 回退：System32 根目录（旧版安装路径）
    fallback_dll = system32 / "wpcap.dll"
    if fallback_dll.exists():
        return True

    # 注册表备选（检查多个路径）
    try:
        import winreg
        for reg_path in (r"SOFTWARE\Npcap", r"SOFTWARE\WOW6432Node\Npcap"):
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
                winreg.CloseKey(key)
                return True
            except OSError:
                continue
    except ImportError:
        pass

    return False


def get_npcap_dll_path() -> str | None:
    """获取 Npcap DLL 路径"""
    if sys.platform != "win32":
        return None
    system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    dll = system32 / "Npcap" / "wpcap.dll"
    if dll.exists():
        return str(dll)

    # 回退到 System32 根目录
    dll = system32 / "wpcap.dll"
    if dll.exists():
        return str(dll)

    return None


_NPCAP_URL = "https://npcap.com/#download"


def open_npcap_download():
    """打开 Npcap 下载页面

    Returns:
        str: 下载页面 URL（即使浏览器打开失败也返回 URL 供用户手动访问）
    """
    try:
        webbrowser.open(_NPCAP_URL)
    except Exception as e:
        logger.warning(f"无法打开浏览器: {e}")
    return _NPCAP_URL


def check_admin_privilege() -> bool:
    """检查是否以管理员权限运行"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except (AttributeError, OSError):
        return False
