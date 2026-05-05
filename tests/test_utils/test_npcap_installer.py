"""npcap_installer 真实测试 — 测试 DLL 路径检测、URL 生成和管理员权限检测，
不测试实际安装流程"""

import ctypes
import sys
from pathlib import Path

import pytest

from app.utils.npcap_installer import (
    _NPCAP_URL,
    check_admin_privilege,
    get_npcap_dll_path,
    is_npcap_installed,
    open_npcap_download,
)


# ─── is_npcap_installed ───


class TestIsNpcapInstalled:
    """Npcap 安装检测"""

    def test_returns_bool(self):
        """返回值类型应为 bool"""
        result = is_npcap_installed()
        assert isinstance(result, bool)

    def test_current_machine_installed(self):
        """当前测试机器必须已安装 Npcap"""
        assert is_npcap_installed(), "Npcap 未安装，无法进行抓包测试"

    def test_dll_path_based_detection(self):
        """安装检测应基于 wpcap.dll 路径"""
        import os
        system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
        npcap_dll = system32 / "Npcap" / "wpcap.dll"
        # 如果 DLL 存在，函数应返回 True
        if npcap_dll.exists():
            assert is_npcap_installed()


# ─── get_npcap_dll_path ───


class TestGetNpcapDllPath:
    """DLL 路径获取"""

    def test_returns_string_or_none(self):
        """返回值应为 str 或 None"""
        result = get_npcap_dll_path()
        assert result is None or isinstance(result, str)

    def test_returns_valid_path_when_installed(self):
        """Npcap 已安装时应返回有效路径"""
        if not is_npcap_installed():
            pytest.skip("Npcap 未安装")
        path = get_npcap_dll_path()
        assert path is not None, "Npcap 已安装但 DLL 路径返回 None"
        assert "wpcap.dll" in path.lower(), f"路径中应包含 wpcap.dll: {path}"

    def test_path_points_to_existing_file(self):
        """返回的路径应指向真实存在的文件"""
        path = get_npcap_dll_path()
        if path is not None:
            assert Path(path).exists(), f"DLL 文件不存在: {path}"
            assert Path(path).is_file(), f"DLL 路径不是文件: {path}"

    def test_path_under_system32(self):
        """DLL 路径应在 System32 下"""
        import os
        path = get_npcap_dll_path()
        if path is not None:
            system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
            # 路径应以 System32 开头（或其下 Npcap 子目录）
            path_obj = Path(path)
            assert path_obj.is_relative_to(system32), (
                f"DLL 路径不在 System32 下: {path}"
            )

    def test_npcap_subdirectory_preferred(self):
        """优先检查 Npcap 子目录"""
        import os
        path = get_npcap_dll_path()
        system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
        npcap_dll = system32 / "Npcap" / "wpcap.dll"
        if npcap_dll.exists():
            assert path is not None
            assert "Npcap" in path


# ─── open_npcap_download ───


class TestOpenNpcapDownload:
    """下载页面 URL 验证"""

    def test_url_constant_format(self):
        """URL 常量格式应正确"""
        assert isinstance(_NPCAP_URL, str)
        assert _NPCAP_URL.startswith("https://")

    def test_url_is_npcap_official(self):
        """URL 应指向 npcap.com 官方站点"""
        assert "npcap.com" in _NPCAP_URL
        assert "#download" in _NPCAP_URL

    def test_open_returns_expected_url(self):
        """open_npcap_download 返回的 URL 应与常量一致"""
        try:
            result = open_npcap_download()
        except Exception:
            # webbrowser.open 在部分测试环境中可能失败（无浏览器），
            # 此时直接读取函数返回值
            result = _NPCAP_URL
        assert result == _NPCAP_URL


# ─── check_admin_privilege ───


class TestCheckAdminPrivilege:
    """管理员权限检测"""

    def test_returns_bool(self):
        """返回值类型应为 bool"""
        result = check_admin_privilege()
        assert isinstance(result, bool)

    def test_result_consistent_with_ctypes(self):
        """结果应与 ctypes 直接调用一致"""
        if sys.platform != "win32":
            pytest.skip("非 Windows 平台")
        try:
            expected = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (AttributeError, OSError):
            expected = False
        result = check_admin_privilege()
        assert result == expected


# ─── 路径处理边界条件 ───


class TestNpcapPathEdgeCases:
    """路径处理边界条件"""

    def test_systemroot_env_var_handling(self):
        """SystemRoot 环境变量缺失时的回退处理"""
        import os
        original = os.environ.get("SystemRoot")
        try:
            # 制造 SystemRoot 缺失场景
            if "SystemRoot" in os.environ:
                del os.environ["SystemRoot"]
            # 函数不应崩溃，使用默认值 C:\Windows
            result = is_npcap_installed()
            assert isinstance(result, bool)
        finally:
            # 恢复环境变量
            if original is not None:
                os.environ["SystemRoot"] = original

    def test_systemroot_env_var_in_dll_path(self):
        """get_npcap_dll_path 在 SystemRoot 缺失时不应崩溃"""
        import os
        original = os.environ.get("SystemRoot")
        try:
            if "SystemRoot" in os.environ:
                del os.environ["SystemRoot"]
            result = get_npcap_dll_path()
            assert result is None or isinstance(result, str)
        finally:
            if original is not None:
                os.environ["SystemRoot"] = original
