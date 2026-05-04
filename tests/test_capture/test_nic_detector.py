"""网卡检测真实测试 — 不使用 mock，直接调用 scapy 枚举真实网卡"""

import pytest

from app.capture.nic_detector import (
    NpcapNotFoundError,
    check_npcap,
    get_default_interface,
    list_interfaces,
)
from app.utils.npcap_installer import is_npcap_installed


class TestNpcapDetection:
    """Npcap 驱动检测"""

    def test_npcap_installed(self):
        """当前机器必须已安装 Npcap"""
        assert is_npcap_installed(), "Npcap 未安装，无法进行抓包测试"

    def test_check_npcap_no_exception(self):
        """check_npcap 在已安装环境下不应抛异常"""
        check_npcap()  # 不抛异常即通过


class TestListInterfaces:
    """真实网卡枚举"""

    def test_returns_non_empty_list(self):
        """至少应检测到一个网卡（含回环）"""
        nics = list_interfaces()
        assert len(nics) > 0

    def test_each_nic_has_required_fields(self):
        """每个 NICInfo 必须有 name 和 description"""
        nics = list_interfaces()
        for nic in nics:
            assert nic.name, f"网卡缺少 name: {nic}"
            assert nic.description, f"网卡缺少 description: {nic}"
            assert nic.is_up is True

    def test_loopback_exists(self):
        """应包含回环接口"""
        nics = list_interfaces()
        names = [nic.name.lower() for nic in nics]
        descs = [nic.description.lower() for nic in nics]
        has_loopback = any("loopback" in n for n in names + descs)
        assert has_loopback, f"未找到回环接口，现有网卡: {[nic.name for nic in nics]}"

    def test_at_least_one_has_ip(self):
        """至少一个网卡有 IP 地址"""
        nics = list_interfaces()
        ips = [nic.ip_address for nic in nics if nic.ip_address]
        assert len(ips) > 0, "没有任何网卡有 IP 地址"

    def test_physical_nic_sorted_first(self):
        """有 IP 的网卡应排在前面"""
        nics = list_interfaces()
        # 找到第一个有 IP 的和第一个没有 IP 的
        first_with_ip = None
        first_without_ip = None
        for nic in nics:
            if nic.ip_address and first_with_ip is None:
                first_with_ip = nics.index(nic)
            if not nic.ip_address and first_without_ip is None:
                first_without_ip = nics.index(nic)
        if first_with_ip is not None and first_without_ip is not None:
            assert first_with_ip < first_without_ip


class TestGetDefaultInterface:
    """默认网卡检测"""

    def test_returns_valid_nic(self):
        """get_default_interface 应返回有效的 NICInfo"""
        nic = get_default_interface()
        assert nic is not None
        assert nic.name
        assert nic.description

    def test_default_in_interface_list(self):
        """默认网卡应出现在完整列表中"""
        default = get_default_interface()
        nics = list_interfaces()
        names = [n.name for n in nics]
        assert default.name in names
