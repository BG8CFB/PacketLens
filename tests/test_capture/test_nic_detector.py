"""网卡检测真实测试 — 不使用 mock，直接调用 scapy 枚举真实网卡"""

import pytest

from app.capture.nic_detector import (
    NpcapNotFoundError,
    check_npcap,
    get_default_interface,
    list_interfaces,
)
from app.models.nic_info import NICInfo
from app.utils.npcap_installer import is_npcap_installed


# ─── NpcapNotFoundError 异常类 ───


class TestNpcapNotFoundError:
    """NpcapNotFoundError 异常类测试"""

    def test_is_exception_subclass(self):
        """NpcapNotFoundError 应是 Exception 的子类"""
        assert issubclass(NpcapNotFoundError, Exception)

    def test_error_message_content(self):
        """异常消息应包含安装指引"""
        err = NpcapNotFoundError()
        assert "Npcap" in str(err)
        assert "npcap.com" in str(err)

    def test_can_be_caught_as_exception(self):
        """可以被 except Exception 捕获"""
        with pytest.raises(Exception):
            raise NpcapNotFoundError()


# ─── Npcap 驱动检测 ───


class TestNpcapDetection:
    """Npcap 驱动检测"""

    def test_npcap_installed(self):
        """当前机器必须已安装 Npcap"""
        assert is_npcap_installed(), "Npcap 未安装，无法进行抓包测试"

    def test_check_npcap_no_exception_when_installed(self):
        """check_npcap 在已安装环境下不应抛异常"""
        check_npcap()  # 不抛异常即通过


# ─── list_interfaces 真实网卡枚举 ───


class TestListInterfaces:
    """真实网卡枚举"""

    def test_returns_list_type(self):
        """返回值类型应为 list"""
        nics = list_interfaces()
        assert isinstance(nics, list)

    def test_returns_non_empty_list(self):
        """至少应检测到一个网卡（含回环）"""
        nics = list_interfaces()
        assert len(nics) > 0

    def test_all_elements_are_nic_info(self):
        """每个元素应为 NICInfo 实例"""
        nics = list_interfaces()
        for nic in nics:
            assert isinstance(nic, NICInfo)

    def test_each_nic_has_name(self):
        """每个 NICInfo 必须有非空 name"""
        nics = list_interfaces()
        for nic in nics:
            assert isinstance(nic.name, str)
            assert len(nic.name) > 0, f"网卡 name 为空: {nic}"

    def test_each_nic_has_description(self):
        """每个 NICInfo 必须有非空 description"""
        nics = list_interfaces()
        for nic in nics:
            assert isinstance(nic.description, str)
            assert len(nic.description) > 0, f"网卡 description 为空: {nic}"

    def test_each_nic_is_up(self):
        """get_working_ifaces 返回的网卡 is_up 应为 True"""
        nics = list_interfaces()
        for nic in nics:
            assert nic.is_up is True

    def test_each_nic_has_non_negative_index(self):
        """每个网卡的 index 应 >= 0"""
        nics = list_interfaces()
        for nic in nics:
            assert nic.index >= 0

    def test_ip_address_is_none_or_valid_format(self):
        """ip_address 应为 None 或合法 IP 格式"""
        nics = list_interfaces()
        for nic in nics:
            if nic.ip_address is not None:
                assert isinstance(nic.ip_address, str)
                parts = nic.ip_address.split(".")
                assert len(parts) == 4, f"非法 IP: {nic.ip_address}"
                for part in parts:
                    assert 0 <= int(part) <= 255, f"IP 段超出范围: {nic.ip_address}"

    def test_mac_address_format(self):
        """mac_address 应为冒号分隔的十六进制格式"""
        nics = list_interfaces()
        for nic in nics:
            if nic.mac_address:
                assert ":" in nic.mac_address, f"MAC 格式异常: {nic.mac_address}"

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

    def test_ip_0_0_0_0_excluded(self):
        """0.0.0.0 不应作为有效 IP 出现"""
        nics = list_interfaces()
        for nic in nics:
            if nic.ip_address is not None:
                assert nic.ip_address != "0.0.0.0"

    def test_sorting_physical_before_loopback(self):
        """物理网卡（有 IP）应排在回环接口之前"""
        nics = list_interfaces()
        if len(nics) < 2:
            pytest.skip("只有一张网卡，无法验证排序")
        # 找到回环接口的位置
        loopback_indices = [
            i for i, nic in enumerate(nics)
            if "loopback" in nic.description.lower() or "loopback" in nic.name.lower()
        ]
        # 找到有 IP 的非回环网卡位置
        physical_indices = [
            i for i, nic in enumerate(nics)
            if nic.ip_address and "loopback" not in nic.description.lower()
            and "loopback" not in nic.name.lower()
        ]
        if loopback_indices and physical_indices:
            assert min(physical_indices) < min(loopback_indices), (
                f"排序错误：物理网卡位置 {physical_indices} 应在回环 {loopback_indices} 之前"
            )

    def test_sorting_no_ip_after_ip(self):
        """没有 IP 的网卡应排在有 IP 的网卡之后"""
        nics = list_interfaces()
        has_ip = [i for i, nic in enumerate(nics) if nic.ip_address]
        no_ip = [i for i, nic in enumerate(nics) if nic.ip_address is None]
        if has_ip and no_ip:
            assert max(has_ip) < min(no_ip), (
                "有 IP 的网卡应排在无 IP 网卡之前"
            )


# ─── get_default_interface ───


class TestGetDefaultInterface:
    """默认网卡检测"""

    def test_returns_nic_info_or_none(self):
        """返回值应为 NICInfo 或 None"""
        nic = get_default_interface()
        assert nic is None or isinstance(nic, NICInfo)

    def test_returns_valid_nic(self):
        """get_default_interface 应返回有效的 NICInfo（假设 Npcap 已装）"""
        nic = get_default_interface()
        assert nic is not None, "应至少有一个默认网卡"
        assert isinstance(nic.name, str)
        assert len(nic.name) > 0
        assert isinstance(nic.description, str)
        assert len(nic.description) > 0

    def test_default_is_up(self):
        """默认网卡应为 up 状态"""
        nic = get_default_interface()
        if nic is not None:
            assert nic.is_up is True

    def test_default_in_interface_list(self):
        """默认网卡应出现在完整列表中"""
        default = get_default_interface()
        if default is None:
            pytest.skip("无默认网卡")
        nics = list_interfaces()
        names = [n.name for n in nics]
        assert default.name in names, (
            f"默认网卡 {default.name} 未在接口列表中找到: {names}"
        )
