"""NICInfo 模型测试"""

from app.models.nic_info import NICInfo


class TestNICInfo:

    def test_basic(self):
        nic = NICInfo(
            name="eth0", description="Intel Ethernet",
            ip_address="192.168.1.100", mac_address="aa:bb:cc:dd:ee:ff",
            is_up=True, index=0,
        )
        assert nic.name == "eth0"
        assert nic.description == "Intel Ethernet"
        assert nic.ip_address == "192.168.1.100"
        assert nic.mac_address == "aa:bb:cc:dd:ee:ff"
        assert nic.is_up is True
        assert nic.index == 0

    def test_display_name_with_ip(self):
        nic = NICInfo(
            name="eth0", description="Ethernet",
            ip_address="10.0.0.1",
        )
        assert "Ethernet" in nic.display_name
        assert "10.0.0.1" in nic.display_name

    def test_display_name_without_ip(self):
        nic = NICInfo(name="lo", description="Loopback")
        assert "Loopback" in nic.display_name
        assert "(" not in nic.display_name  # no IP = no parentheses

    def test_display_name_fallback_to_name(self):
        nic = NICInfo(name="wlan0", description="")
        assert "wlan0" in nic.display_name
