"""ProtocolClassifier 单元测试"""

from app.preprocessing.protocol_classifier import classify_service, get_protocol_color


class TestClassifyService:

    def test_known_ports(self):
        assert classify_service(None, 80, "TCP") == "HTTP"
        assert classify_service(None, 443, "TCP") == "TLS"
        assert classify_service(None, 22, "TCP") == "SSH"
        assert classify_service(None, 53, "UDP") == "DNS"
        assert classify_service(None, 3306, "TCP") == "MySQL"
        assert classify_service(None, 3389, "TCP") == "RDP"

    def test_classify_from_src_port(self):
        """当 dst_port 未知时，从 src_port 推断"""
        assert classify_service(80, 12345, "TCP") == "HTTP"

    def test_unknown_ports_return_none(self):
        assert classify_service(None, 99999, "TCP") is None
        assert classify_service(12345, 54321, "UDP") is None

    def test_none_ports(self):
        assert classify_service(None, None, "TCP") is None


class TestGetProtocolColor:

    def test_known_protocols(self):
        assert get_protocol_color("TCP") == "#4488CC"
        assert get_protocol_color("UDP") == "#44AA44"
        assert get_protocol_color("ICMP") == "#CC4444"
        assert get_protocol_color("ARP") == "#CC8844"
        assert get_protocol_color("DNS") == "#8844CC"
        assert get_protocol_color("TLS") == "#CC44AA"
        assert get_protocol_color("HTTP") == "#44CCAA"

    def test_unknown_protocol(self):
        assert get_protocol_color("UNKNOWN") == "#CCCCCC"
        assert get_protocol_color("") == "#CCCCCC"
