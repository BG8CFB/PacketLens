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

    def test_zero_port_skipped(self):
        """port=0 应被跳过，不参与查找"""
        assert classify_service(0, 0, "ICMP") is None
        assert classify_service(0, 80, "TCP") == "HTTP"
        assert classify_service(80, 0, "TCP") == "HTTP"

    def test_dst_port_priority(self):
        """dst_port 优先于 src_port 匹配"""
        # dst=80(HTTP) 优先于 src=22(SSH)
        result = classify_service(22, 80, "TCP")
        assert result == "HTTP"

    def test_quic_on_udp_443(self):
        """UDP 443 应识别为 QUIC"""
        assert classify_service(None, 443, "UDP") == "QUIC"

    def test_tls_on_tcp_443(self):
        """TCP 443 应识别为 TLS"""
        assert classify_service(None, 443, "TCP") == "TLS"

    def test_protocol_matters(self):
        """相同端口号不同协议应返回不同服务"""
        assert classify_service(None, 53, "TCP") == "DNS"
        assert classify_service(None, 53, "UDP") == "DNS"
        # 53 端口的 ICMP 协议无匹配
        assert classify_service(None, 53, "ICMP") is None

    def test_smb_port(self):
        """445 端口应识别为 SMB"""
        assert classify_service(None, 445, "TCP") == "SMB"

    def test_wireguard_port(self):
        """51820 端口 UDP 应识别为 WireGuard"""
        assert classify_service(None, 51820, "UDP") == "WireGuard"

    def test_redis_port(self):
        """6379 端口应识别为 Redis"""
        assert classify_service(None, 6379, "TCP") == "Redis"


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

    def test_quic_color(self):
        """QUIC 协议应有对应颜色"""
        assert get_protocol_color("QUIC") == "#CC44CC"
