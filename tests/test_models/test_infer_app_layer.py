"""应用层协议推断函数测试

使用 Scapy 构造真实数据包，测试 _infer_tcp_app_layer、_infer_udp_app_layer、
_extract_dns_name、_match_port 等推断函数的所有分支。
"""

import scapy.all as scapy

from app.models.packet_record import (
    _extract_dns_name,
    _infer_tcp_app_layer,
    _infer_udp_app_layer,
    _match_port,
)


# ---------------------------------------------------------------------------
# _match_port 测试
# ---------------------------------------------------------------------------
class TestMatchPort:
    """测试 _match_port 辅助函数"""

    PORT_GROUPS = [
        (80, 8080, 8000, 8888),
        (443, 8443),
        (22,),
        (53,),
    ]

    def test_dst_port_matches_first_group(self):
        assert _match_port(80, 9999, self.PORT_GROUPS) == 80

    def test_dst_port_matches_second_group(self):
        assert _match_port(443, 9999, self.PORT_GROUPS) == 443

    def test_src_port_matches_when_dst_does_not(self):
        """dst_port 不匹配但 src_port 匹配时应返回 src_port"""
        assert _match_port(9999, 80, self.PORT_GROUPS) == 80

    def test_src_port_matches_ssh(self):
        assert _match_port(9999, 22, self.PORT_GROUPS) == 22

    def test_neither_matches_returns_zero(self):
        assert _match_port(9999, 7777, self.PORT_GROUPS) == 0

    def test_none_ports(self):
        assert _match_port(None, None, self.PORT_GROUPS) == 0

    def test_dst_none_src_matches(self):
        assert _match_port(None, 53, self.PORT_GROUPS) == 53

    def test_both_match_dst_priority(self):
        """两个端口都匹配时优先返回 dst_port"""
        result = _match_port(80, 443, self.PORT_GROUPS)
        assert result == 80

    def test_empty_groups(self):
        assert _match_port(80, 443, []) == 0

    def test_dns_port_via_dst(self):
        assert _match_port(53, 12345, self.PORT_GROUPS) == 53

    def test_dns_port_via_src(self):
        """服务器响应包中 src_port=53，dst_port=随机高端口"""
        assert _match_port(54321, 53, self.PORT_GROUPS) == 53


# ---------------------------------------------------------------------------
# _infer_tcp_app_layer 测试
# ---------------------------------------------------------------------------
class TestInferTcpAppLayer:
    """测试 TCP 应用层推断"""

    def _make_tcp(self, sport: int, dport: int, payload: bytes = b""):
        """构造带有指定端口号和 payload 的 TCP 数据包"""
        layers = [scapy.IP(src="10.0.0.1", dst="10.0.0.2"),
                  scapy.TCP(sport=sport, dport=dport)]
        if payload:
            layers.append(scapy.Raw(payload))
        pkt = layers[0] / layers[1]
        if payload:
            pkt = pkt / scapy.Raw(payload)
        return pkt[scapy.TCP]

    def test_http_get_request(self):
        """检测 HTTP GET 请求"""
        tcp = self._make_tcp(12345, 80, b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n")
        result = _infer_tcp_app_layer(tcp, dst_port=80, src_port=12345)
        assert "[HTTP]" in result
        assert "GET" in result

    def test_http_post_request(self):
        tcp = self._make_tcp(12345, 80, b"POST /api HTTP/1.1\r\n")
        result = _infer_tcp_app_layer(tcp, dst_port=80, src_port=12345)
        assert "[HTTP]" in result
        assert "POST" in result

    def test_http_response(self):
        """检测 HTTP 响应"""
        tcp = self._make_tcp(80, 12345, b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n")
        result = _infer_tcp_app_layer(tcp, dst_port=12345, src_port=80)
        assert "[HTTP]" in result
        assert "HTTP/" in result

    def test_http_via_src_port(self):
        """服务器响应包 src_port=80 应被识别为 HTTP"""
        tcp = self._make_tcp(80, 54321, b"HTTP/1.1 200 OK\r\n")
        result = _infer_tcp_app_layer(tcp, dst_port=54321, src_port=80)
        assert "[HTTP]" in result

    def test_tls_handshake(self):
        """检测 TLS ClientHello（content_type=0x16）"""
        # TLS record: type=0x16, version=0x0301 (TLS 1.0), length=5
        payload = bytes([0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00])
        tcp = self._make_tcp(12345, 443, payload)
        result = _infer_tcp_app_layer(tcp, dst_port=443, src_port=12345)
        assert "[TLS]" in result
        # payload[5] = 0x01 → Client Hello
        assert "Client Hello" in result

    def test_tls_via_src_port(self):
        """服务器响应 src_port=443 也应识别为 TLS"""
        payload = bytes([0x16, 0x03, 0x03, 0x00, 0x02, 0x00, 0x00])
        tcp = self._make_tcp(443, 54321, payload)
        result = _infer_tcp_app_layer(tcp, dst_port=54321, src_port=443)
        assert "[TLS]" in result

    def test_tls_application_data(self):
        payload = bytes([0x17, 0x03, 0x03, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00])
        tcp = self._make_tcp(12345, 443, payload)
        result = _infer_tcp_app_layer(tcp, dst_port=443, src_port=12345)
        assert "[TLS]" in result
        assert "Application Data" in result

    def test_tls_alert(self):
        payload = bytes([0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00])
        tcp = self._make_tcp(12345, 443, payload)
        result = _infer_tcp_app_layer(tcp, dst_port=443, src_port=12345)
        assert "[TLS]" in result
        assert "Alert" in result

    def test_tls_change_cipher_spec(self):
        payload = bytes([0x14, 0x03, 0x03, 0x00, 0x01, 0x01])
        tcp = self._make_tcp(12345, 443, payload)
        result = _infer_tcp_app_layer(tcp, dst_port=443, src_port=12345)
        assert "[TLS]" in result
        assert "Change Cipher Spec" in result

    def test_tls_hint_when_no_record_header(self):
        """端口匹配 TLS 但 payload 不像 TLS 时返回 hint"""
        tcp = self._make_tcp(12345, 443, b"not tls data here")
        result = _infer_tcp_app_layer(tcp, dst_port=443, src_port=12345)
        assert result == "[TLS]"

    def test_ssh(self):
        tcp = self._make_tcp(12345, 22, b"SSH-2.0-OpenSSH_8.9\r\n")
        result = _infer_tcp_app_layer(tcp, dst_port=22, src_port=12345)
        assert "[SSH]" in result
        assert "SSH-2.0" in result

    def test_ssh_via_src_port(self):
        tcp = self._make_tcp(22, 54321, b"SSH-2.0-OpenSSH_8.9\r\n")
        result = _infer_tcp_app_layer(tcp, dst_port=54321, src_port=22)
        assert "[SSH]" in result

    def test_ftp(self):
        tcp = self._make_tcp(12345, 21, b"220 Welcome to FTP Server\r\n")
        result = _infer_tcp_app_layer(tcp, dst_port=21, src_port=12345)
        assert "[FTP]" in result

    def test_ftp_user_command(self):
        tcp = self._make_tcp(12345, 21, b"USER anonymous\r\n")
        result = _infer_tcp_app_layer(tcp, dst_port=21, src_port=12345)
        assert "[FTP]" in result
        assert "USER" in result

    def test_smtp_ehlo(self):
        tcp = self._make_tcp(12345, 25, b"EHLO client.example.com\r\n")
        result = _infer_tcp_app_layer(tcp, dst_port=25, src_port=12345)
        assert "[SMTP]" in result
        assert "EHLO" in result

    def test_smtp_via_src_port(self):
        tcp = self._make_tcp(25, 54321, b"220 mail.example.com ESMTP\r\n")
        result = _infer_tcp_app_layer(tcp, dst_port=54321, src_port=25)
        assert "[SMTP]" in result

    def test_pop3_hint(self):
        tcp = self._make_tcp(12345, 110, b"+OK POP3 server ready")
        result = _infer_tcp_app_layer(tcp, dst_port=110, src_port=12345)
        assert result == "[POP3]"

    def test_imap_hint(self):
        tcp = self._make_tcp(12345, 143, b"* OK IMAP4rev1 server ready")
        result = _infer_tcp_app_layer(tcp, dst_port=143, src_port=12345)
        assert result == "[IMAP]"

    def test_telnet_hint(self):
        tcp = self._make_tcp(12345, 23, b"Login: ")
        result = _infer_tcp_app_layer(tcp, dst_port=23, src_port=12345)
        assert result == "[Telnet]"

    def test_rdp_hint(self):
        tcp = self._make_tcp(12345, 3389, b"\x03\x00\x00\x13\x0e\xd0\x00\x00")
        result = _infer_tcp_app_layer(tcp, dst_port=3389, src_port=12345)
        assert result == "[RDP]"

    def test_smb_hint(self):
        tcp = self._make_tcp(12345, 445, b"\x00\x00\x00\x00\xff\x53\x4d\x42")
        result = _infer_tcp_app_layer(tcp, dst_port=445, src_port=12345)
        assert result == "[SMB]"

    def test_mysql(self):
        tcp = self._make_tcp(12345, 3306, b"5.7.35-0ubuntu0.18.04.1\x00")
        result = _infer_tcp_app_layer(tcp, dst_port=3306, src_port=12345)
        assert "[MySQL]" in result

    def test_mysql_via_src_port(self):
        tcp = self._make_tcp(3306, 54321, b"5.7.35-0ubuntu0.18.04.1\x00")
        result = _infer_tcp_app_layer(tcp, dst_port=54321, src_port=3306)
        assert "[MySQL]" in result

    def test_empty_payload_returns_empty(self):
        tcp = self._make_tcp(12345, 80, b"")
        result = _infer_tcp_app_layer(tcp, dst_port=80, src_port=12345)
        assert result == ""

    def test_unknown_port_returns_empty(self):
        tcp = self._make_tcp(12345, 9999, b"some random data")
        result = _infer_tcp_app_layer(tcp, dst_port=9999, src_port=12345)
        assert result == ""

    def test_http_on_alt_port_8080(self):
        tcp = self._make_tcp(12345, 8080, b"GET /api HTTP/1.1\r\n")
        result = _infer_tcp_app_layer(tcp, dst_port=8080, src_port=12345)
        assert "[HTTP]" in result
        assert "GET" in result


# ---------------------------------------------------------------------------
# _infer_udp_app_layer 测试
# ---------------------------------------------------------------------------
class TestInferUdpAppLayer:
    """测试 UDP 应用层推断"""

    def _make_udp(self, sport: int, dport: int, payload: bytes = b""):
        """构造带有指定端口号和 payload 的 UDP 数据包"""
        pkt = scapy.IP(src="10.0.0.1", dst="10.0.0.2") / scapy.UDP(sport=sport, dport=dport)
        if payload:
            pkt = pkt / scapy.Raw(payload)
        return pkt[scapy.UDP]

    def _build_dns_query(self, domain: str) -> bytes:
        """手动构建 DNS 查询 payload（不依赖 Scapy DNS 层）"""
        # Transaction ID: 0x1234
        # Flags: 0x0100 (standard query, RD=1)
        # Questions: 1, Answer/Authority/Additional RRs: 0
        header = bytes([
            0x12, 0x34,  # Transaction ID
            0x01, 0x00,  # Flags: standard query, RD=1
            0x00, 0x01,  # QDCOUNT: 1
            0x00, 0x00,  # ANCOUNT: 0
            0x00, 0x00,  # NSCOUNT: 0
            0x00, 0x00,  # ARCOUNT: 0
        ])
        # 编码域名
        qname = b""
        for label in domain.split("."):
            qname += bytes([len(label)]) + label.encode("ascii")
        qname += b"\x00"
        # QTYPE=A(1), QCLASS=IN(1)
        qtype_qclass = bytes([0x00, 0x01, 0x00, 0x01])
        return header + qname + qtype_qclass

    def _build_dns_response(self, domain: str) -> bytes:
        """手动构建 DNS 响应 payload"""
        header = bytes([
            0x12, 0x34,  # Transaction ID
            0x81, 0x80,  # Flags: standard response, RD=1, RA=1
            0x00, 0x01,  # QDCOUNT: 1
            0x00, 0x01,  # ANCOUNT: 1
            0x00, 0x00,  # NSCOUNT: 0
            0x00, 0x00,  # ARCOUNT: 0
        ])
        # Question section
        qname = b""
        for label in domain.split("."):
            qname += bytes([len(label)]) + label.encode("ascii")
        qname += b"\x00"
        qtype_qclass = bytes([0x00, 0x01, 0x00, 0x01])
        # Answer section (pointer to qname)
        answer_name = bytes([0xC0, 0x0C])  # 压缩指针指向偏移 12
        answer = answer_name + bytes([
            0x00, 0x01, 0x00, 0x01,  # TYPE=A, CLASS=IN
            0x00, 0x00, 0x01, 0x00,  # TTL=256
            0x00, 0x04,              # RDLENGTH=4
            0x01, 0x02, 0x03, 0x04,  # RDATA=1.2.3.4
        ])
        return header + qname + qtype_qclass + answer

    def test_dns_query(self):
        """检测 DNS 查询"""
        payload = self._build_dns_query("example.com")
        udp = self._make_udp(54321, 53, payload)
        result = _infer_udp_app_layer(udp, dst_port=53, src_port=54321)
        assert "[DNS]" in result
        # Wireshark 风格: [DNS] Standard query 0x1234 A example.com
        assert "Standard query" in result
        assert "example.com" in result

    def test_dns_response(self):
        """检测 DNS 响应"""
        payload = self._build_dns_response("example.com")
        udp = self._make_udp(53, 54321, payload)
        result = _infer_udp_app_layer(udp, dst_port=54321, src_port=53)
        assert "[DNS]" in result
        # Wireshark 风格: [DNS] Standard query response 0x1234 A example.com
        assert "Standard query response" in result

    def test_dns_response_via_src_port(self):
        """服务器响应 src_port=53, dst_port=随机端口，也应识别"""
        payload = self._build_dns_response("test.org")
        udp = self._make_udp(53, 54321, payload)
        result = _infer_udp_app_layer(udp, dst_port=54321, src_port=53)
        assert "[DNS]" in result
        assert "Standard query response" in result

    def test_dns_short_payload(self):
        """DNS payload 不足 12 字节时返回 [DNS]"""
        udp = self._make_udp(54321, 53, b"\x00" * 5)
        result = _infer_udp_app_layer(udp, dst_port=53, src_port=54321)
        assert result == "[DNS]"

    def test_dns_no_domain(self):
        """DNS payload 有效但无法提取域名时仍应返回 [DNS] + direction"""
        # 12 字节 header 后紧跟 0x00（空标签，即根域名）
        payload = bytes(12) + b"\x00"
        udp = self._make_udp(54321, 53, payload)
        result = _infer_udp_app_layer(udp, dst_port=53, src_port=54321)
        assert "[DNS]" in result

    def test_dhcp_client(self):
        udp = self._make_udp(68, 67, b"\x01" + b"\x00" * 10)
        result = _infer_udp_app_layer(udp, dst_port=67, src_port=68)
        assert result == "[DHCP]"

    def test_dhcp_server(self):
        udp = self._make_udp(67, 68, b"\x02" + b"\x00" * 10)
        result = _infer_udp_app_layer(udp, dst_port=68, src_port=67)
        assert result == "[DHCP]"

    def test_ntp(self):
        udp = self._make_udp(123, 123, b"\x00" * 48)
        result = _infer_udp_app_layer(udp, dst_port=123, src_port=123)
        assert result == "[NTP]"

    def test_snmp(self):
        udp = self._make_udp(54321, 161, b"\x30\x00")
        result = _infer_udp_app_layer(udp, dst_port=161, src_port=54321)
        assert result == "[SNMP]"

    def test_quic_handshake(self):
        payload = bytes([0x16, 0x03, 0x03, 0x00, 0x10]) + b"\x00" * 16
        udp = self._make_udp(54321, 443, payload)
        result = _infer_udp_app_layer(udp, dst_port=443, src_port=54321)
        assert "[QUIC]" in result
        assert "Handshake" in result

    def test_quic_via_src_port(self):
        """服务器响应 src_port=443 也应识别为 QUIC"""
        payload = bytes([0x16, 0x03, 0x03, 0x00, 0x10]) + b"\x00" * 16
        udp = self._make_udp(443, 54321, payload)
        result = _infer_udp_app_layer(udp, dst_port=54321, src_port=443)
        assert "[QUIC]" in result

    def test_quic_no_handshake(self):
        udp = self._make_udp(54321, 443, b"random data not quic")
        result = _infer_udp_app_layer(udp, dst_port=443, src_port=54321)
        assert result == "[QUIC]"

    def test_empty_payload_returns_empty(self):
        udp = self._make_udp(54321, 53, b"")
        result = _infer_udp_app_layer(udp, dst_port=53, src_port=54321)
        assert result == ""

    def test_unknown_port_returns_empty(self):
        udp = self._make_udp(54321, 9999, b"some data")
        result = _infer_udp_app_layer(udp, dst_port=9999, src_port=54321)
        assert result == ""


# ---------------------------------------------------------------------------
# _extract_dns_name 测试
# ---------------------------------------------------------------------------
class TestExtractDnsName:
    """测试 DNS 域名提取"""

    def test_simple_name(self):
        """提取简单域名"""
        # 3"www" + 11"example" + 3"com" + 0
        data = b"\x03www\x07example\x03com\x00"
        result = _extract_dns_name(data, 0)
        assert result == "www.example.com"

    def test_single_label(self):
        data = b"\x09localhost\x00"
        result = _extract_dns_name(data, 0)
        assert result == "localhost"

    def test_compressed_pointer(self):
        """DNS 压缩指针解析"""
        # 偏移 0: 3"www" + pointer(0x10)
        # 偏移 0x10: 7"example" + 3"com" + 0
        suffix = b"\x07example\x03com\x00"
        prefix = b"\x03www" + bytes([0xC0, 0x10])
        # 用零填充使 suffix 在偏移 0x10
        padding = b"\x00" * (0x10 - len(prefix))
        data = prefix + padding + suffix
        result = _extract_dns_name(data, 0)
        assert result == "www.example.com"

    def test_empty_data(self):
        result = _extract_dns_name(b"", 0)
        assert result == ""

    def test_offset_beyond_data(self):
        result = _extract_dns_name(b"\x00", 10)
        assert result == ""

    def test_non_ascii_label(self):
        """非 ASCII 字符用 replacement char 替换"""
        data = b"\x04test\xc0\x80\x00"  # 含有非 ASCII 字节
        result = _extract_dns_name(data, 0)
        assert "test" in result
