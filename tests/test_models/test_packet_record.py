"""PacketRecord 模型测试"""

import scapy.all as scapy
from app.models.packet_record import PacketRecord


class TestPacketRecordBasic:
    """测试 PacketRecord 基本属性"""

    def test_create_minimal(self):
        pkt = PacketRecord(
            index=1, timestamp=1000.5, src_ip="192.168.1.1",
            dst_ip="10.0.0.1", src_port=443, dst_port=8080,
            protocol="TCP", length=1500, info="test info",
            raw_bytes=b"\x00" * 100,
        )
        assert pkt.index == 1
        assert pkt.src_ip == "192.168.1.1"
        assert pkt.dst_ip == "10.0.0.1"
        assert pkt.src_port == 443
        assert pkt.dst_port == 8080
        assert pkt.protocol == "TCP"
        assert pkt.length == 1500
        assert pkt.raw_bytes == b"\x00" * 100
        assert pkt.ttl is None
        assert pkt.flags is None
        assert pkt.summary == ""

    def test_create_with_optional_fields(self):
        pkt = PacketRecord(
            index=2, timestamp=2000.0, src_ip="", dst_ip="",
            src_port=None, dst_port=None, protocol="ARP", length=42,
            info="arp", raw_bytes=b"abc", ttl=64, flags="SA",
            summary="ARP summary",
        )
        assert pkt.ttl == 64
        assert pkt.flags == "SA"
        assert pkt.summary == "ARP summary"


class TestPacketRecordFromScapy:
    """测试 from_scapy_packet 工厂方法"""

    def test_tcp_syn(self):
        pkt = scapy.IP(src="10.0.0.1", dst="10.0.0.2") / scapy.TCP(
            sport=12345, dport=80, flags="S", seq=1000, window=8192
        )
        record = PacketRecord.from_scapy_packet(0, pkt)

        assert record.protocol == "TCP"
        assert record.src_ip == "10.0.0.1"
        assert record.dst_ip == "10.0.0.2"
        assert record.src_port == 12345
        assert record.dst_port == 80
        assert record.flags == "S"
        assert record.ttl == 64  # Scapy 默认 TTL
        # Wireshark 风格: [SYN] Seq=1000 Win=8192
        assert "[SYN]" in record.info
        assert "Seq=1000" in record.info
        assert "Win=8192" in record.info

    def test_tcp_syn_ack(self):
        pkt = scapy.IP(src="10.0.0.2", dst="10.0.0.1") / scapy.TCP(
            sport=80, dport=12345, flags="SA", seq=2000, ack=1001
        )
        record = PacketRecord.from_scapy_packet(1, pkt)

        assert record.protocol == "TCP"
        assert record.src_ip == "10.0.0.2"
        assert record.dst_ip == "10.0.0.1"
        assert record.flags == "SA"
        assert record.length > 0

    def test_udp(self):
        pkt = scapy.IP(src="10.0.0.1", dst="8.8.8.8") / scapy.UDP(
            sport=54321, dport=53
        ) / scapy.DNS(rd=1, qd=scapy.DNSQR(qname="example.com"))
        record = PacketRecord.from_scapy_packet(2, pkt)

        assert record.protocol == "UDP"
        assert record.src_port == 54321
        assert record.dst_port == 53
        assert record.src_ip == "10.0.0.1"
        assert record.dst_ip == "8.8.8.8"

    def test_icmp(self):
        pkt = scapy.IP(src="10.0.0.1", dst="10.0.0.2") / scapy.ICMP(type=8, code=0)
        record = PacketRecord.from_scapy_packet(3, pkt)

        assert record.protocol == "ICMP"
        # Wireshark 风格: Echo (ping) request id=0xNNNN seq=N
        assert "Echo (ping) request" in record.info

    def test_arp(self):
        pkt = scapy.ARP(op=1, psrc="10.0.0.1", pdst="10.0.0.2",
                        hwsrc="aa:bb:cc:dd:ee:ff", hwdst="00:00:00:00:00:00")
        record = PacketRecord.from_scapy_packet(4, pkt)

        assert record.protocol == "ARP"
        assert record.src_ip == "10.0.0.1"
        assert record.dst_ip == "10.0.0.2"
        # Wireshark 风格: Who has 10.0.0.2? Tell 10.0.0.1
        assert "Who has" in record.info
        assert "10.0.0.2" in record.info
        assert "Tell" in record.info

    def test_index_is_set(self):
        pkt = scapy.IP(src="1.1.1.1", dst="2.2.2.2") / scapy.TCP(sport=1, dport=2)
        for i in range(5):
            record = PacketRecord.from_scapy_packet(i, pkt)
            assert record.index == i

    def test_raw_bytes_are_captured(self):
        pkt = scapy.IP(src="1.1.1.1", dst="2.2.2.2") / scapy.TCP(sport=80, dport=443)
        record = PacketRecord.from_scapy_packet(0, pkt)
        assert record.raw_bytes == bytes(pkt)
        assert record.length == len(bytes(pkt))

    def test_ip_with_unknown_proto(self):
        pkt = scapy.IP(src="10.0.0.1", dst="10.0.0.2", proto=47)
        record = PacketRecord.from_scapy_packet(0, pkt)

        assert record.protocol == "IP proto=47"
        assert record.src_ip == "10.0.0.1"
        assert record.dst_ip == "10.0.0.2"


class TestPacketRecordSerialization:
    """测试 PacketRecord to_dict / from_dict 序列化"""

    def test_to_dict_basic(self):
        pkt = PacketRecord(
            index=1, timestamp=1000.5, src_ip="192.168.1.1",
            dst_ip="10.0.0.1", src_port=443, dst_port=8080,
            protocol="TCP", length=1500, info="SA seq=100",
            raw_bytes=b"\xde\xad\xbe\xef",
            ttl=64, flags="SA", summary="TCP summary",
        )
        d = pkt.to_dict()
        assert d["index"] == 1
        assert d["timestamp"] == 1000.5
        assert d["src_ip"] == "192.168.1.1"
        assert d["dst_ip"] == "10.0.0.1"
        assert d["src_port"] == 443
        assert d["dst_port"] == 8080
        assert d["protocol"] == "TCP"
        assert d["length"] == 1500
        assert d["info"] == "SA seq=100"
        assert d["raw_bytes"] == "deadbeef"
        assert d["ttl"] == 64
        assert d["flags"] == "SA"
        assert d["summary"] == "TCP summary"

    def test_from_dict_roundtrip(self):
        original = PacketRecord(
            index=42, timestamp=9999.0, src_ip="1.2.3.4",
            dst_ip="5.6.7.8", src_port=12345, dst_port=80,
            protocol="TCP", length=256, info="test info",
            raw_bytes=b"\x01\x02\x03\x04",
            ttl=128, flags="S", summary="summary text",
        )
        d = original.to_dict()
        restored = PacketRecord.from_dict(d)
        assert restored.index == original.index
        assert restored.timestamp == original.timestamp
        assert restored.src_ip == original.src_ip
        assert restored.dst_ip == original.dst_ip
        assert restored.src_port == original.src_port
        assert restored.dst_port == original.dst_port
        assert restored.protocol == original.protocol
        assert restored.length == original.length
        assert restored.info == original.info
        assert restored.raw_bytes == original.raw_bytes
        assert restored.ttl == original.ttl
        assert restored.flags == original.flags
        assert restored.summary == original.summary

    def test_from_dict_with_none_fields(self):
        d = {
            "index": 0,
            "timestamp": 0.0,
            "src_ip": "", "dst_ip": "",
            "protocol": "Other",
            "length": 0,
            "info": "",
            "raw_bytes": "",
        }
        pkt = PacketRecord.from_dict(d)
        assert pkt.src_port is None
        assert pkt.dst_port is None
        assert pkt.ttl is None
        assert pkt.flags is None
        assert pkt.summary == ""
        assert pkt.raw_bytes == b""

    def test_from_dict_defaults(self):
        d = {}
        pkt = PacketRecord.from_dict(d)
        assert pkt.index == 0
        assert pkt.timestamp == 0.0
        assert pkt.src_ip == ""
        assert pkt.protocol == "Other"
        assert pkt.raw_bytes == b""

    def test_to_dict_raw_bytes_hex(self):
        """raw_bytes 应以 hex 字符串序列化，from_dict 应能正确还原"""
        pkt = PacketRecord(
            index=0, timestamp=0.0, src_ip="", dst_ip="",
            src_port=None, dst_port=None, protocol="TCP",
            length=4, info="", raw_bytes=b"\x00\xff\x0a\x0d",
        )
        d = pkt.to_dict()
        assert d["raw_bytes"] == "00ff0a0d"
        restored = PacketRecord.from_dict(d)
        assert restored.raw_bytes == b"\x00\xff\x0a\x0d"
