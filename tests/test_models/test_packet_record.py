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
        assert "seq=1000" in record.info
        assert "win=8192" in record.info

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
        assert "type=8" in record.info
        assert "code=0" in record.info

    def test_arp(self):
        pkt = scapy.ARP(op=1, psrc="10.0.0.1", pdst="10.0.0.2",
                        hwsrc="aa:bb:cc:dd:ee:ff", hwdst="00:00:00:00:00:00")
        record = PacketRecord.from_scapy_packet(4, pkt)

        assert record.protocol == "ARP"
        assert record.src_ip == "10.0.0.1"
        assert record.dst_ip == "10.0.0.2"
        assert "op=1" in record.info

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
