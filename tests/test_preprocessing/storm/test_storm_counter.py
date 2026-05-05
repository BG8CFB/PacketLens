"""StormCounter 单元测试"""

from __future__ import annotations

import pytest

from app.models.packet_record import PacketRecord
from app.preprocessing.storm.counter import StormCounter


def _make_packet(
    protocol: str = "TCP",
    is_broadcast: bool = False,
    is_multicast: bool = False,
    info: str = "",
    length: int = 60,
    arp_op: int | None = None,
    icmp_type: int | None = None,
) -> PacketRecord:
    """创建测试用的 PacketRecord"""
    return PacketRecord(
        index=0,
        timestamp=0.0,
        src_ip="192.168.1.1",
        dst_ip="192.168.1.2",
        src_port=None,
        dst_port=None,
        protocol=protocol,
        length=length,
        info=info,
        raw_bytes=b"",
        is_broadcast=is_broadcast,
        is_multicast=is_multicast,
        arp_op=arp_op,
        icmp_type=icmp_type,
    )


class TestStormCounterBasic:
    def test_empty_counter(self):
        counter = StormCounter()
        assert counter.broadcast_count == 0
        assert counter.multicast_count == 0
        assert counter.arp_count == 0
        assert counter.icmp_count == 0

    def test_reset_clears_all(self):
        counter = StormCounter()
        counter.broadcast_count = 10
        counter.arp_count = 5
        counter.reset()
        assert counter.broadcast_count == 0
        assert counter.arp_count == 0


class TestStormCounterBroadcast:
    def test_broadcast_packet(self):
        counter = StormCounter()
        pkt = _make_packet(is_broadcast=True, length=100)
        counter.update(pkt)
        assert counter.broadcast_count == 1
        assert counter.broadcast_bytes == 100

    def test_non_broadcast_packet(self):
        counter = StormCounter()
        pkt = _make_packet(is_broadcast=False)
        counter.update(pkt)
        assert counter.broadcast_count == 0

    def test_multiple_broadcast_packets(self):
        counter = StormCounter()
        for _ in range(5):
            counter.update(_make_packet(is_broadcast=True, length=60))
        assert counter.broadcast_count == 5
        assert counter.broadcast_bytes == 300


class TestStormCounterMulticast:
    def test_multicast_packet(self):
        counter = StormCounter()
        pkt = _make_packet(is_multicast=True, length=80)
        counter.update(pkt)
        assert counter.multicast_count == 1
        assert counter.multicast_bytes == 80

    def test_non_multicast_packet(self):
        counter = StormCounter()
        pkt = _make_packet(is_multicast=False)
        counter.update(pkt)
        assert counter.multicast_count == 0


class TestStormCounterARP:
    def test_arp_request(self):
        counter = StormCounter()
        pkt = _make_packet(protocol="ARP", arp_op=1, info="Who has 192.168.1.1? Tell 192.168.1.2")
        counter.update(pkt)
        assert counter.arp_count == 1
        assert counter.arp_request == 1
        assert counter.arp_reply == 0

    def test_arp_reply(self):
        counter = StormCounter()
        pkt = _make_packet(protocol="ARP", arp_op=2, info="192.168.1.1 is at aa:bb:cc:dd:ee:ff")
        counter.update(pkt)
        assert counter.arp_count == 1
        assert counter.arp_request == 0
        assert counter.arp_reply == 1

    def test_non_arp_packet(self):
        counter = StormCounter()
        pkt = _make_packet(protocol="TCP")
        counter.update(pkt)
        assert counter.arp_count == 0


class TestStormCounterICMP:
    def test_icmp_echo_request(self):
        counter = StormCounter()
        pkt = _make_packet(protocol="ICMP", icmp_type=8, info="Echo (ping) request id=0x0001 seq=1")
        counter.update(pkt)
        assert counter.icmp_count == 1
        assert counter.icmp_echo_request == 1
        assert counter.icmp_echo_reply == 0

    def test_icmp_echo_reply(self):
        counter = StormCounter()
        pkt = _make_packet(protocol="ICMP", icmp_type=0, info="Echo (ping) reply id=0x0001 seq=1")
        counter.update(pkt)
        assert counter.icmp_count == 1
        assert counter.icmp_echo_request == 0
        assert counter.icmp_echo_reply == 1

    def test_icmp_other_type(self):
        counter = StormCounter()
        pkt = _make_packet(protocol="ICMP", icmp_type=3, info="Destination unreachable")
        counter.update(pkt)
        assert counter.icmp_count == 1
        assert counter.icmp_echo_request == 0
        assert counter.icmp_echo_reply == 0


class TestStormCounterMixed:
    def test_simultaneous_counts(self):
        counter = StormCounter()
        counter.update(_make_packet(is_broadcast=True, protocol="UDP"))
        counter.update(_make_packet(is_multicast=True, protocol="UDP"))
        counter.update(_make_packet(protocol="ARP", arp_op=1, info="Who has 192.168.1.1?"))
        counter.update(_make_packet(protocol="ICMP", icmp_type=8, info="Echo (ping) request"))

        assert counter.broadcast_count == 1
        assert counter.multicast_count == 1
        assert counter.arp_count == 1
        assert counter.icmp_count == 1
        assert counter.arp_request == 1
        assert counter.icmp_echo_request == 1

    def test_broadcast_arp_packet(self):
        """ARP 请求通常是广播的 — 两个计数器都应增加"""
        counter = StormCounter()
        pkt = _make_packet(
            protocol="ARP",
            is_broadcast=True,
            arp_op=1,
            info="Who has 192.168.1.1? Tell 192.168.1.2",
        )
        counter.update(pkt)
        assert counter.broadcast_count == 1
        assert counter.arp_count == 1
        assert counter.arp_request == 1
