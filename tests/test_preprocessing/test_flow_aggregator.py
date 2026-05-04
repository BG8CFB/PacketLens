"""FlowAggregator 单元测试"""

from app.models.packet_record import PacketRecord
from app.preprocessing.flow_aggregator import FlowAggregator


def _make_pkt(index, src_ip, dst_ip, src_port, dst_port, protocol, length, timestamp,
              flags=None, raw_bytes=None):
    """辅助函数：快速创建 PacketRecord"""
    return PacketRecord(
        index=index, timestamp=timestamp,
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        protocol=protocol, length=length,
        info="", raw_bytes=raw_bytes or b"\x00" * length,
        flags=flags,
    )


class TestFlowAggregator:

    def test_empty_aggregator(self):
        agg = FlowAggregator()
        assert agg.get_flow_count() == 0
        assert agg.get_total_packets() == 0
        assert agg.get_total_bytes() == 0
        assert agg.get_flows() == []

    def test_single_packet_creates_flow(self):
        agg = FlowAggregator()
        pkt = _make_pkt(0, "10.0.0.1", "10.0.0.2", 12345, 80,
                        "TCP", 100, 1000.0, flags="S")
        agg.update(pkt)

        flows = agg.get_flows()
        assert len(flows) == 1
        f = flows[0]
        assert f.src_ip == "10.0.0.1"
        assert f.dst_ip == "10.0.0.2"
        assert f.src_port == 12345
        assert f.dst_port == 80
        assert f.protocol == "TCP"
        assert f.packet_count == 1
        assert f.byte_count == 100
        assert "S" in f.flags_set

    def test_same_flow_aggregates(self):
        agg = FlowAggregator()
        for i in range(5):
            pkt = _make_pkt(i, "10.0.0.1", "10.0.0.2", 12345, 80,
                            "TCP", 100 + i * 10, 1000.0 + i, flags="SA")
            agg.update(pkt)

        assert agg.get_flow_count() == 1
        assert agg.get_total_packets() == 5
        assert agg.get_total_bytes() == 100 * 5 + 10 * (0 + 1 + 2 + 3 + 4)

        f = agg.get_flows()[0]
        assert f.packet_count == 5
        assert f.first_seen == 1000.0
        assert f.last_seen == 1004.0
        assert "SA" in f.flags_set

    def test_direction_independent(self):
        """A→B 和 B→A 应归入同一条流"""
        agg = FlowAggregator()
        agg.update(_make_pkt(0, "10.0.0.1", "10.0.0.2", 12345, 80,
                             "TCP", 100, 0.0, flags="S"))
        agg.update(_make_pkt(1, "10.0.0.2", "10.0.0.1", 80, 12345,
                             "TCP", 150, 1.0, flags="SA"))

        assert agg.get_flow_count() == 1
        f = agg.get_flows()[0]
        assert f.packet_count == 2
        assert f.byte_count == 250

    def test_different_protocols_separate(self):
        agg = FlowAggregator()
        agg.update(_make_pkt(0, "10.0.0.1", "10.0.0.2", 53, 53,
                             "UDP", 80, 0.0))
        agg.update(_make_pkt(1, "10.0.0.1", "10.0.0.2", 53, 53,
                             "TCP", 100, 1.0))

        assert agg.get_flow_count() == 2

    def test_different_ports_separate(self):
        agg = FlowAggregator()
        agg.update(_make_pkt(0, "10.0.0.1", "10.0.0.2", 80, 443,
                             "TCP", 100, 0.0))
        agg.update(_make_pkt(1, "10.0.0.1", "10.0.0.2", 80, 8080,
                             "TCP", 100, 1.0))

        assert agg.get_flow_count() == 2

    def test_different_ips_separate(self):
        agg = FlowAggregator()
        agg.update(_make_pkt(0, "10.0.0.1", "10.0.0.2", 80, 443,
                             "TCP", 100, 0.0))
        agg.update(_make_pkt(1, "10.0.0.1", "10.0.0.3", 80, 443,
                             "TCP", 100, 1.0))

        assert agg.get_flow_count() == 2

    def test_update_batch(self):
        agg = FlowAggregator()
        packets = [
            _make_pkt(i, "10.0.0.1", "10.0.0.2", 12345, 80, "TCP", 100, float(i))
            for i in range(10)
        ]
        agg.update_batch(packets)
        assert agg.get_flow_count() == 1
        assert agg.get_total_packets() == 10

    def test_reset(self):
        agg = FlowAggregator()
        agg.update(_make_pkt(0, "10.0.0.1", "10.0.0.2", 80, 443,
                             "TCP", 100, 0.0))
        assert agg.get_flow_count() == 1

        agg.reset()
        assert agg.get_flow_count() == 0
        assert agg.get_total_packets() == 0

    def test_flows_sorted_by_packet_count(self):
        agg = FlowAggregator()
        # flow1: 1 packet
        agg.update(_make_pkt(0, "10.0.0.1", "10.0.0.2", 80, 443, "TCP", 100, 0.0))
        # flow2: 3 packets
        for i in range(3):
            agg.update(_make_pkt(i + 1, "10.0.0.2", "10.0.0.3", 22, 22, "TCP", 100, float(i)))
        # flow3: 2 packets
        for i in range(2):
            agg.update(_make_pkt(i + 4, "10.0.0.3", "10.0.0.4", 53, 53, "UDP", 80, float(i)))

        flows = agg.get_flows()
        assert flows[0].packet_count == 3
        assert flows[1].packet_count == 2
        assert flows[2].packet_count == 1

    def test_has_payload(self):
        agg = FlowAggregator()
        # 小包 (无 payload)
        agg.update(_make_pkt(0, "1.1.1.1", "2.2.2.2", 80, 443, "TCP", 54, 0.0))
        assert agg.get_flows()[0].has_payload is False

        # 大包 (有 payload)
        agg.update(_make_pkt(1, "1.1.1.1", "2.2.2.2", 80, 443, "TCP", 1500, 1.0))
        assert agg.get_flows()[0].has_payload is True

    def test_skip_packets_without_ip(self):
        agg = FlowAggregator()
        agg.update(PacketRecord(
            index=0, timestamp=0.0, src_ip="", dst_ip="",
            src_port=None, dst_port=None, protocol="ARP",
            length=42, info="arp", raw_bytes=b"\x00" * 42,
        ))
        assert agg.get_flow_count() == 0

    def test_zero_ports(self):
        agg = FlowAggregator()
        agg.update(_make_pkt(0, "10.0.0.1", "10.0.0.2", None, None,
                             "ICMP", 84, 0.0))
        assert agg.get_flow_count() == 1
        f = agg.get_flows()[0]
        assert f.src_port == 0
        assert f.dst_port == 0
