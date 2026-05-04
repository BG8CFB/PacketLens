"""StatsComputer 单元测试"""

from app.models.flow_record import FlowRecord
from app.models.packet_record import PacketRecord
from app.preprocessing.stats_computer import StatsComputer


def _make_pkt(index, src_ip, dst_ip, protocol, length, timestamp):
    return PacketRecord(
        index=index, timestamp=timestamp,
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=0, dst_port=0, protocol=protocol,
        length=length, info="",
        raw_bytes=b"\x00" * length,
    )


class TestStatsComputer:

    def test_empty_packets(self):
        computer = StatsComputer()
        result = computer.compute([], [])
        assert result["total_packets"] == 0
        assert result["total_bytes"] == 0
        assert result["avg_packet_size"] == 0.0
        assert result["duration"] == 0.0
        assert result["bandwidth_bps"] == 0.0
        assert result["avg_flow_size"] == 0
        assert result["top_flows"] == []
        assert result["flow_size_median"] == 0

    def test_single_packet(self):
        computer = StatsComputer()
        packets = [_make_pkt(0, "10.0.0.1", "10.0.0.2", "TCP", 100, 1000.0)]
        result = computer.compute([], packets)

        assert result["total_packets"] == 1
        assert result["total_bytes"] == 100
        assert result["avg_packet_size"] == 100.0
        assert result["duration"] == 0.0  # 只有 1 个包，duration=0
        assert result["bandwidth_bps"] == 0.0  # 除数为 0

    def test_protocol_distribution(self):
        computer = StatsComputer()
        packets = [
            _make_pkt(i, "10.0.0.1", "10.0.0.2", "TCP", 100, float(i))
            for i in range(10)
        ] + [
            _make_pkt(i + 10, "10.0.0.1", "10.0.0.2", "UDP", 80, float(i + 10))
            for i in range(5)
        ] + [
            _make_pkt(15, "10.0.0.1", "10.0.0.2", "ICMP", 84, 15.0)
        ]

        result = computer.compute([], packets)
        assert result["total_packets"] == 16
        assert result["protocol_distribution"]["TCP"] == 10
        assert result["protocol_distribution"]["UDP"] == 5
        assert result["protocol_distribution"]["ICMP"] == 1

    def test_top_talkers(self):
        computer = StatsComputer()
        packets = []
        # IP A sends 3 packets
        for i in range(3):
            packets.append(_make_pkt(i, "10.0.0.1", "10.0.0.100", "TCP", 100, float(i)))
        # IP B sends 5 packets
        for i in range(5):
            packets.append(_make_pkt(i + 3, "10.0.0.2", "10.0.0.100", "TCP", 100, float(i + 3)))

        result = computer.compute([], packets)

        # Top src: B(5) then A(3)
        top_src = result["top_talkers_src"]
        assert top_src[0] == ("10.0.0.2", 5)
        assert top_src[1] == ("10.0.0.1", 3)

        # All packets go to same dst
        top_dst = result["top_talkers_dst"]
        assert top_dst[0] == ("10.0.0.100", 8)

    def test_duration_and_bandwidth(self):
        computer = StatsComputer()
        packets = [
            _make_pkt(0, "10.0.0.1", "10.0.0.2", "TCP", 1000, 100.0),
            _make_pkt(1, "10.0.0.1", "10.0.0.2", "TCP", 1000, 105.0),
        ]
        result = computer.compute([], packets)

        assert result["duration"] == 5.0
        assert result["total_bytes"] == 2000
        # bandwidth = 2000 * 8 / 5 = 3200 bps
        assert result["bandwidth_bps"] == 3200.0

    def test_total_flows(self):
        computer = StatsComputer()
        packets = [_make_pkt(0, "1.1.1.1", "2.2.2.2", "TCP", 100, 0.0)]
        flows = [
            FlowRecord(flow_id="f1", src_ip="1.1.1.1", dst_ip="2.2.2.2",
                       src_port=1234, dst_port=80, protocol="TCP",
                       packet_count=1, byte_count=100, first_seen=0.0, last_seen=1.0),
            FlowRecord(flow_id="f2", src_ip="2.2.2.2", dst_ip="1.1.1.1",
                       src_port=80, dst_port=1234, protocol="TCP",
                       packet_count=1, byte_count=100, first_seen=0.0, last_seen=1.0),
            FlowRecord(flow_id="f3", src_ip="1.1.1.1", dst_ip="3.3.3.3",
                       src_port=5678, dst_port=443, protocol="TCP",
                       packet_count=1, byte_count=200, first_seen=0.0, last_seen=1.0),
        ]
        result = computer.compute(flows, packets)
        assert result["total_flows"] == 3
