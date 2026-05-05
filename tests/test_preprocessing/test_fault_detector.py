"""FaultCounter + FaultDetector 单元测试"""

import pytest

from app.models.packet_record import PacketRecord
from app.models.flow_record import FlowRecord
from app.preprocessing.fault.counter import FaultCounter
from app.preprocessing.fault.fault_detector import FaultDetector
from app.preprocessing.storm.counter import StormCounter


def _make_packet(**overrides) -> PacketRecord:
    defaults = dict(
        index=0, timestamp=1.0, src_ip="192.168.1.1", dst_ip="192.168.1.2",
        src_port=12345, dst_port=80, protocol="TCP", length=100,
        info="", raw_bytes=b"", summary="",
    )
    defaults.update(overrides)
    return PacketRecord(**defaults)


def _make_flow(**overrides) -> FlowRecord:
    defaults = dict(
        flow_id="abc123", src_ip="192.168.1.1", dst_ip="192.168.1.2",
        src_port=12345, dst_port=80, protocol="TCP",
        packet_count=100, byte_count=10000,
    )
    defaults.update(overrides)
    return FlowRecord(**defaults)


# ── FaultCounter 测试 ──


class TestFaultCounter:
    def test_tcp_zero_window_counted(self):
        counter = FaultCounter()
        for i in range(5):
            counter.update(_make_packet(protocol="TCP", tcp_window=0, index=i))
        assert counter.tcp_zero_windows == 5
        assert counter.tcp_total == 5

    def test_tcp_rst_counted(self):
        counter = FaultCounter()
        counter.update(_make_packet(protocol="TCP", flags="R", index=0))
        counter.update(_make_packet(protocol="TCP", flags="S", index=1))
        assert counter.tcp_rst_count == 1
        assert counter.tcp_total == 2

    def test_icmp_error_counted(self):
        counter = FaultCounter()
        for t in [3, 5, 11, 8, 0]:
            counter.update(_make_packet(protocol="ICMP", icmp_type=t, index=t))
        assert counter.icmp_error_count == 3
        assert counter.icmp_error_by_type == {3: 1, 5: 1, 11: 1}

    def test_dns_rcode_counted(self):
        counter = FaultCounter()
        counter.update(_make_packet(protocol="UDP", src_port=53, dns_rcode=0, index=0))
        counter.update(_make_packet(protocol="UDP", src_port=53, dns_rcode=3, index=1))
        counter.update(_make_packet(protocol="UDP", src_port=53, dns_rcode=2, index=2))
        assert counter.dns_response_count == 3
        assert counter.dns_failure_count == 2
        assert counter.dns_rcode_breakdown == {0: 1, 3: 1, 2: 1}

    def test_fragment_counted(self):
        counter = FaultCounter()
        counter.update(_make_packet(ip_flags_mf=True, ip_frag=0, index=0))
        counter.update(_make_packet(ip_flags_mf=False, ip_frag=8, index=1))
        assert counter.frag_packets == 2

    def test_ttl_tracked(self):
        counter = FaultCounter()
        for ttl in [64, 64, 63, 64, 62]:
            counter.update(_make_packet(ttl=ttl, index=ttl))
        assert counter.ttl_by_src["192.168.1.1"] == [64, 64, 63, 64, 62]

    def test_ttl_sample_limit(self):
        counter = FaultCounter()
        for i in range(150):
            counter.update(_make_packet(ttl=64, index=i))
        assert len(counter.ttl_by_src["192.168.1.1"]) == 100

    def test_pps_buckets(self):
        counter = FaultCounter()
        for i in range(100):
            counter.update(_make_packet(timestamp=float(i) / 10, index=i))
        stats = counter.get_pps_stats()
        assert stats["max_pps"] > 0

    def test_reset(self):
        counter = FaultCounter()
        counter.update(_make_packet(protocol="TCP", tcp_window=0))
        counter.reset()
        assert counter.tcp_total == 0
        assert counter.tcp_zero_windows == 0

    def test_non_tcp_window_ignored(self):
        counter = FaultCounter()
        counter.update(_make_packet(protocol="UDP", tcp_window=0))
        assert counter.tcp_total == 0
        assert counter.tcp_zero_windows == 0


# ── FaultDetector 测试 ──


class TestARPSpoof:
    def test_detects_arp_spoof(self):
        packets = [
            _make_packet(protocol="ARP", arp_op=2, src_ip="192.168.1.1",
                         src_mac="aa:bb:cc:dd:ee:01", index=i)
            for i in range(3)
        ]
        packets += [
            _make_packet(protocol="ARP", arp_op=2, src_ip="192.168.1.1",
                         src_mac="aa:bb:cc:dd:ee:02", index=i)
            for i in range(3, 6)
        ]
        detector = FaultDetector()
        alerts = detector._detect_arp_spoof(packets)
        assert len(alerts) == 1
        assert alerts[0].type == "arp_spoof"
        assert alerts[0].severity == "Warning"

    def test_no_spoof_same_mac(self):
        packets = [
            _make_packet(protocol="ARP", arp_op=2, src_ip="192.168.1.1",
                         src_mac="aa:bb:cc:dd:ee:ff", index=i)
            for i in range(5)
        ]
        detector = FaultDetector()
        alerts = detector._detect_arp_spoof(packets)
        assert len(alerts) == 0

    def test_critical_arp_spoof(self):
        packets = []
        for i in range(6):
            packets.append(
                _make_packet(protocol="ARP", arp_op=2, src_ip="192.168.1.1",
                             src_mac=f"aa:bb:cc:dd:ee:{i:02x}", index=i)
            )
        detector = FaultDetector()
        alerts = detector._detect_arp_spoof(packets)
        assert len(alerts) == 1
        assert alerts[0].severity == "Critical"


class TestTCPRetransmit:
    def test_global_high_retransmit(self):
        counter = FaultCounter()
        counter.tcp_total = 100
        flows = [_make_flow(retransmit_count=10, packet_count=100)]
        detector = FaultDetector()
        alerts = detector._detect_tcp_retransmit(counter, flows)
        assert len(alerts) == 1
        assert alerts[0].type == "tcp_retransmit"
        assert alerts[0].severity == "Warning"

    def test_critical_retransmit(self):
        counter = FaultCounter()
        counter.tcp_total = 100
        flows = [_make_flow(retransmit_count=20, packet_count=100)]
        detector = FaultDetector()
        alerts = detector._detect_tcp_retransmit(counter, flows)
        assert len(alerts) == 1
        assert alerts[0].severity == "Critical"

    def test_below_threshold(self):
        counter = FaultCounter()
        counter.tcp_total = 100
        flows = [_make_flow(retransmit_count=2, packet_count=100)]
        detector = FaultDetector()
        alerts = detector._detect_tcp_retransmit(counter, flows)
        assert len(alerts) == 0

    def test_single_flow_high_retransmit(self):
        counter = FaultCounter()
        counter.tcp_total = 100
        flows = [_make_flow(retransmit_count=30, packet_count=50)]
        detector = FaultDetector()
        alerts = detector._detect_tcp_retransmit(counter, flows)
        assert len(alerts) >= 1


class TestTCPZeroWindow:
    def test_warning_threshold(self):
        counter = FaultCounter()
        counter.tcp_zero_windows = 15
        flows = [_make_flow(zero_window_count=15)]
        detector = FaultDetector()
        alerts = detector._detect_tcp_zero_window(counter, flows)
        assert len(alerts) == 1
        assert alerts[0].type == "tcp_zero_window"
        assert alerts[0].severity == "Warning"

    def test_critical_threshold(self):
        counter = FaultCounter()
        counter.tcp_zero_windows = 60
        flows = [_make_flow(zero_window_count=60)]
        detector = FaultDetector()
        alerts = detector._detect_tcp_zero_window(counter, flows)
        assert alerts[0].severity == "Critical"

    def test_below_threshold(self):
        counter = FaultCounter()
        counter.tcp_zero_windows = 5
        detector = FaultDetector()
        alerts = detector._detect_tcp_zero_window(counter, [])
        assert len(alerts) == 0


class TestRSTStorm:
    def test_rst_storm_detected(self):
        counter = FaultCounter()
        counter.tcp_rst_count = 200
        detector = FaultDetector()
        alerts = detector._detect_rst_storm(counter, 10.0)
        assert len(alerts) == 1
        assert alerts[0].type == "rst_storm"
        assert alerts[0].severity == "Warning"

    def test_critical_rst(self):
        counter = FaultCounter()
        counter.tcp_rst_count = 600
        detector = FaultDetector()
        alerts = detector._detect_rst_storm(counter, 10.0)
        assert alerts[0].severity == "Critical"

    def test_below_threshold(self):
        counter = FaultCounter()
        counter.tcp_rst_count = 50
        detector = FaultDetector()
        alerts = detector._detect_rst_storm(counter, 10.0)
        assert len(alerts) == 0


class TestICMPErrors:
    def test_icmp_error_storm(self):
        counter = FaultCounter()
        counter.icmp_error_count = 100
        counter.icmp_error_by_type = {3: 60, 11: 40}
        detector = FaultDetector()
        alerts = detector._detect_icmp_errors(counter, 10.0)
        assert len(alerts) == 1
        assert alerts[0].type == "icmp_error_storm"

    def test_below_threshold(self):
        counter = FaultCounter()
        counter.icmp_error_count = 20
        detector = FaultDetector()
        alerts = detector._detect_icmp_errors(counter, 10.0)
        assert len(alerts) == 0


class TestTTLAnomaly:
    def test_ttl_anomaly_detected(self):
        counter = FaultCounter()
        counter.ttl_by_src = {"10.0.0.1": [64, 64, 63, 64, 62] * 5 + [1, 2]}
        detector = FaultDetector()
        alerts = detector._detect_ttl_anomaly(counter)
        assert len(alerts) == 1
        assert alerts[0].type == "ttl_anomaly"
        assert alerts[0].detail["ttl_range"] == 63

    def test_no_anomaly_stable_ttl(self):
        counter = FaultCounter()
        counter.ttl_by_src = {"10.0.0.1": [64] * 30}
        detector = FaultDetector()
        alerts = detector._detect_ttl_anomaly(counter)
        assert len(alerts) == 0

    def test_insufficient_samples(self):
        counter = FaultCounter()
        counter.ttl_by_src = {"10.0.0.1": [64, 1]}
        detector = FaultDetector()
        alerts = detector._detect_ttl_anomaly(counter)
        assert len(alerts) == 0


class TestDNSFailure:
    def test_high_failure_rate(self):
        counter = FaultCounter()
        counter.dns_response_count = 50
        counter.dns_failure_count = 10
        counter.dns_rcode_breakdown = {3: 8, 2: 2}
        detector = FaultDetector()
        alerts = detector._detect_dns_failure(counter)
        assert any(a.type == "dns_failure" for a in alerts)

    def test_servfail_independent(self):
        counter = FaultCounter()
        counter.dns_response_count = 100
        counter.dns_failure_count = 3
        counter.dns_rcode_breakdown = {2: 6, 0: 97}
        detector = FaultDetector()
        alerts = detector._detect_dns_failure(counter)
        assert any(a.type == "dns_servfail" for a in alerts)

    def test_below_threshold(self):
        counter = FaultCounter()
        counter.dns_response_count = 20
        counter.dns_failure_count = 1
        counter.dns_rcode_breakdown = {0: 19, 3: 1}
        detector = FaultDetector()
        alerts = detector._detect_dns_failure(counter)
        assert len(alerts) == 0


class TestIPFragmentAnomaly:
    def test_fragment_overlap(self):
        counter = FaultCounter()
        counter.frag_packets = 20
        counter.frag_overlaps = 8
        detector = FaultDetector()
        alerts = detector._detect_ip_fragment_anomaly(counter)
        assert any(a.type == "fragment_overlap" for a in alerts)

    def test_fragment_incomplete(self):
        counter = FaultCounter()
        counter.frag_packets = 30
        counter.frag_incomplete = 15
        detector = FaultDetector()
        alerts = detector._detect_ip_fragment_anomaly(counter)
        assert any(a.type == "fragment_incomplete" for a in alerts)


class TestTrafficBurst:
    def test_burst_detected(self):
        counter = FaultCounter()
        counter.pps_buckets = [10] * 59 + [500]
        counter._current_bucket_ts = 60.0
        detector = FaultDetector()
        alerts = detector._detect_traffic_burst(counter, 60.0)
        assert len(alerts) == 1
        assert alerts[0].type == "traffic_burst"

    def test_no_burst_uniform(self):
        counter = FaultCounter()
        counter.pps_buckets = [50] * 60
        counter._current_bucket_ts = 60.0
        detector = FaultDetector()
        alerts = detector._detect_traffic_burst(counter, 60.0)
        assert len(alerts) == 0


class TestFaultDetectorIntegration:
    def test_detect_all_empty(self):
        detector = FaultDetector()
        alerts = detector.detect(
            fault_counter=FaultCounter(),
            storm_counter=StormCounter(),
            flows=[], packets=[], duration=10.0,
        )
        assert alerts == []

    def test_detect_with_multiple_faults(self):
        counter = FaultCounter()
        counter.tcp_total = 100
        counter.tcp_zero_windows = 15
        counter.tcp_rst_count = 200
        counter.ttl_by_src = {"10.0.0.1": [64, 1] * 15}

        flows = [_make_flow(retransmit_count=10, zero_window_count=15)]

        detector = FaultDetector()
        alerts = detector.detect(
            fault_counter=counter,
            storm_counter=StormCounter(),
            flows=flows, packets=[], duration=10.0,
        )
        types = {a["type"] for a in alerts}
        assert "tcp_zero_window" in types
        assert "rst_storm" in types
        assert "ttl_anomaly" in types
