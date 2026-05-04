"""AnomalyMarker 单元测试"""

from app.models.flow_record import FlowRecord
from app.preprocessing.anomaly_marker import AnomalyMarker, PORT_SCAN_THRESHOLD


def _make_flow(flow_id, src_ip, dst_ip, src_port, dst_port, protocol,
               packet_count=1, byte_count=100, duration=1.0):
    return FlowRecord(
        flow_id=flow_id,
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        protocol=protocol,
        packet_count=packet_count,
        byte_count=byte_count,
        first_seen=100.0,
        last_seen=100.0 + duration,
    )


class TestAnomalyMarker:

    def test_empty_flows(self):
        marker = AnomalyMarker()
        assert marker.mark([]) == []

    def test_no_anomalies_on_normal_flows(self):
        marker = AnomalyMarker()
        flows = [
            _make_flow("f1", "10.0.0.1", "10.0.0.2", 12345, 443, "TCP",
                       packet_count=50, byte_count=50000),
            _make_flow("f2", "10.0.0.1", "10.0.0.2", 12346, 80, "TCP",
                       packet_count=100, byte_count=200000),
        ]
        result = marker.mark(flows)
        assert len(result) == 0

    def test_detect_port_scan(self):
        marker = AnomalyMarker()
        flows = []
        base_port = 1000
        for i in range(PORT_SCAN_THRESHOLD):
            flows.append(
                _make_flow(f"f{i}", "192.168.1.100", "10.0.0.1",
                           i, base_port + i, "TCP", packet_count=1, byte_count=40)
            )

        result = marker.mark(flows)
        assert len(result) >= 1
        scan_alerts = [a for a in result if a["type"] == "port_scan"]
        assert len(scan_alerts) == 1
        assert scan_alerts[0]["severity"] == "Warning"
        assert "端口扫描" in scan_alerts[0]["description"]

    def test_no_port_scan_when_below_threshold(self):
        marker = AnomalyMarker()
        flows = []
        for i in range(PORT_SCAN_THRESHOLD - 1):
            flows.append(
                _make_flow(f"f{i}", "192.168.1.100", "10.0.0.1",
                           i, 1000 + i, "TCP", packet_count=1, byte_count=40)
            )

        result = marker.mark(flows)
        scan_alerts = [a for a in result if a["type"] == "port_scan"]
        assert len(scan_alerts) == 0

    def test_multiple_target_port_scans(self):
        marker = AnomalyMarker()
        flows = []
        # 对目标1的大量端口
        for i in range(PORT_SCAN_THRESHOLD):
            flows.append(_make_flow(f"a{i}", "10.0.0.1", "192.168.1.1",
                                    i, 1000 + i, "TCP", packet_count=1, byte_count=40))
        # 对目标2的大量端口
        for i in range(PORT_SCAN_THRESHOLD):
            flows.append(_make_flow(f"b{i}", "10.0.0.2", "192.168.1.2",
                                    i, 1000 + i, "TCP", packet_count=1, byte_count=40))

        result = marker.mark(flows)
        scan_alerts = [a for a in result if a["type"] == "port_scan"]
        assert len(scan_alerts) == 2

    def test_skip_high_packet_flows_for_scan(self):
        """端口扫描只检测 packet_count <= 3 的流"""
        marker = AnomalyMarker()
        flows = []
        for i in range(PORT_SCAN_THRESHOLD):
            flows.append(_make_flow(f"f{i}", "10.0.0.1", "192.168.1.1",
                                    i, 1000 + i, "TCP", packet_count=10, byte_count=400))
        result = marker.mark(flows)
        scan_alerts = [a for a in result if a["type"] == "port_scan"]
        assert len(scan_alerts) == 0

    def test_detect_unusual_port(self):
        marker = AnomalyMarker()
        flows = [
            _make_flow("f1", "10.0.0.1", "10.0.0.2", 12345, 50000, "TCP",
                       byte_count=200000),
        ]
        result = marker.mark(flows)
        unusual = [a for a in result if a["type"] == "unusual_port"]
        assert len(unusual) == 1
        assert unusual[0]["severity"] == "Info"

    def test_no_unusual_port_when_small_bytes(self):
        marker = AnomalyMarker()
        flows = [
            _make_flow("f1", "10.0.0.1", "10.0.0.2", 12345, 50000, "TCP",
                       byte_count=5000),
        ]
        result = marker.mark(flows)
        unusual = [a for a in result if a["type"] == "unusual_port"]
        assert len(unusual) == 0

    def test_detect_large_transfer(self):
        marker = AnomalyMarker()
        flows = [
            _make_flow("f1", "10.0.0.1", "10.0.0.2", 12345, 443, "TCP",
                       byte_count=2_000_000),
        ]
        result = marker.mark(flows)
        large = [a for a in result if a["type"] == "large_transfer"]
        assert len(large) == 1
        assert "MB" in large[0]["description"]

    def test_no_large_transfer_under_threshold(self):
        marker = AnomalyMarker()
        flows = [
            _make_flow("f1", "10.0.0.1", "10.0.0.2", 12345, 443, "TCP",
                       byte_count=500_000),
        ]
        result = marker.mark(flows)
        large = [a for a in result if a["type"] == "large_transfer"]
        assert len(large) == 0

    def test_description_fields(self):
        marker = AnomalyMarker()
        flows = [_make_flow("f1", "10.0.0.1", "10.0.0.2", 12345, 50000, "TCP",
                            byte_count=200000)]
        result = marker.mark(flows)
        assert len(result) == 1
        a = result[0]
        assert "type" in a
        assert "severity" in a
        assert "description" in a
        assert "affected_flows" in a
        assert "detail" in a
