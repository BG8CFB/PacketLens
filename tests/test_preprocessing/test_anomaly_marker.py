"""AnomalyMarker 单元测试 — 全部调用真实代码，不使用 mock"""

from app.models.flow_record import FlowRecord
from app.preprocessing.anomaly_marker import AnomalyMarker, PORT_SCAN_THRESHOLD


def _make_flow(
    flow_id: str,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: str,
    packet_count: int = 1,
    byte_count: int = 100,
    duration: float = 1.0,
    flags_set: set[str] | None = None,
    service: str | None = None,
) -> FlowRecord:
    """辅助函数：创建 FlowRecord 实例"""
    return FlowRecord(
        flow_id=flow_id,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        packet_count=packet_count,
        byte_count=byte_count,
        first_seen=100.0,
        last_seen=100.0 + duration,
        flags_set=flags_set or set(),
        service=service,
    )


# ── 基础场景 ─────────────────────────────────────────────


class TestAnomalyMarkerBasic:

    def test_empty_flows_returns_empty_list(self):
        marker = AnomalyMarker()
        assert marker.mark([]) == []

    def test_normal_flows_produce_no_anomalies(self):
        marker = AnomalyMarker()
        flows = [
            _make_flow("f1", "10.0.0.1", "10.0.0.2", 12345, 443, "TCP",
                        packet_count=50, byte_count=50000),
            _make_flow("f2", "10.0.0.1", "10.0.0.2", 12346, 80, "TCP",
                        packet_count=100, byte_count=200000),
        ]
        result = marker.mark(flows)
        assert len(result) == 0


# ── 端口扫描检测 ─────────────────────────────────────────


class TestPortScanDetection:

    def test_detect_port_scan_at_threshold(self):
        """恰好达到 PORT_SCAN_THRESHOLD 个不同端口时触发"""
        marker = AnomalyMarker()
        flows = [
            _make_flow(f"f{i}", "192.168.1.100", "10.0.0.1",
                        i, 1000 + i, "TCP", packet_count=1, byte_count=40)
            for i in range(PORT_SCAN_THRESHOLD)
        ]

        result = marker.mark(flows)
        scan_alerts = [a for a in result if a["type"] == "port_scan"]
        assert len(scan_alerts) == 1

        alert = scan_alerts[0]
        assert alert["severity"] == "Warning"
        assert "端口扫描" in alert["description"]
        assert alert["detail"]["source_ip"] == "192.168.1.100"
        assert alert["detail"]["target_ip"] == "10.0.0.1"
        assert alert["detail"]["port_count"] == PORT_SCAN_THRESHOLD
        assert alert["detail"]["flow_count"] == PORT_SCAN_THRESHOLD
        assert len(alert["detail"]["ports_sample"]) == PORT_SCAN_THRESHOLD
        assert len(alert["affected_flows"]) == PORT_SCAN_THRESHOLD

    def test_no_port_scan_below_threshold(self):
        """差 1 条未达阈值，不应触发"""
        marker = AnomalyMarker()
        flows = [
            _make_flow(f"f{i}", "192.168.1.100", "10.0.0.1",
                        i, 1000 + i, "TCP", packet_count=1, byte_count=40)
            for i in range(PORT_SCAN_THRESHOLD - 1)
        ]

        result = marker.mark(flows)
        scan_alerts = [a for a in result if a["type"] == "port_scan"]
        assert len(scan_alerts) == 0

    def test_multiple_targets_produce_multiple_alerts(self):
        """对不同目标 IP 的端口扫描各自独立触发"""
        marker = AnomalyMarker()
        flows = []
        for i in range(PORT_SCAN_THRESHOLD):
            flows.append(_make_flow(f"a{i}", "10.0.0.1", "192.168.1.1",
                                     i, 1000 + i, "TCP", packet_count=1, byte_count=40))
        for i in range(PORT_SCAN_THRESHOLD):
            flows.append(_make_flow(f"b{i}", "10.0.0.2", "192.168.1.2",
                                     i, 1000 + i, "TCP", packet_count=1, byte_count=40))

        result = marker.mark(flows)
        scan_alerts = [a for a in result if a["type"] == "port_scan"]
        assert len(scan_alerts) == 2

    def test_skip_high_packet_count_flows(self):
        """端口扫描只检测 packet_count <= 3 的流"""
        marker = AnomalyMarker()
        flows = [
            _make_flow(f"f{i}", "10.0.0.1", "192.168.1.1",
                        i, 1000 + i, "TCP", packet_count=10, byte_count=400)
            for i in range(PORT_SCAN_THRESHOLD)
        ]
        result = marker.mark(flows)
        scan_alerts = [a for a in result if a["type"] == "port_scan"]
        assert len(scan_alerts) == 0

    def test_udp_port_scan_also_detected(self):
        """UDP 协议的端口扫描同样应被检测"""
        marker = AnomalyMarker()
        flows = [
            _make_flow(f"f{i}", "192.168.1.100", "10.0.0.1",
                        5000 + i, 2000 + i, "UDP", packet_count=1, byte_count=40)
            for i in range(PORT_SCAN_THRESHOLD)
        ]
        result = marker.mark(flows)
        scan_alerts = [a for a in result if a["type"] == "port_scan"]
        assert len(scan_alerts) == 1
        assert scan_alerts[0]["detail"]["port_count"] == PORT_SCAN_THRESHOLD

    def test_duplicate_ports_counted_once(self):
        """重复的同一目标端口只算 1 个不同端口"""
        marker = AnomalyMarker()
        flows = [
            _make_flow(f"f{i}", "192.168.1.100", "10.0.0.1",
                        5000, 80, "TCP", packet_count=1, byte_count=40)
            for i in range(PORT_SCAN_THRESHOLD + 5)
        ]
        result = marker.mark(flows)
        scan_alerts = [a for a in result if a["type"] == "port_scan"]
        assert len(scan_alerts) == 0  # 只有 1 个不同端口


# ── 非标准端口检测 ───────────────────────────────────────


class TestUnusualPortDetection:

    def test_detect_unusual_port_traffic(self):
        """高端口 + 大流量 + 无已知服务 → 触发"""
        marker = AnomalyMarker()
        flows = [
            _make_flow("f1", "10.0.0.1", "10.0.0.2", 12345, 50000, "TCP",
                        byte_count=600000),
        ]
        result = marker.mark(flows)
        unusual = [a for a in result if a["type"] == "unusual_port"]
        assert len(unusual) == 1

        alert = unusual[0]
        assert alert["severity"] == "Info"
        assert alert["detail"]["src"] == "10.0.0.1:12345"
        assert alert["detail"]["dst"] == "10.0.0.2:50000"
        assert alert["detail"]["bytes"] == 600000
        assert alert["detail"]["packets"] == 1

    def test_no_unusual_port_when_small_bytes(self):
        """字节数低于 500KB 阈值不触发"""
        marker = AnomalyMarker()
        flows = [
            _make_flow("f1", "10.0.0.1", "10.0.0.2", 12345, 50000, "TCP",
                        byte_count=300000),
        ]
        result = marker.mark(flows)
        unusual = [a for a in result if a["type"] == "unusual_port"]
        assert len(unusual) == 0

    def test_no_unusual_port_for_well_known_port(self):
        """端口号 < 49152（高端口阈值）的不触发"""
        marker = AnomalyMarker()
        flows = [
            _make_flow("f1", "10.0.0.1", "10.0.0.2", 12345, 8080, "TCP",
                        byte_count=600000),
        ]
        result = marker.mark(flows)
        unusual = [a for a in result if a["type"] == "unusual_port"]
        assert len(unusual) == 0

    def test_no_unusual_port_when_service_identified(self):
        """有已知 service 的流不触发（如 QUIC 走 UDP:443）"""
        marker = AnomalyMarker()
        flows = [
            _make_flow("f1", "10.0.0.1", "10.0.0.2", 12345, 50000, "UDP",
                        byte_count=600000, service="SomeService"),
        ]
        result = marker.mark(flows)
        unusual = [a for a in result if a["type"] == "unusual_port"]
        assert len(unusual) == 0

    def test_icmp_not_flagged_as_unusual_port(self):
        """ICMP 协议流不应被标记为 unusual_port"""
        marker = AnomalyMarker()
        flows = [
            _make_flow("f1", "10.0.0.1", "10.0.0.2", 0, 0, "ICMP",
                        byte_count=600000),
        ]
        result = marker.mark(flows)
        unusual = [a for a in result if a["type"] == "unusual_port"]
        assert len(unusual) == 0


# ── 大流量传输检测 ───────────────────────────────────────


class TestLargeTransferDetection:

    def test_detect_large_transfer_over_10mb(self):
        """超过 10MB 触发 large_transfer"""
        marker = AnomalyMarker()
        flows = [
            _make_flow("f1", "10.0.0.1", "10.0.0.2", 12345, 443, "TCP",
                        byte_count=20_000_000, duration=5.0),
        ]
        result = marker.mark(flows)
        large = [a for a in result if a["type"] == "large_transfer"]
        assert len(large) == 1

        alert = large[0]
        assert alert["severity"] == "Info"
        assert "MB" in alert["description"]
        assert alert["detail"]["src_ip"] == "10.0.0.1"
        assert alert["detail"]["dst_ip"] == "10.0.0.2"
        assert alert["detail"]["bytes"] == 20_000_000
        assert alert["detail"]["packets"] == 1
        assert alert["detail"]["duration"] == 5.0

    def test_no_large_transfer_under_threshold(self):
        """低于 10MB 不触发"""
        marker = AnomalyMarker()
        flows = [
            _make_flow("f1", "10.0.0.1", "10.0.0.2", 12345, 443, "TCP",
                        byte_count=5_000_000),
        ]
        result = marker.mark(flows)
        large = [a for a in result if a["type"] == "large_transfer"]
        assert len(large) == 0

    def test_exactly_10mb_triggers(self):
        """恰好 10MB（等于阈值）不触发，需严格大于"""
        marker = AnomalyMarker()
        flows = [
            _make_flow("f1", "10.0.0.1", "10.0.0.2", 12345, 443, "TCP",
                        byte_count=10_000_000),
        ]
        result = marker.mark(flows)
        large = [a for a in result if a["type"] == "large_transfer"]
        assert len(large) == 0

    def test_large_transfer_description_shows_mb(self):
        """描述中包含 MB 数值"""
        marker = AnomalyMarker()
        flows = [
            _make_flow("f1", "10.0.0.1", "10.0.0.2", 12345, 443, "TCP",
                        byte_count=15_000_000, packet_count=3000),
        ]
        result = marker.mark(flows)
        large = [a for a in result if a["type"] == "large_transfer"]
        assert len(large) == 1
        assert "14.3 MB" in large[0]["description"]
        assert "3000 包" in large[0]["description"]


# ── SYN Flood 检测 ──────────────────────────────────────


class TestSynFloodDetection:

    def test_detect_syn_flood_at_threshold(self):
        """同一目标 IP 收到 >=50 条 SYN-only 流触发 Critical"""
        marker = AnomalyMarker()
        flows = [
            _make_flow(f"f{i}", f"192.168.{i // 50}.{i % 50}", "10.0.0.1",
                        40000 + i, 80, "TCP",
                        packet_count=1, byte_count=60,
                        flags_set={"S"})
            for i in range(50)
        ]

        result = marker.mark(flows)
        syn_alerts = [a for a in result if a["type"] == "syn_flood"]
        assert len(syn_alerts) == 1

        alert = syn_alerts[0]
        assert alert["severity"] == "Critical"
        assert "SYN Flood" in alert["description"]
        assert alert["detail"]["target_ip"] == "10.0.0.1"
        assert alert["detail"]["syn_flow_count"] == 50
        assert alert["detail"]["unique_sources"] == 50

    def test_no_syn_flood_below_threshold(self):
        """49 条 SYN 流不触发"""
        marker = AnomalyMarker()
        flows = [
            _make_flow(f"f{i}", f"192.168.1.{i % 50}", "10.0.0.1",
                        40000 + i, 80, "TCP",
                        packet_count=1, byte_count=60,
                        flags_set={"S"})
            for i in range(49)
        ]
        result = marker.mark(flows)
        syn_alerts = [a for a in result if a["type"] == "syn_flood"]
        assert len(syn_alerts) == 0

    def test_syn_ack_not_counted_as_syn_flood(self):
        """SYN+ACK 流不应被算作 SYN Flood（需要 'A' not in flags_set）"""
        marker = AnomalyMarker()
        flows = [
            _make_flow(f"f{i}", "192.168.1.100", "10.0.0.1",
                        40000 + i, 80, "TCP",
                        packet_count=1, byte_count=60,
                        flags_set={"S", "A"})
            for i in range(60)
        ]
        result = marker.mark(flows)
        syn_alerts = [a for a in result if a["type"] == "syn_flood"]
        assert len(syn_alerts) == 0

    def test_syn_flood_only_tcp(self):
        """非 TCP 协议的流不应触发 SYN Flood"""
        marker = AnomalyMarker()
        flows = [
            _make_flow(f"f{i}", "192.168.1.100", "10.0.0.1",
                        40000 + i, 80, "UDP",
                        packet_count=1, byte_count=60,
                        flags_set={"S"})
            for i in range(60)
        ]
        result = marker.mark(flows)
        syn_alerts = [a for a in result if a["type"] == "syn_flood"]
        assert len(syn_alerts) == 0

    def test_syn_flood_high_packet_count_excluded(self):
        """packet_count > 3 的 SYN 流不参与检测"""
        marker = AnomalyMarker()
        flows = [
            _make_flow(f"f{i}", "192.168.1.100", "10.0.0.1",
                        40000 + i, 80, "TCP",
                        packet_count=10, byte_count=600,
                        flags_set={"S"})
            for i in range(60)
        ]
        result = marker.mark(flows)
        syn_alerts = [a for a in result if a["type"] == "syn_flood"]
        assert len(syn_alerts) == 0

    def test_syn_flood_affected_flows_capped_at_50(self):
        """affected_flows 最多只取前 50 条"""
        marker = AnomalyMarker()
        flows = [
            _make_flow(f"f{i}", "192.168.1.100", "10.0.0.1",
                        40000 + i, 80, "TCP",
                        packet_count=1, byte_count=60,
                        flags_set={"S"})
            for i in range(80)
        ]
        result = marker.mark(flows)
        syn_alerts = [a for a in result if a["type"] == "syn_flood"]
        assert len(syn_alerts) == 1
        assert len(syn_alerts[0]["affected_flows"]) == 50
        assert syn_alerts[0]["detail"]["syn_flow_count"] == 80

    def test_syn_flood_sources_sample_capped_at_10(self):
        """sources_sample 最多取前 10 个源 IP"""
        marker = AnomalyMarker()
        flows = [
            _make_flow(f"f{i}", f"192.168.{i}.{i}", "10.0.0.1",
                        40000 + i, 80, "TCP",
                        packet_count=1, byte_count=60,
                        flags_set={"S"})
            for i in range(50)
        ]
        result = marker.mark(flows)
        syn_alerts = [a for a in result if a["type"] == "syn_flood"]
        assert len(syn_alerts) == 1
        assert len(syn_alerts[0]["detail"]["sources_sample"]) == 10

    def test_multiple_target_ips_multiple_alerts(self):
        """不同目标 IP 各自触发独立的 SYN Flood 告警"""
        marker = AnomalyMarker()
        flows = []
        for target_idx in range(2):
            for i in range(50):
                flows.append(
                    _make_flow(f"t{target_idx}_f{i}", "192.168.1.100",
                                f"10.0.0.{target_idx + 1}",
                                40000 + i + target_idx * 100, 80, "TCP",
                                packet_count=1, byte_count=60,
                                flags_set={"S"})
                )
        result = marker.mark(flows)
        syn_alerts = [a for a in result if a["type"] == "syn_flood"]
        assert len(syn_alerts) == 2


# ── DNS 隧道检测 ────────────────────────────────────────


class TestDnsTunnelDetection:

    def test_detect_dns_tunnel_by_service(self):
        """同一源 IP 发起 >=100 条 service='DNS' 的流触发 Warning"""
        marker = AnomalyMarker()
        flows = [
            _make_flow(f"f{i}", "192.168.1.100", "8.8.8.8",
                        40000 + i, 53, "UDP",
                        packet_count=1, byte_count=60,
                        service="DNS")
            for i in range(100)
        ]

        result = marker.mark(flows)
        dns_alerts = [a for a in result if a["type"] == "dns_tunnel"]
        assert len(dns_alerts) == 1

        alert = dns_alerts[0]
        assert alert["severity"] == "Warning"
        assert "DNS 隧道" in alert["description"]
        assert alert["detail"]["source_ip"] == "192.168.1.100"
        assert alert["detail"]["dns_flow_count"] == 100
        assert alert["detail"]["total_bytes"] == 100 * 60

    def test_detect_dns_tunnel_by_port_and_protocol(self):
        """无 service 字段但 dst_port=53 且协议为 UDP/TCP 也可触发"""
        marker = AnomalyMarker()
        flows = [
            _make_flow(f"f{i}", "192.168.1.100", "8.8.8.8",
                        40000 + i, 53, "UDP",
                        packet_count=1, byte_count=80)
            for i in range(100)
        ]

        result = marker.mark(flows)
        dns_alerts = [a for a in result if a["type"] == "dns_tunnel"]
        assert len(dns_alerts) == 1

    def test_no_dns_tunnel_below_threshold(self):
        """99 条 DNS 流不触发"""
        marker = AnomalyMarker()
        flows = [
            _make_flow(f"f{i}", "192.168.1.100", "8.8.8.8",
                        40000 + i, 53, "UDP",
                        packet_count=1, byte_count=60,
                        service="DNS")
            for i in range(99)
        ]
        result = marker.mark(flows)
        dns_alerts = [a for a in result if a["type"] == "dns_tunnel"]
        assert len(dns_alerts) == 0

    def test_dns_tunnel_tcp_port_53_also_detected(self):
        """TCP 协议 + dst_port=53 也应被计入"""
        marker = AnomalyMarker()
        flows = [
            _make_flow(f"f{i}", "192.168.1.100", "8.8.8.8",
                        40000 + i, 53, "TCP",
                        packet_count=1, byte_count=100)
            for i in range(100)
        ]
        result = marker.mark(flows)
        dns_alerts = [a for a in result if a["type"] == "dns_tunnel"]
        assert len(dns_alerts) == 1

    def test_dns_tunnel_affected_flows_capped_at_50(self):
        """affected_flows 最多取前 50 条"""
        marker = AnomalyMarker()
        flows = [
            _make_flow(f"f{i}", "192.168.1.100", "8.8.8.8",
                        40000 + i, 53, "UDP",
                        packet_count=1, byte_count=60,
                        service="DNS")
            for i in range(150)
        ]
        result = marker.mark(flows)
        dns_alerts = [a for a in result if a["type"] == "dns_tunnel"]
        assert len(dns_alerts) == 1
        assert len(dns_alerts[0]["affected_flows"]) == 50
        assert dns_alerts[0]["detail"]["dns_flow_count"] == 150

    def test_different_source_ips_counted_separately(self):
        """不同源 IP 各自独立计数"""
        marker = AnomalyMarker()
        flows = []
        for src_idx in range(2):
            for i in range(50):
                flows.append(
                    _make_flow(f"s{src_idx}_f{i}", f"192.168.1.{src_idx + 1}",
                                "8.8.8.8", 40000 + i, 53, "UDP",
                                packet_count=1, byte_count=60,
                                service="DNS")
                )
        # 每个源 IP 50 条，均未达阈值
        result = marker.mark(flows)
        dns_alerts = [a for a in result if a["type"] == "dns_tunnel"]
        assert len(dns_alerts) == 0

    def test_dns_tunnel_total_bytes_summed_correctly(self):
        """total_bytes 应为所有 DNS 流 byte_count 之和"""
        marker = AnomalyMarker()
        flows = [
            _make_flow(f"f{i}", "192.168.1.100", "8.8.8.8",
                        40000 + i, 53, "UDP",
                        packet_count=1, byte_count=100 + i,
                        service="DNS")
            for i in range(100)
        ]
        result = marker.mark(flows)
        dns_alerts = [a for a in result if a["type"] == "dns_tunnel"]
        assert len(dns_alerts) == 1
        expected_total = sum(100 + i for i in range(100))
        assert dns_alerts[0]["detail"]["total_bytes"] == expected_total


# ── 多种异常交互测试 ─────────────────────────────────────


class TestMultipleAnomaliesInteraction:

    def test_port_scan_and_syn_flood_together(self):
        """同一批流可以同时触发端口扫描和 SYN Flood"""
        marker = AnomalyMarker()
        flows = [
            _make_flow(f"f{i}", "192.168.1.100", "10.0.0.1",
                        40000 + i, 1000 + i, "TCP",
                        packet_count=1, byte_count=60,
                        flags_set={"S"})
            for i in range(50)
        ]
        # 50 个不同端口 → 端口扫描（>=20）
        # 50 条 SYN 流 → SYN Flood（>=50）
        result = marker.mark(flows)
        types = {a["type"] for a in result}
        assert "port_scan" in types
        assert "syn_flood" in types

    def test_port_scan_and_large_transfer_independent(self):
        """端口扫描 + 大流量传输可同时出现"""
        marker = AnomalyMarker()
        flows = [
            # 端口扫描流
            *[
                _make_flow(f"scan{i}", "192.168.1.100", "10.0.0.1",
                            i, 1000 + i, "TCP", packet_count=1, byte_count=40)
                for i in range(PORT_SCAN_THRESHOLD)
            ],
            # 大流量传输流
            _make_flow("big", "10.0.0.1", "10.0.0.2", 12345, 443, "TCP",
                        byte_count=20_000_000),
        ]
        result = marker.mark(flows)
        types = {a["type"] for a in result}
        assert "port_scan" in types
        assert "large_transfer" in types

    def test_all_anomaly_types_simultaneously(self):
        """五种异常可同时存在"""
        marker = AnomalyMarker()
        flows = []

        # 1) 端口扫描: 同一源→目标，>=20 个不同端口
        for i in range(PORT_SCAN_THRESHOLD):
            flows.append(
                _make_flow(f"scan{i}", "192.168.1.100", "10.0.0.1",
                            i, 1000 + i, "TCP", packet_count=1, byte_count=40)
            )

        # 2) 非标准端口: 高端口 + 大流量 + 无 service
        flows.append(
            _make_flow("unusual", "10.0.0.1", "10.0.0.2", 12345, 50000, "TCP",
                        byte_count=600000)
        )

        # 3) 大流量传输: >10MB
        flows.append(
            _make_flow("big", "10.0.0.3", "10.0.0.4", 12345, 443, "TCP",
                        byte_count=20_000_000)
        )

        # 4) SYN Flood: >=50 条 SYN-only 流
        for i in range(50):
            flows.append(
                _make_flow(f"syn{i}", f"192.168.{i}.1", "10.0.0.5",
                            40000 + i, 80, "TCP",
                            packet_count=1, byte_count=60,
                            flags_set={"S"})
            )

        # 5) DNS 隧道: >=100 条 DNS 流
        for i in range(100):
            flows.append(
                _make_flow(f"dns{i}", "192.168.1.200", "8.8.8.8",
                            40000 + i, 53, "UDP",
                            packet_count=1, byte_count=60,
                            service="DNS")
            )

        result = marker.mark(flows)
        types = {a["type"] for a in result}
        assert types == {"port_scan", "unusual_port", "large_transfer",
                         "syn_flood", "dns_tunnel"}


# ── 异常结构验证 ─────────────────────────────────────────


class TestAnomalyStructure:

    def test_anomaly_dict_has_all_required_fields(self):
        """每条异常必须包含 type, severity, description, affected_flows, detail"""
        marker = AnomalyMarker()
        flows = [
            _make_flow("f1", "10.0.0.1", "10.0.0.2", 12345, 50000, "TCP",
                        byte_count=600000),
        ]
        result = marker.mark(flows)
        assert len(result) == 1
        a = result[0]
        assert "type" in a
        assert "severity" in a
        assert "description" in a
        assert "affected_flows" in a
        assert "detail" in a
        assert isinstance(a["affected_flows"], list)
        assert isinstance(a["detail"], dict)
