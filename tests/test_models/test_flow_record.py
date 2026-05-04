"""FlowRecord 模型测试"""

from app.models.flow_record import FlowRecord


class TestFlowRecord:

    def test_basic_properties(self):
        flow = FlowRecord(
            flow_id="abc123",
            src_ip="192.168.1.1", dst_ip="10.0.0.1",
            src_port=443, dst_port=8080, protocol="TCP",
            packet_count=100, byte_count=10000,
            first_seen=100.0, last_seen=110.0,
        )
        assert flow.flow_id == "abc123"
        assert flow.src_ip == "192.168.1.1"
        assert flow.dst_ip == "10.0.0.1"
        assert flow.src_port == 443
        assert flow.dst_port == 8080
        assert flow.protocol == "TCP"
        assert flow.packet_count == 100
        assert flow.byte_count == 10000

    def test_duration(self):
        flow = FlowRecord(
            flow_id="x", src_ip="1.1.1.1", dst_ip="2.2.2.2",
            src_port=1, dst_port=2, protocol="TCP",
            first_seen=100.0, last_seen=115.5,
        )
        assert flow.duration == 15.5

    def test_duration_zero_when_no_first_seen(self):
        flow = FlowRecord(
            flow_id="x", src_ip="1.1.1.1", dst_ip="2.2.2.2",
            src_port=1, dst_port=2, protocol="TCP",
        )
        assert flow.duration == 0.0

    def test_bps(self):
        flow = FlowRecord(
            flow_id="x", src_ip="1.1.1.1", dst_ip="2.2.2.2",
            src_port=1, dst_port=2, protocol="TCP",
            packet_count=10, byte_count=1000,
            first_seen=100.0, last_seen=102.0,
        )
        assert flow.bps == (1000 * 8) / 2.0  # 4000 bps

    def test_bps_zero_when_no_duration(self):
        flow = FlowRecord(
            flow_id="x", src_ip="1.1.1.1", dst_ip="2.2.2.2",
            src_port=1, dst_port=2, protocol="TCP",
            byte_count=1000,
        )
        assert flow.bps == 0.0

    def test_pps(self):
        flow = FlowRecord(
            flow_id="x", src_ip="1.1.1.1", dst_ip="2.2.2.2",
            src_port=1, dst_port=2, protocol="TCP",
            packet_count=50,
            first_seen=100.0, last_seen=110.0,
        )
        assert flow.pps == 5.0

    def test_pps_zero_when_no_duration(self):
        flow = FlowRecord(
            flow_id="x", src_ip="1.1.1.1", dst_ip="2.2.2.2",
            src_port=1, dst_port=2, protocol="TCP",
            packet_count=50,
        )
        assert flow.pps == 0.0

    def test_defaults(self):
        flow = FlowRecord(
            flow_id="x", src_ip="1.1.1.1", dst_ip="2.2.2.2",
            src_port=1, dst_port=2, protocol="TCP",
        )
        assert flow.packet_count == 0
        assert flow.byte_count == 0
        assert flow.flags_set == set()
        assert flow.has_payload is False
        assert flow.service is None

    def test_flags_set_is_mutable(self):
        flow = FlowRecord(
            flow_id="x", src_ip="1.1.1.1", dst_ip="2.2.2.2",
            src_port=1, dst_port=2, protocol="TCP",
            flags_set={"S", "A"},
        )
        assert "S" in flow.flags_set
        assert "A" in flow.flags_set
        flow.flags_set.add("F")
        assert "F" in flow.flags_set
