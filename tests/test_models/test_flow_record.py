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

    # --- to_dict / from_dict 测试 ---

    def test_to_dict_contains_only_storage_fields(self):
        """to_dict 不应包含计算属性（duration, bps, pps）"""
        flow = FlowRecord(
            flow_id="abc", src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=12345, dst_port=80, protocol="TCP",
            packet_count=10, byte_count=5000,
            first_seen=100.0, last_seen=110.0,
            flags_set={"S", "A"}, has_payload=True, service="HTTP",
        )
        d = flow.to_dict()
        # 存储属性必须存在
        assert d["flow_id"] == "abc"
        assert d["src_ip"] == "10.0.0.1"
        assert d["dst_ip"] == "10.0.0.2"
        assert d["src_port"] == 12345
        assert d["dst_port"] == 80
        assert d["protocol"] == "TCP"
        assert d["packet_count"] == 10
        assert d["byte_count"] == 5000
        assert d["first_seen"] == 100.0
        assert d["last_seen"] == 110.0
        assert d["flags_set"] == ["A", "S"]  # sorted
        assert d["has_payload"] is True
        assert d["service"] == "HTTP"
        # 计算属性不应存在
        assert "duration" not in d
        assert "bps" not in d
        assert "pps" not in d

    def test_to_dict_flags_set_sorted(self):
        """flags_set 应排序后输出，确保 JSON 序列化稳定性"""
        flow = FlowRecord(
            flow_id="x", src_ip="1.1.1.1", dst_ip="2.2.2.2",
            src_port=1, dst_port=2, protocol="TCP",
            flags_set={"F", "S", "A"},
        )
        d = flow.to_dict()
        assert d["flags_set"] == ["A", "F", "S"]

    def test_from_dict_roundtrip(self):
        """to_dict → from_dict 往返一致性"""
        original = FlowRecord(
            flow_id="rt", src_ip="192.168.0.1", dst_ip="8.8.8.8",
            src_port=54321, dst_port=53, protocol="UDP",
            packet_count=42, byte_count=8400,
            first_seen=1000.0, last_seen=1020.0,
            flags_set=set(), has_payload=True, service="DNS",
        )
        d = original.to_dict()
        restored = FlowRecord.from_dict(d)
        assert restored.flow_id == original.flow_id
        assert restored.src_ip == original.src_ip
        assert restored.dst_ip == original.dst_ip
        assert restored.src_port == original.src_port
        assert restored.dst_port == original.dst_port
        assert restored.protocol == original.protocol
        assert restored.packet_count == original.packet_count
        assert restored.byte_count == original.byte_count
        assert restored.first_seen == original.first_seen
        assert restored.last_seen == original.last_seen
        assert restored.flags_set == original.flags_set
        assert restored.has_payload == original.has_payload
        assert restored.service == original.service
        # 计算属性也应一致
        assert restored.duration == original.duration

    def test_from_dict_with_empty_flags(self):
        d = {
            "flow_id": "e", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
            "src_port": 1, "dst_port": 2, "protocol": "ICMP",
        }
        flow = FlowRecord.from_dict(d)
        assert flow.flags_set == set()

    def test_from_dict_defaults(self):
        """from_dict 缺少字段时应使用合理默认值"""
        d = {"flow_id": "d"}
        flow = FlowRecord.from_dict(d)
        assert flow.src_ip == ""
        assert flow.dst_ip == ""
        assert flow.src_port == 0
        assert flow.dst_port == 0
        assert flow.protocol == ""
        assert flow.packet_count == 0
        assert flow.byte_count == 0
        assert flow.first_seen == 0.0
        assert flow.last_seen == 0.0
        assert flow.flags_set == set()
        assert flow.has_payload is False
        assert flow.service is None
