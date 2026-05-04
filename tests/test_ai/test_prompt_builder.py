"""PromptBuilder 单元测试"""

from app.ai.prompt_builder import PromptBuilder, _select_relevant_packets
from app.models.flow_record import FlowRecord
from app.models.packet_record import PacketRecord


def _make_flow(flow_id, src_ip, dst_ip, src_port, dst_port, protocol,
               packet_count=10, byte_count=1000, duration=5.0):
    return FlowRecord(
        flow_id=flow_id,
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        protocol=protocol,
        packet_count=packet_count, byte_count=byte_count,
        first_seen=100.0, last_seen=100.0 + duration,
    )


def _make_pkt(index, src_ip, dst_ip, src_port, dst_port, protocol,
              length=100, timestamp=100.0):
    return PacketRecord(
        index=index, timestamp=timestamp,
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        protocol=protocol, length=length,
        info=f"pkt{index}", raw_bytes=b"\x00" * length,
    )


class TestPromptBuilder:

    def test_build_quick_prompt_basic(self):
        builder = PromptBuilder()
        flows = [
            _make_flow("abc123", "10.0.0.1", "10.0.0.2", 12345, 80, "TCP"),
        ]
        stats = {
            "total_packets": 100,
            "total_bytes": 50000,
            "total_flows": 5,
            "duration": 10.5,
            "bandwidth_bps": 40000.0,
            "protocol_distribution": {"TCP": 80, "UDP": 20},
            "top_talkers_src": [("10.0.0.1", 50), ("10.0.0.2", 30)],
            "top_talkers_dst": [("10.0.0.3", 60)],
        }
        anomalies = []

        user_prompt, system_prompt = builder.build_quick_prompt(flows, stats, anomalies)

        assert isinstance(user_prompt, str)
        assert isinstance(system_prompt, str)
        assert "100" in user_prompt  # total_packets
        assert "50000" in user_prompt  # total_bytes
        assert "10.5" in user_prompt  # duration
        assert "TCP" in user_prompt
        assert "10.0.0.1" in user_prompt
        assert len(system_prompt) > 50  # 系统提示词不能太短

    def test_build_quick_prompt_with_anomalies(self):
        builder = PromptBuilder()
        stats = {
            "total_packets": 10, "total_bytes": 1000,
            "total_flows": 1, "duration": 1.0, "bandwidth_bps": 8000,
            "protocol_distribution": {"TCP": 10},
            "top_talkers_src": [], "top_talkers_dst": [],
        }
        anomalies = [
            {"severity": "Warning", "type": "port_scan", "description": "疑似端口扫描: 目标 10.0.0.1"},
        ]

        user_prompt, _ = builder.build_quick_prompt([], stats, anomalies)
        assert "端口扫描" in user_prompt

    def test_build_quick_prompt_without_anomalies(self):
        builder = PromptBuilder()
        stats = {
            "total_packets": 0, "total_bytes": 0,
            "total_flows": 0, "duration": 0, "bandwidth_bps": 0,
            "protocol_distribution": {}, "top_talkers_src": [], "top_talkers_dst": [],
        }
        user_prompt, _ = builder.build_quick_prompt([], stats, [])
        assert "未检测到明显异常" in user_prompt

    def test_build_quick_prompt_service_classification(self):
        """HTTP 端口 80 应在流摘要中显示服务名"""
        builder = PromptBuilder()
        flows = [
            _make_flow("f1", "10.0.0.1", "93.184.216.34", 54321, 80, "TCP"),
        ]
        stats = {
            "total_packets": 1, "total_bytes": 100, "total_flows": 1,
            "duration": 0, "bandwidth_bps": 0,
            "protocol_distribution": {"TCP": 1},
            "top_talkers_src": [("10.0.0.1", 1)],
            "top_talkers_dst": [("93.184.216.34", 1)],
        }

        user_prompt, _ = builder.build_quick_prompt(flows, stats, [])
        assert "[HTTP]" in user_prompt  # 端口 80 识别为 HTTP

    def test_build_deep_layer1_prompt(self):
        builder = PromptBuilder()
        flows = [
            _make_flow("f1", "10.0.0.1", "10.0.0.2", 12345, 443, "TCP"),
        ]
        stats = {"key": "value"}
        anomalies = []

        user_prompt, system_prompt = builder.build_deep_layer1_prompt(
            flows, stats, anomalies, user_focus="TLS 流量"
        )

        assert "f1" in user_prompt
        assert "TLS 流量" in user_prompt
        assert isinstance(system_prompt, str)

    def test_build_deep_layer2_prompt(self):
        builder = PromptBuilder()
        flows = [
            _make_flow("f1", "10.0.0.1", "10.0.0.2", 12345, 443, "TCP"),
            _make_flow("f2", "10.0.0.3", "10.0.0.4", 80, 80, "TCP"),
        ]
        packets = [
            _make_pkt(i, "10.0.0.1", "10.0.0.2" if i % 2 else "10.0.0.3",
                       12345, 443, "TCP") for i in range(10)
        ]
        context = "可疑文件下载"

        # 只测试第一个 flow
        user_prompt, system_prompt = builder.build_deep_layer2_prompt(
            flows[0], packets, context
        )

        assert "f1" in user_prompt
        assert "10.0.0.1" in user_prompt
        assert "443" in user_prompt
        assert "可疑文件下载" in user_prompt
        assert isinstance(system_prompt, str)


class TestSelectRelevantPackets:

    def test_less_than_max(self):
        packets = [_make_pkt(i, "1.1.1.1", "2.2.2.2", 80, 443, "TCP") for i in range(5)]
        flow = _make_flow("f1", "1.1.1.1", "2.2.2.2", 80, 443, "TCP")
        selected = _select_relevant_packets(packets, flow, max_packets=20)
        assert len(selected) == 5

    def test_more_than_max(self):
        packets = [_make_pkt(i, "1.1.1.1", "2.2.2.2", 80, 443, "TCP") for i in range(100)]
        flow = _make_flow("f1", "1.1.1.1", "2.2.2.2", 80, 443, "TCP")
        selected = _select_relevant_packets(packets, flow, max_packets=20)
        assert len(selected) == 20
        # 前一半 + 后一半
        assert selected[0].index == 0
        assert selected[-1].index == 99
