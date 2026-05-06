"""PromptBuilder 单元测试"""

import logging

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


class TestLayer1Prompt:

    def test_build_layer1_prompt_basic(self):
        builder = PromptBuilder()
        flows = [
            _make_flow("abc123", "10.0.0.1", "10.0.0.2", 12345, 80, "TCP"),
        ]
        packets = [
            _make_pkt(0, "10.0.0.1", "10.0.0.2", 12345, 80, "TCP"),
            _make_pkt(1, "10.0.0.2", "10.0.0.1", 80, 12345, "TCP"),
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

        user_prompt, system_prompt = builder.build_layer1_prompt(flows, packets, stats, anomalies)

        assert isinstance(user_prompt, str)
        assert isinstance(system_prompt, str)
        assert "100" in user_prompt  # total_packets
        assert "50000" in user_prompt  # total_bytes
        assert "TCP" in user_prompt
        assert "10.0.0.1" in user_prompt
        assert "abc123" in user_prompt  # flow_id
        assert len(system_prompt) > 50

    def test_build_layer1_prompt_with_anomalies(self):
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

        user_prompt, _ = builder.build_layer1_prompt([], [], stats, anomalies)
        assert "端口扫描" in user_prompt

    def test_build_layer1_prompt_without_anomalies(self):
        builder = PromptBuilder()
        stats = {
            "total_packets": 0, "total_bytes": 0,
            "total_flows": 0, "duration": 0, "bandwidth_bps": 0,
            "protocol_distribution": {}, "top_talkers_src": [], "top_talkers_dst": [],
        }
        user_prompt, _ = builder.build_layer1_prompt([], [], stats, [])
        assert "未检测到明显异常" in user_prompt

    def test_build_layer1_prompt_all_flows_included(self):
        """全部流都应包含在 prompt 中"""
        builder = PromptBuilder()
        flows = [
            _make_flow(f"f{i}", "10.0.0.1", f"10.0.0.{i}", 12345, 80, "TCP")
            for i in range(20)
        ]
        stats = {
            "total_packets": 100, "total_bytes": 50000,
            "total_flows": 20, "duration": 10, "bandwidth_bps": 40000,
            "protocol_distribution": {"TCP": 100},
            "top_talkers_src": [], "top_talkers_dst": [],
        }
        user_prompt, _ = builder.build_layer1_prompt(flows, [], stats, [])
        for i in range(20):
            assert f"f{i}" in user_prompt, f"流 f{i} 未出现在 prompt 中"

    def test_build_layer1_prompt_packets_per_flow(self):
        """每条流应包含采样包"""
        builder = PromptBuilder()
        flow = _make_flow("f1", "10.0.0.1", "10.0.0.2", 12345, 80, "TCP")
        packets = [
            _make_pkt(i, "10.0.0.1", "10.0.0.2", 12345, 80, "TCP")
            for i in range(10)
        ]
        stats = {
            "total_packets": 10, "total_bytes": 1000,
            "total_flows": 1, "duration": 1, "bandwidth_bps": 8000,
            "protocol_distribution": {"TCP": 10},
            "top_talkers_src": [], "top_talkers_dst": [],
        }
        user_prompt, _ = builder.build_layer1_prompt([flow], packets, stats, [])
        # 应包含包数据（至少有 #0）
        assert "#0" in user_prompt


class TestLayer2Prompt:

    def test_build_layer2_prompt(self):
        builder = PromptBuilder()
        flow = _make_flow("f1", "10.0.0.1", "10.0.0.2", 12345, 443, "TCP")
        packets = [
            _make_pkt(i, "10.0.0.1", "10.0.0.2", 12345, 443, "TCP")
            for i in range(10)
        ]
        context = "可疑 TLS 流量"

        user_prompt, system_prompt = builder.build_layer2_prompt(
            flow, packets, context,
        )

        assert "f1" in user_prompt
        assert "10.0.0.1" in user_prompt
        assert "443" in user_prompt
        assert "可疑 TLS 流量" in user_prompt
        assert isinstance(system_prompt, str)


class TestLayer3Prompt:

    def test_build_layer3_prompt(self):
        builder = PromptBuilder()
        stats = {
            "total_packets": 100, "total_flows": 10,
        }

        user_prompt, system_prompt = builder.build_layer3_prompt(
            layer1_raw="Layer1 分析结果",
            layer2_results=["流A诊断", "流B诊断"],
            stats=stats,
            suspicious_flow_count=3,
            confirmed_flow_count=1,
        )

        assert "Layer1 分析结果" in user_prompt
        assert "流A诊断" in user_prompt
        assert "100" in user_prompt
        assert isinstance(system_prompt, str)


class TestSelectRelevantPackets:

    def test_less_than_max(self):
        packets = [_make_pkt(i, "1.1.1.1", "2.2.2.2", 80, 443, "TCP") for i in range(5)]
        flow = _make_flow("f1", "1.1.1.1", "2.2.2.2", 80, 443, "TCP")
        selected = _select_relevant_packets(packets, flow, max_packets=20)
        assert len(selected) == 5

    def test_sampling_strategy(self):
        """采样策略：前2 + 中间均匀 + 后2"""
        packets = [_make_pkt(i, "1.1.1.1", "2.2.2.2", 80, 443, "TCP") for i in range(100)]
        flow = _make_flow("f1", "1.1.1.1", "2.2.2.2", 80, 443, "TCP")
        selected = _select_relevant_packets(packets, flow, max_packets=5)
        assert len(selected) == 5
        assert selected[0].index == 0   # 前部
        assert selected[-1].index == 99  # 后部

    def test_no_matching_packets(self):
        packets = [_make_pkt(i, "3.3.3.3", "4.4.4.4", 80, 80, "UDP") for i in range(10)]
        flow = _make_flow("f1", "1.1.1.1", "2.2.2.2", 80, 443, "TCP")
        selected = _select_relevant_packets(packets, flow, max_packets=5)
        assert len(selected) == 0


class TestPromptBuilderMaxInputChars:
    """max_input_chars 相关功能测试"""

    def test_default_max_input_chars(self):
        """默认应使用 AI_DEFAULTS 中的 max_input_chars"""
        builder = PromptBuilder()
        assert builder._max_input_chars > 0

    def test_custom_max_input_chars(self):
        """自定义 max_input_chars 应生效"""
        builder = PromptBuilder(max_input_chars=5000)
        assert builder._max_input_chars == 5000

    def test_layer3_dynamic_truncation(self):
        """Layer 3 截断长度应基于 max_input_chars 动态计算"""
        builder = PromptBuilder(max_input_chars=10000)
        stats = {"total_packets": 100, "total_flows": 10}
        long_layer1 = "A" * 20000
        long_layer2 = ["B" * 20000]

        user_prompt, _ = builder.build_layer3_prompt(
            layer1_raw=long_layer1,
            layer2_results=long_layer2,
            stats=stats,
            suspicious_flow_count=1,
            confirmed_flow_count=0,
        )

        # 验证 Layer1 结果被截断到约 40%（10000 * 0.4 = 4000 字符）
        assert "A" * 4000 in user_prompt
        assert "A" * 4001 not in user_prompt

    def test_layer1_length_warning_on_oversized(self, caplog):
        """超长 Layer1 prompt 应记录警告"""
        builder = PromptBuilder(max_input_chars=100)
        flows = [
            _make_flow(f"f{i}", "10.0.0.1", f"10.0.0.{i}", 12345, 80, "TCP")
            for i in range(50)
        ]
        stats = {
            "total_packets": 1000, "total_bytes": 500000,
            "total_flows": 50, "duration": 10, "bandwidth_bps": 400000,
            "protocol_distribution": {"TCP": 1000},
            "top_talkers_src": [], "top_talkers_dst": [],
        }

        with caplog.at_level(logging.WARNING):
            user_prompt, _ = builder.build_layer1_prompt(flows, [], stats, [])

        # prompt 应被截断到预算内
        assert any("截断" in r.message or "超过安全上限" in r.message for r in caplog.records)


class TestFormatFlowFlagsOrder:
    """flags_set 排序一致性测试"""

    def test_flags_output_is_sorted(self):
        """flags_set 输出应始终按字典序排列"""
        flow = FlowRecord(
            flow_id="f1", src_ip="1.1.1.1", dst_ip="2.2.2.2",
            src_port=80, dst_port=443, protocol="TCP",
            flags_set={"SYN", "ACK", "FIN", "PSH"},
        )
        builder = PromptBuilder()
        from app.ai.prompt_builder import _format_flow_with_packets
        result = _format_flow_with_packets(flow, [], 5)
        # flags 应按排序顺序出现：ACK,FIN,PSH,SYN
        assert "flags=ACK,FIN,PSH,SYN" in result
