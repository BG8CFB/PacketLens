"""端到端集成测试 — 拉通完整数据链路

测试场景：
1. 抓包链路：网卡检测 → 抓包 → 模型更新 → 流聚合 → PCAP写入 → 读回验证
2. 预处理链路：抓包 → 流聚合 → 统计计算 → 异常检测
3. AI 链路：预处理结果 → 提示词构建 → AI 分析 → 结果解析 → 报告导出
4. 存储链路：会话保存 → 历史查询 → 报告导出 → 文件验证
"""

import json
import os
import queue
import time
from datetime import datetime
from pathlib import Path

import pytest
from scapy.all import Ether, IP, TCP, UDP, ICMP, send

from app.capture.bpf_validator import validate_bpf
from app.capture.nic_detector import get_default_interface, list_interfaces
from app.capture.pcap_writer import PCAPWriter
from app.capture.sniff_thread import SniffThread
from app.models.packet_record import PacketRecord
from app.models.flow_record import FlowRecord
from app.models.analysis_result import AnalysisResult, AnalysisIssue
from app.preprocessing.flow_aggregator import FlowAggregator
from app.preprocessing.stats_computer import StatsComputer
from app.preprocessing.anomaly_marker import AnomalyMarker
from app.ai.ai_engine import AIEngine
from app.ai.prompt_builder import PromptBuilder
from app.ai.result_parser import ResultParser
from app.storage.history_manager import HistoryManager
from app.storage.report_exporter import ReportExporter


# ═══════════════════════════════════════════
# 链路一：抓包全流程
# ═══════════════════════════════════════════

class TestCapturePipeline:
    """真实抓包 → 模型 → 流聚合 → PCAP 完整链路"""

    LOOPBACK = "\\Device\\NPF_Loopback"

    def test_nic_to_sniff_to_model_and_pcap(self, tmp_path):
        """网卡检测 → BPF 验证 → 抓包 → 模型更新 → 流聚合 → PCAP 写入 → 读回"""
        # 1. 网卡检测
        nics = list_interfaces()
        assert len(nics) > 0

        default_nic = get_default_interface()
        assert default_nic is not None

        # 2. BPF 验证
        ok, _ = validate_bpf("")
        assert ok is True

        # 3. 启动抓包 + PCAP 写入
        capture_q = queue.Queue()
        pcap_q = queue.Queue()
        pcap_file = tmp_path / "integration.pcap"

        writer = PCAPWriter(pcap_file, pcap_q)
        writer.start()

        thread = SniffThread(
            iface=self.LOOPBACK,
            capture_queue=capture_q,
            pcap_queue=pcap_q,
        )
        thread.start()
        time.sleep(0.3)

        # 4. 发送真实 ICMP + TCP 包
        try:
            from scapy.all import send as scapy_send
            # ICMP
            scapy_send(IP(src="127.0.0.1", dst="127.0.0.1") / ICMP(), verbose=0, count=3)
            # TCP SYN to localhost:80
            scapy_send(
                IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=45000, dport=80, flags="S"),
                verbose=0, count=2,
            )
        except Exception:
            pass

        time.sleep(1)

        # 5. 停止抓包
        thread.stop(timeout=5)
        assert thread.packet_count > 0

        # 6. 从 capture_queue 收集 PacketRecord
        captured = []
        while not capture_q.empty():
            captured.append(capture_q.get_nowait())
        assert len(captured) > 0
        assert all(isinstance(p, PacketRecord) for p in captured)

        # 7. 流聚合
        aggregator = FlowAggregator()
        aggregator.update_batch(captured)
        flows = aggregator.get_flows()
        assert len(flows) > 0

        # 验证流中有 ICMP 或 TCP
        flow_protocols = {f.protocol for f in flows}
        # 应该包含 ICMP 或 TCP（回环接口可能看到双向包）
        assert flow_protocols.intersection({"ICMP", "TCP"}) != set(), \
            f"期望包含 ICMP 或 TCP，实际: {flow_protocols}"

        # 8. 停止 PCAP 写入并验证
        writer.stop(timeout=10)
        assert pcap_file.exists()
        assert pcap_file.stat().st_size > 0
        assert writer.total_written > 0

        from scapy.all import rdpcap
        read_pkts = rdpcap(str(pcap_file))
        assert len(read_pkts) > 0

    def test_bpf_filter_affects_capture_pipeline(self, tmp_path):
        """BPF 过滤器在完整链路中生效"""
        capture_q = queue.Queue()
        pcap_q = queue.Queue()

        # 只允许 UDP
        ok, _ = validate_bpf("udp")
        assert ok is True

        thread = SniffThread(
            iface=self.LOOPBACK,
            capture_queue=capture_q,
            pcap_queue=pcap_q,
            bpf_filter="udp",
        )
        thread.start()
        time.sleep(0.3)

        # 发送 ICMP（应被过滤）
        try:
            from scapy.all import send as scapy_send
            scapy_send(IP(src="127.0.0.1", dst="127.0.0.1") / ICMP(), verbose=0, count=5)
        except Exception:
            pass

        time.sleep(1)
        thread.stop(timeout=5)

        captured = []
        while not capture_q.empty():
            captured.append(capture_q.get_nowait())

        # BPF=udp 应过滤掉 ICMP
        for pkt in captured:
            assert pkt.protocol != "ICMP", f"UDP 过滤器不应捕获 ICMP 包"


# ═══════════════════════════════════════════
# 链路二：预处理链路
# ═══════════════════════════════════════════

class TestPreprocessingPipeline:
    """抓包数据 → 流聚合 → 统计 → 异常检测 完整链路"""

    def _make_realistic_packets(self):
        """构造真实场景的包数据（端口扫描 + 正常流量）"""
        packets = []
        ts = time.time()

        # 正常 HTTP 流量
        for i in range(20):
            packets.append(PacketRecord(
                index=i + 1, timestamp=ts + i * 0.01,
                src_ip="192.168.1.100", dst_ip="10.0.0.1",
                src_port=50000 + i, dst_port=80,
                protocol="TCP", length=200,
                info="S seq=1000", raw_bytes=b"\x00" * 200,
                flags="S",
            ))

        # DNS 查询
        for i in range(10):
            packets.append(PacketRecord(
                index=20 + i + 1, timestamp=ts + 20 * 0.01 + i * 0.01,
                src_ip="192.168.1.100", dst_ip="8.8.8.8",
                src_port=55000, dst_port=53,
                protocol="UDP", length=80,
                info="len=48", raw_bytes=b"\x00" * 80,
            ))

        # 端口扫描（同 IP 不同端口）
        for i in range(30):
            packets.append(PacketRecord(
                index=30 + i + 1, timestamp=ts + 30 * 0.01 + i * 0.005,
                src_ip="192.168.1.200", dst_ip="10.0.0.1",
                src_port=60000, dst_port=44000 + i,
                protocol="TCP", length=60,
                info="S seq=0", raw_bytes=b"\x00" * 60,
                flags="S",
            ))

        return packets

    def test_full_preprocessing_chain(self):
        """完整预处理链路：流聚合 → 统计 → 异常检测"""
        packets = self._make_realistic_packets()

        # 1. 流聚合
        aggregator = FlowAggregator()
        aggregator.update_batch(packets)
        flows = aggregator.get_flows()

        # 应有：HTTP流(20包)、DNS流(10包)、30个端口扫描流(各1包) = 至少 32 条流
        assert len(flows) >= 30, f"期望至少30条流，实际 {len(flows)} 条"

        # HTTP 流应包数最多
        assert flows[0].packet_count >= 10, "最多包的流应有较多包"

        # 2. 统计计算
        computer = StatsComputer()
        stats = computer.compute(flows, packets)

        assert stats["total_packets"] == len(packets)
        assert stats["total_bytes"] > 0
        assert stats["total_flows"] == len(flows)
        assert "TCP" in stats["protocol_distribution"]
        assert "UDP" in stats["protocol_distribution"]
        assert stats["duration"] > 0

        # 3. 异常检测
        marker = AnomalyMarker()
        anomalies = marker.mark(flows)

        # 端口扫描应被检测到
        assert len(anomalies) > 0, "端口扫描未被检测到"
        anomaly_types = {a["type"] for a in anomalies}
        assert "port_scan" in anomaly_types, f"期望检测到 port_scan，实际: {anomaly_types}"

        # 4. 验证 stats 结构完整
        expected_keys = {
            "protocol_distribution", "top_talkers_src", "top_talkers_dst",
            "total_packets", "total_bytes", "total_flows",
            "avg_packet_size", "duration", "bandwidth_bps",
        }
        assert expected_keys.issubset(stats.keys()), \
            f"stats 缺少键: {expected_keys - stats.keys()}"

    def test_preprocessing_with_normal_traffic_only(self):
        """正常流量不触发异常检测"""
        packets = []
        ts = time.time()
        for i in range(50):
            packets.append(PacketRecord(
                index=i + 1, timestamp=ts + i * 0.01,
                src_ip="192.168.1.100", dst_ip="10.0.0.1",
                src_port=50000, dst_port=443,
                protocol="TCP", length=200,
                info="S seq=1000", raw_bytes=b"\x00" * 200,
                flags="S",
            ))

        aggregator = FlowAggregator()
        aggregator.update_batch(packets)
        flows = aggregator.get_flows()

        marker = AnomalyMarker()
        anomalies = marker.mark(flows)

        # 正常单流不应有端口扫描异常
        scan_anomalies = [a for a in anomalies if a["type"] == "port_scan"]
        assert len(scan_anomalies) == 0, f"正常流量不应触发端口扫描告警: {scan_anomalies}"


# ═══════════════════════════════════════════
# 链路三：AI 分析全链路
# ═══════════════════════════════════════════

class TestAIAnalysisPipeline:
    """预处理结果 → 提示词构建 → AI 调用 → 结果解析 → 报告导出"""

    def test_prompt_build_to_ai_to_report(self):
        """完整链路：提示词构建 → AI 分析 → JSON 解析 → 报告生成"""
        # 1. 构造预处理数据
        packets = []
        ts = time.time()
        for i in range(30):
            packets.append(PacketRecord(
                index=i + 1, timestamp=ts + i * 0.01,
                src_ip="192.168.1.100", dst_ip="10.0.0.1",
                src_port=50000 + i, dst_port=80 + (i % 5),
                protocol="TCP", length=150,
                info="S seq=1000", raw_bytes=b"\x00" * 150,
                flags="S",
            ))

        aggregator = FlowAggregator()
        aggregator.update_batch(packets)
        flows = aggregator.get_flows()

        computer = StatsComputer()
        stats = computer.compute(flows, packets)

        marker = AnomalyMarker()
        anomalies = marker.mark(flows)

        # 2. 构建提示词
        builder = PromptBuilder()
        user_prompt, system_prompt = builder.build_layer1_prompt(flows, packets, stats, anomalies)

        assert len(user_prompt) > 100, "提示词应包含实质性内容"
        assert "30" in user_prompt, "提示词应包含总包数"
        assert "TCP" in user_prompt, "提示词应包含协议信息"

        # 3. AI 分析（真实调用）
        from app.storage.config_manager import ConfigManager
        cfg = ConfigManager().get_ai_config()
        engine = AIEngine(
            provider_type=cfg.get("provider_type", "openai"),
            api_key=cfg["api_key"],
            base_url=cfg["base_url"],
            model=cfg["model"],
        )
        ok, msg = engine.test_connection()
        assert ok is True, f"AI 连接失败: {msg}"

        response = engine.analyze(
            prompt=user_prompt,
            system_prompt=system_prompt,
            max_tokens=500,
        )
        if len(response) == 0:
            pytest.skip("AI API 返回空响应，跳过后续断言（外部服务波动）")

        # 4. 结果解析
        parser = ResultParser()
        result = parser.parse(response, session_id="integ_test", mode="quick")

        assert isinstance(result, AnalysisResult)
        assert result.session_id == "integ_test"
        assert result.analysis_mode == "quick"

        # 5. 报告导出
        session_data = {
            "packet_count": stats["total_packets"],
            "flow_count": stats["total_flows"],
            "interface": "Loopback",
            "duration": stats["duration"],
        }
        exporter = ReportExporter()

        md = exporter.export_markdown(session_data, result)
        assert "PacketLens" in md
        assert "30" in md

        html = exporter.export_html(session_data, result)
        assert "<!DOCTYPE html>" in html

        json_str = exporter.export_json(session_data, result)
        data = json.loads(json_str)
        assert data["session"]["packet_count"] == 30


# ═══════════════════════════════════════════
# 链路四：存储全链路
# ═══════════════════════════════════════════

class TestStoragePipeline:
    """历史管理 + 报告导出完整链路"""

    def test_session_lifecycle(self, tmp_path):
        """完整生命周期：创建 → 保存 → 查询 → 导出报告 → 删除"""
        db_path = tmp_path / "lifecycle.db"
        history = HistoryManager(db_path=db_path)

        # 1. 创建并保存会话
        session_data = {
            "id": "sess_001",
            "start_time": datetime.now().isoformat(),
            "end_time": datetime.now().isoformat(),
            "interface": "以太网",
            "bpf_filter": "tcp",
            "mode": "quick",
            "packet_count": 150,
            "flow_count": 12,
            "protocol_dist": '{"TCP": 120, "UDP": 30}',
            "pcap_path": "captures/sess_001.pcap",
            "report_path": "reports/sess_001.md",
            "notes": "集成测试会话",
        }
        history.save_session(session_data)

        # 2. 查询验证
        loaded = history.get_session("sess_001")
        assert loaded is not None
        assert loaded["packet_count"] == 150
        assert loaded["flow_count"] == 12
        assert loaded["mode"] == "quick"

        # 3. 列出会话
        sessions = history.list_sessions()
        assert len(sessions) == 1
        assert sessions[0]["id"] == "sess_001"

        # 4. 导出报告
        result = AnalysisResult(
            session_id="sess_001",
            analysis_mode="quick",
            timestamp=datetime.now(),
            summary="检测到端口扫描行为",
            overall_assessment="有风险",
            issues=[
                AnalysisIssue(
                    severity="Critical", category="Security",
                    title="端口扫描", description="检测到端口扫描行为",
                    recommendation="检查防火墙规则",
                    affected_flows=["f1"],
                ),
                AnalysisIssue(
                    severity="Warning", category="Performance",
                    title="高延迟", description="TCP 连接延迟超过阈值",
                    recommendation="检查网络链路",
                ),
            ],
        )
        exporter = ReportExporter()

        # 5. 保存报告到文件
        report_dir = tmp_path / "reports"
        report_dir.mkdir()

        md_path = report_dir / "sess_001.md"
        md_content = exporter.export_markdown(session_data, result)
        exporter.save_report(md_content, md_path)
        assert md_path.exists()

        html_path = report_dir / "sess_001.html"
        html_content = exporter.export_html(session_data, result)
        exporter.save_report(html_content, html_path)
        assert html_path.exists()

        json_path = report_dir / "sess_001.json"
        json_content = exporter.export_json(session_data, result)
        exporter.save_report(json_content, json_path)
        assert json_path.exists()

        # 6. 验证报告内容完整性
        assert "端口扫描" in md_path.read_text(encoding="utf-8")
        assert "Critical" in md_path.read_text(encoding="utf-8")

        json_data = json.loads(json_path.read_text(encoding="utf-8"))
        assert len(json_data["analysis"]["issues"]) == 2

        # 7. 更新会话（添加报告路径后）
        session_data["report_path"] = str(md_path)
        session_data["packet_count"] = 200
        history.save_session(session_data)

        updated = history.get_session("sess_001")
        assert updated["packet_count"] == 200

        # 8. 删除会话
        history.delete_session("sess_001")
        assert history.get_session("sess_001") is None

        # 9. 多会话场景
        for i in range(5):
            history.save_session({
                "id": f"sess_{i:03d}",
                "start_time": datetime.now().isoformat(),
                "interface": "以太网",
                "mode": "quick",
                "packet_count": 50 + i * 10,
            })

        all_sessions = history.list_sessions()
        assert len(all_sessions) == 5

        # 分页
        page1 = history.list_sessions(limit=2, offset=0)
        page2 = history.list_sessions(limit=2, offset=2)
        assert len(page1) == 2
        assert len(page2) == 2
        ids1 = {s["id"] for s in page1}
        ids2 = {s["id"] for s in page2}
        assert ids1.isdisjoint(ids2)

        history.close()


# ═══════════════════════════════════════════
# 链路五：Qt 模型 + 数据流集成
# ═══════════════════════════════════════════

class TestQtModelIntegration:
    """PacketTableModel 与预处理组件集成"""

    def test_model_to_preprocessing_chain(self, qapp):
        """模型数据直接输入预处理链路"""
        from PySide6.QtWidgets import QApplication
        from app.ui.packet_table_model import PacketTableModel

        model = PacketTableModel()

        # 添加混合协议包
        packets = []
        ts = time.time()
        for i in range(100):
            proto = ["TCP", "UDP", "ICMP"][i % 3]
            port = [80, 53, None][i % 3]
            packets.append(PacketRecord(
                index=i + 1, timestamp=ts + i * 0.001,
                src_ip=f"10.0.0.{(i % 5) + 1}", dst_ip=f"10.0.0.{(i % 3) + 10}",
                src_port=40000 + i, dst_port=port or 0,
                protocol=proto, length=64 + i,
                info=f"test packet {i}", raw_bytes=b"\x00" * (64 + i),
            ))

        model.add_packets(packets)
        assert model.rowCount() == 100

        # 从模型取数据做预处理
        all_pkts = model.all_packets()
        assert len(all_pkts) == 100

        # 流聚合
        aggregator = FlowAggregator()
        aggregator.update_batch(all_pkts)
        flows = aggregator.get_flows()
        assert len(flows) > 0

        # 统计
        computer = StatsComputer()
        stats = computer.compute(flows, all_pkts)
        assert stats["total_packets"] == 100
        assert len(stats["protocol_distribution"]) == 3

        # 清空模型后预处理数据不受影响
        model.clear()
        assert model.rowCount() == 0
        assert len(flows) > 0  # 预处理结果独立于模型


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app
