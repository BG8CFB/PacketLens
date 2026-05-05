"""AnalysisWorker 测试 — 真实数据，无 mock

策略：
- 纯逻辑方法（_extract_suspicious_flows / _count_confirmed_issues /
  _build_layer2_context / _empty_result）直接调用验证。
- run() 错误路径通过空 api_key 触发 AIEngine 自身的 ValueError，
  验证 analysis_error 信号被正确发出（无需 mock）。
- 构造器参数默认值落到 AI_DEFAULTS。
"""

from __future__ import annotations

import time

import pytest
from PySide6.QtCore import QCoreApplication

from app.ai.ai_engine import AIEngine
from app.ai.analysis_worker import AnalysisWorker
from app.ai.prompt_builder import PromptBuilder
from app.ai.result_parser import ResultParser
from app.config.ai_defaults import AI_DEFAULTS
from app.models.analysis_result import AnalysisIssue, AnalysisResult
from app.models.flow_record import FlowRecord


@pytest.fixture(scope="module")
def qapp():
    app = QCoreApplication.instance()
    if app is None:
        app = QCoreApplication([])
    return app


def _make_flow(flow_id: str, src="10.0.0.1", dst="10.0.0.2",
               sport=12345, dport=80, proto="TCP") -> FlowRecord:
    return FlowRecord(
        flow_id=flow_id,
        src_ip=src,
        dst_ip=dst,
        src_port=sport,
        dst_port=dport,
        protocol=proto,
        packet_count=10,
        byte_count=1024,
        first_seen=1000.0,
        last_seen=1010.0,
    )


def _make_issue(severity: str, title: str, flows: list[str]) -> AnalysisIssue:
    return AnalysisIssue(
        severity=severity,
        category="Security",
        title=title,
        description="test",
        affected_flows=flows,
    )


@pytest.fixture
def worker_components():
    """创建 AnalysisWorker 依赖（PromptBuilder + ResultParser + 空 key 的 AIEngine）"""
    engine = AIEngine(
        provider_type="openai",
        api_key="",  # 空 key，触发 ValueError
        base_url="https://api.example.test/v1",
        model="test-model",
    )
    builder = PromptBuilder()
    parser = ResultParser()
    return engine, builder, parser


# ── 一、构造器参数 ──


class TestAnalysisWorkerConstruction:
    """构造器参数与默认值"""

    def test_defaults_fallback_to_ai_defaults(self, qapp, worker_components):
        """未传参时使用 AI_DEFAULTS"""
        engine, builder, parser = worker_components
        worker = AnalysisWorker(engine=engine, prompt_builder=builder, result_parser=parser)
        assert worker._temperature == AI_DEFAULTS["temperature"]
        assert worker._max_tokens == AI_DEFAULTS["max_tokens"]
        assert worker._max_concurrency == AI_DEFAULTS["max_concurrency"]
        assert worker._max_layer2_flows == AI_DEFAULTS["max_layer2_flows"]
        assert worker._mode == "quick"
        assert worker._flows == []
        assert worker._stats == {}
        assert worker._anomalies == []
        assert worker._packets == []

    def test_explicit_params_override_defaults(self, qapp, worker_components):
        """显式参数优先于 AI_DEFAULTS"""
        engine, builder, parser = worker_components
        worker = AnalysisWorker(
            engine=engine,
            prompt_builder=builder,
            result_parser=parser,
            mode="deep",
            temperature=0.5,
            max_tokens=1024,
            max_concurrency=2,
            max_layer2_flows=5,
        )
        assert worker._mode == "deep"
        assert worker._temperature == 0.5
        assert worker._max_tokens == 1024
        assert worker._max_concurrency == 2
        assert worker._max_layer2_flows == 5

    def test_zero_temperature_not_replaced_by_default(self, qapp, worker_components):
        """temperature=0.0 不应被默认值覆盖（is not None 检查）"""
        engine, builder, parser = worker_components
        worker = AnalysisWorker(
            engine=engine,
            prompt_builder=builder,
            result_parser=parser,
            temperature=0.0,
        )
        assert worker._temperature == 0.0


# ── 二、_extract_suspicious_flows ──


class TestExtractSuspiciousFlows:
    """从 Layer 1 结果中提取可疑流"""

    def test_returns_critical_and_warning_flows(self, qapp, worker_components):
        """提取 Critical 和 Warning 严重性的 affected_flows"""
        engine, builder, parser = worker_components
        flow_a = _make_flow("flow-A")
        flow_b = _make_flow("flow-B", dst="10.0.0.3")
        flow_c = _make_flow("flow-C", dst="10.0.0.4")
        worker = AnalysisWorker(
            engine=engine, prompt_builder=builder, result_parser=parser,
            flows=[flow_a, flow_b, flow_c],
        )
        layer1 = AnalysisResult(
            issues=[
                _make_issue("Critical", "扫描", ["flow-A"]),
                _make_issue("Warning", "异常", ["flow-B"]),
                _make_issue("Info", "正常", ["flow-C"]),
            ],
        )
        suspicious = worker._extract_suspicious_flows(layer1)
        ids = {f.flow_id for f in suspicious}
        assert ids == {"flow-A", "flow-B"}

    def test_returns_empty_when_no_issues(self, qapp, worker_components):
        """无 issues 时返回空列表"""
        engine, builder, parser = worker_components
        worker = AnalysisWorker(
            engine=engine, prompt_builder=builder, result_parser=parser,
            flows=[_make_flow("flow-A")],
        )
        layer1 = AnalysisResult(issues=[])
        assert worker._extract_suspicious_flows(layer1) == []

    def test_returns_empty_when_no_flows(self, qapp, worker_components):
        """无 flows 时返回空列表"""
        engine, builder, parser = worker_components
        worker = AnalysisWorker(
            engine=engine, prompt_builder=builder, result_parser=parser,
            flows=[],
        )
        layer1 = AnalysisResult(
            issues=[_make_issue("Critical", "扫描", ["flow-A"])],
        )
        assert worker._extract_suspicious_flows(layer1) == []

    def test_unknown_flow_id_skipped(self, qapp, worker_components):
        """affected_flows 中不存在的 flow_id 被跳过"""
        engine, builder, parser = worker_components
        worker = AnalysisWorker(
            engine=engine, prompt_builder=builder, result_parser=parser,
            flows=[_make_flow("flow-A")],
        )
        layer1 = AnalysisResult(
            issues=[_make_issue("Critical", "扫描", ["flow-A", "flow-X"])],
        )
        suspicious = worker._extract_suspicious_flows(layer1)
        assert len(suspicious) == 1
        assert suspicious[0].flow_id == "flow-A"

    def test_fallback_to_anomalies_when_no_ai_marks(self, qapp, worker_components):
        """AI 没标记任何流时，回退使用 anomalies"""
        engine, builder, parser = worker_components
        flow_a = _make_flow("flow-A")
        flow_b = _make_flow("flow-B", dst="10.0.0.3")
        worker = AnalysisWorker(
            engine=engine, prompt_builder=builder, result_parser=parser,
            flows=[flow_a, flow_b],
            anomalies=[
                {"affected_flows": ["flow-A"]},
                {"affected_flows": ["flow-B"]},
            ],
        )
        # AI 标记的 issues 不指向我们已知的流
        layer1 = AnalysisResult(
            issues=[_make_issue("Critical", "未知扫描", ["flow-Z"])],
        )
        suspicious = worker._extract_suspicious_flows(layer1)
        ids = {f.flow_id for f in suspicious}
        assert ids == {"flow-A", "flow-B"}


# ── 三、_count_confirmed_issues ──


class TestCountConfirmedIssues:
    """确认异常流数量"""

    def test_unique_flow_count(self, qapp):
        """同一流出现在多个 issue 中只计一次"""
        layer1 = AnalysisResult(
            issues=[
                _make_issue("Critical", "扫描", ["flow-A"]),
                _make_issue("Warning", "异常", ["flow-A", "flow-B"]),
            ],
        )
        assert AnalysisWorker._count_confirmed_issues(layer1) == 2

    def test_info_severity_excluded(self, qapp):
        """Info 严重性不计入"""
        layer1 = AnalysisResult(
            issues=[
                _make_issue("Critical", "扫描", ["flow-A"]),
                _make_issue("Info", "提示", ["flow-B", "flow-C"]),
            ],
        )
        assert AnalysisWorker._count_confirmed_issues(layer1) == 1

    def test_zero_when_no_issues(self, qapp):
        """无 issue 时返回 0"""
        layer1 = AnalysisResult(issues=[])
        assert AnalysisWorker._count_confirmed_issues(layer1) == 0


# ── 四、_build_layer2_context ──


class TestBuildLayer2Context:
    """Layer 2 上下文构建"""

    def test_includes_summary(self, qapp):
        """包含 Layer 1 摘要"""
        layer1 = AnalysisResult(summary="检测到端口扫描行为", issues=[])
        ctx = AnalysisWorker._build_layer2_context(layer1, "")
        assert "检测到端口扫描行为" in ctx

    def test_severity_order_critical_first(self, qapp):
        """issue 按严重性排序，Critical 优先"""
        layer1 = AnalysisResult(
            issues=[
                _make_issue("Info", "B-info", ["flow-1"]),
                _make_issue("Critical", "A-critical", ["flow-2"]),
                _make_issue("Warning", "C-warning", ["flow-3"]),
            ],
        )
        ctx = AnalysisWorker._build_layer2_context(layer1, "")
        # Critical 应在 Warning 之前，Warning 在 Info 之前
        c_pos = ctx.find("A-critical")
        w_pos = ctx.find("C-warning")
        i_pos = ctx.find("B-info")
        assert c_pos > 0
        assert w_pos > c_pos
        assert i_pos > w_pos

    def test_long_affected_flows_truncated(self, qapp):
        """affected_flows 超过 5 个时显示总数"""
        layer1 = AnalysisResult(
            issues=[
                _make_issue("Critical", "海量扫描",
                            [f"flow-{i}" for i in range(1, 11)]),
            ],
        )
        ctx = AnalysisWorker._build_layer2_context(layer1, "")
        assert "等10个" in ctx

    def test_max_chars_enforced(self, qapp):
        """生成的上下文长度不超过 max_chars"""
        layer1 = AnalysisResult(
            summary="x" * 5000,
            issues=[],
        )
        ctx = AnalysisWorker._build_layer2_context(layer1, "y" * 5000, max_chars=3000)
        assert len(ctx) <= 3000

    def test_appends_layer1_text_when_room_remains(self, qapp):
        """若剩余空间足够，附加 Layer 1 原始文本片段"""
        layer1 = AnalysisResult(summary="短摘要", issues=[])
        layer1_text = "RAW_LAYER1_TEXT"
        ctx = AnalysisWorker._build_layer2_context(layer1, layer1_text, max_chars=3000)
        assert "RAW_LAYER1_TEXT" in ctx


# ── 五、_empty_result ──


class TestEmptyResult:
    """取消时的空结果"""

    def test_empty_result_basic_fields(self, qapp):
        """session_id、mode、summary 字段正确"""
        start = time.time() - 1.5
        result = AnalysisWorker._empty_result("sess-1", "deep", start)
        assert result.session_id == "sess-1"
        assert result.analysis_mode == "deep"
        assert result.summary == "分析已被取消"
        assert result.issues == []
        assert result.duration_seconds >= 1.0


# ── 六、run() 错误路径（无 mock，真实触发 ValueError）──


class TestAnalysisWorkerErrorEmit:
    """空 api_key 触发 AIEngine.analyze_stream 抛 ValueError，测试 analysis_error 信号"""

    def test_run_emits_error_when_api_key_missing(self, qapp, worker_components):
        """quick 模式下 api_key 为空，应触发 analysis_error 信号"""
        engine, builder, parser = worker_components
        worker = AnalysisWorker(
            engine=engine,
            prompt_builder=builder,
            result_parser=parser,
            mode="quick",
            flows=[_make_flow("flow-A")],
            stats={"total_packets": 1, "total_bytes": 64},
            anomalies=[],
            packets=[],
        )

        captured = {"error": None, "completed": None}
        worker.analysis_error.connect(lambda msg: captured.update(error=msg))
        worker.analysis_completed.connect(lambda r: captured.update(completed=r))

        # 在主线程直接调用 run()，避免起 QThread 带来的事件循环依赖
        worker.run()

        assert captured["error"] is not None
        assert captured["completed"] is None
        # ValueError 路径走 ai 配置错误分支，消息应包含 "API Key"
        assert "API Key" in captured["error"]
