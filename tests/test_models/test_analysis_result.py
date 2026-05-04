"""AnalysisResult / AnalysisIssue 模型测试"""

from datetime import datetime
from app.models.analysis_result import AnalysisIssue, AnalysisResult


class TestAnalysisIssue:

    def test_basic(self):
        issue = AnalysisIssue(
            severity="Critical", category="Security",
            title="端口扫描", description="检测到异常扫描行为",
            recommendation="检查防火墙规则",
        )
        assert issue.severity == "Critical"
        assert issue.category == "Security"
        assert issue.title == "端口扫描"
        assert issue.description == "检测到异常扫描行为"
        assert issue.recommendation == "检查防火墙规则"
        assert issue.affected_flows == []
        assert issue.raw_detail is None

    def test_with_affected_flows(self):
        issue = AnalysisIssue(
            severity="Warning", category="Anomaly",
            title="test", description="desc",
            affected_flows=["flow1", "flow2"],
        )
        assert len(issue.affected_flows) == 2
        assert "flow1" in issue.affected_flows


class TestAnalysisResult:

    def test_empty_result(self):
        result = AnalysisResult()
        assert result.session_id == ""
        assert result.analysis_mode == "quick"
        assert result.summary == ""
        assert result.issues == []
        assert result.critical_count == 0
        assert result.warning_count == 0
        assert result.info_count == 0
        assert result.has_critical is False
        assert result.has_warnings is False

    def test_counters(self):
        result = AnalysisResult(
            session_id="s1",
            analysis_mode="deep",
            issues=[
                AnalysisIssue(severity="Critical", category="S", title="c1", description="d1"),
                AnalysisIssue(severity="Critical", category="S", title="c2", description="d2"),
                AnalysisIssue(severity="Warning", category="P", title="w1", description="d3"),
                AnalysisIssue(severity="Info", category="G", title="i1", description="d4"),
                AnalysisIssue(severity="Normal", category="G", title="n1", description="d5"),
            ],
        )
        assert result.critical_count == 2
        assert result.warning_count == 1
        assert result.info_count == 1
        assert result.has_critical is True
        assert result.has_warnings is True

    def test_timestamp(self):
        now = datetime(2024, 1, 15, 10, 30, 0)
        result = AnalysisResult(timestamp=now)
        assert result.timestamp == now
