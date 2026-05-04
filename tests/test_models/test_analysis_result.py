"""AnalysisResult / AnalysisIssue 模型测试"""

from datetime import datetime, timezone
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
        now = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        result = AnalysisResult(timestamp=now)
        assert result.timestamp == now

    # --- to_dict / from_dict 测试 ---

    def test_to_dict_basic(self):
        now = datetime(2024, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
        result = AnalysisResult(
            session_id="sess1",
            analysis_mode="deep",
            timestamp=now,
            summary="测试摘要",
            issues=[
                AnalysisIssue(
                    severity="Critical", category="Security",
                    title="发现问题", description="描述内容",
                    affected_flows=["f1", "f2"],
                    recommendation="修复",
                ),
            ],
            protocol_insights={"tcp": "正常"},
            overall_assessment="良好",
            raw_ai_response="raw json",
            token_usage={"prompt": 100, "completion": 50},
            duration_seconds=2.5,
        )
        d = result.to_dict()
        assert d["session_id"] == "sess1"
        assert d["analysis_mode"] == "deep"
        assert d["timestamp"] == "2024-03-01T12:00:00+00:00"
        assert d["summary"] == "测试摘要"
        assert len(d["issues"]) == 1
        assert d["issues"][0]["severity"] == "Critical"
        assert d["issues"][0]["title"] == "发现问题"
        assert d["issues"][0]["affected_flows"] == ["f1", "f2"]
        assert d["protocol_insights"] == {"tcp": "正常"}
        assert d["overall_assessment"] == "良好"
        assert d["raw_ai_response"] == "raw json"
        assert d["token_usage"] == {"prompt": 100, "completion": 50}
        assert d["duration_seconds"] == 2.5

    def test_from_dict_roundtrip(self):
        now = datetime(2024, 6, 15, 8, 30, 0, tzinfo=timezone.utc)
        original = AnalysisResult(
            session_id="rt",
            analysis_mode="quick",
            timestamp=now,
            summary="往返测试",
            issues=[
                AnalysisIssue(
                    severity="Warning", category="Performance",
                    title="延迟高", description="平均延迟 200ms",
                    recommendation="优化网络",
                ),
            ],
            protocol_insights={},
            overall_assessment="需要优化",
            raw_ai_response="",
            token_usage={},
            duration_seconds=1.0,
        )
        d = original.to_dict()
        restored = AnalysisResult.from_dict(d)
        assert restored.session_id == original.session_id
        assert restored.analysis_mode == original.analysis_mode
        assert restored.summary == original.summary
        assert len(restored.issues) == 1
        assert restored.issues[0].severity == "Warning"
        assert restored.issues[0].title == "延迟高"
        assert restored.protocol_insights == original.protocol_insights
        assert restored.overall_assessment == original.overall_assessment
        assert restored.token_usage == original.token_usage
        assert restored.duration_seconds == original.duration_seconds

    def test_from_dict_defaults(self):
        d = {}
        result = AnalysisResult.from_dict(d)
        assert result.session_id == ""
        assert result.analysis_mode == "quick"
        assert result.summary == ""
        assert result.issues == []
        assert result.protocol_insights == {}
        assert result.overall_assessment == ""
        assert result.raw_ai_response == ""
        assert result.token_usage == {}
        assert result.duration_seconds == 0.0

    def test_issue_to_dict(self):
        issue = AnalysisIssue(
            severity="Info", category="Protocol",
            title="测试", description="描述",
            affected_flows=["a"], recommendation="建议",
            raw_detail="原始",
        )
        d = issue.to_dict()
        assert d["severity"] == "Info"
        assert d["category"] == "Protocol"
        assert d["title"] == "测试"
        assert d["description"] == "描述"
        assert d["affected_flows"] == ["a"]
        assert d["recommendation"] == "建议"
        assert d["raw_detail"] == "原始"

    def test_issue_from_dict(self):
        d = {
            "severity": "Critical",
            "category": "Security",
            "title": "标题",
            "description": "描述",
        }
        issue = AnalysisIssue.from_dict(d)
        assert issue.severity == "Critical"
        assert issue.category == "Security"
        assert issue.title == "标题"
        assert issue.description == "描述"
        assert issue.affected_flows == []
        assert issue.recommendation == ""
        assert issue.raw_detail is None
