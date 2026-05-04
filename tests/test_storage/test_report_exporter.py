"""ReportExporter 单元测试"""

import json
from datetime import datetime

from app.models.analysis_result import AnalysisIssue, AnalysisResult
from app.storage.report_exporter import ReportExporter


class TestReportExporter:

    def test_export_markdown_basic(self):
        exporter = ReportExporter()
        session_data = {
            "packet_count": 100,
            "flow_count": 5,
            "interface": "eth0",
            "duration": 60,
        }
        result = AnalysisResult(
            session_id="s1",
            analysis_mode="quick",
            timestamp=datetime(2024, 6, 15, 14, 30, 0),
            summary="这是一份测试摘要",
            overall_assessment="无异常",
            issues=[
                AnalysisIssue(
                    severity="Critical", category="Security",
                    title="端口扫描", description="检测到端口扫描行为",
                    recommendation="检查防火墙",
                    affected_flows=["f1", "f2"],
                ),
            ],
        )

        md = exporter.export_markdown(session_data, result)

        assert "PacketLens" in md
        assert "2024-06-15" in md
        assert "快速" in md
        assert "100" in md
        assert "eth0" in md
        assert "这是一份测试摘要" in md
        assert "无异常" in md
        assert "端口扫描" in md
        assert "检查防火墙" in md
        assert "f1" in md or "f2" in md

    def test_export_markdown_no_issues(self):
        exporter = ReportExporter()
        result = AnalysisResult(summary="无发现")
        md = exporter.export_markdown({}, result)
        assert "无发现" in md
        assert "## 发现" not in md  # 没有 issues 就不应该有 "## 发现" section

    def test_export_html_basic(self):
        exporter = ReportExporter()
        result = AnalysisResult(
            summary="测试",
            issues=[
                AnalysisIssue(
                    severity="Warning", category="Performance",
                    title="高延迟", description="网络延迟超过阈值",
                    recommendation="检查网络",
                ),
            ],
        )

        html = exporter.export_html({}, result)
        assert "<!DOCTYPE html>" in html
        assert "PacketLens" in html
        assert "高延迟" in html
        assert "Warning" in html

    def test_export_html_no_issues(self):
        exporter = ReportExporter()
        result = AnalysisResult()
        html = exporter.export_html({}, result)
        assert "无异常发现" in html

    def test_export_json(self):
        exporter = ReportExporter()
        session = {"id": "abc", "packet_count": 50}
        result = AnalysisResult(
            session_id="abc",
            analysis_mode="deep",
            summary="JSON 测试",
            overall_assessment="OK",
            issues=[
                AnalysisIssue(
                    severity="Info", category="Protocol",
                    title="HTTP", description="HTTP 明文",
                ),
            ],
        )

        json_str = exporter.export_json(session, result)
        data = json.loads(json_str)

        assert data["session"] == session
        assert data["analysis"]["mode"] == "deep"
        assert data["analysis"]["summary"] == "JSON 测试"
        assert len(data["analysis"]["issues"]) == 1
        assert data["analysis"]["issues"][0]["severity"] == "Info"

    def test_save_report(self, tmp_path):
        exporter = ReportExporter()
        filepath = tmp_path / "sub" / "report.md"
        exporter.save_report("# Test Report", filepath)

        assert filepath.exists()
        content = filepath.read_text(encoding="utf-8")
        assert content == "# Test Report"
