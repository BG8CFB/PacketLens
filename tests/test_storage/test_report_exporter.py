"""ReportExporter 单元测试 — 覆盖导出格式、XSS 防护、文件保存"""

import json
from datetime import datetime
from pathlib import Path

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


class TestReportExporterXSS:
    """XSS 防护测试 — 验证 HTML 输出中对用户输入的转义"""

    def test_html_escapes_script_in_title(self):
        """title 中的 <script> 标签应被转义"""
        exporter = ReportExporter()
        result = AnalysisResult(
            summary="正常摘要",
            issues=[
                AnalysisIssue(
                    severity="Warning",
                    category="Security",
                    title='<script>alert("xss")</script>',
                    description="描述",
                ),
            ],
        )
        html = exporter.export_html({}, result)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html
        assert 'alert("xss")' in html or "alert(&quot;xss&quot;)" in html

    def test_html_escapes_script_in_description(self):
        """description 中的恶意内容应被转义"""
        exporter = ReportExporter()
        result = AnalysisResult(
            summary="正常摘要",
            issues=[
                AnalysisIssue(
                    severity="Info",
                    category="Protocol",
                    title="正常标题",
                    description='<img src=x onerror="alert(1)">',
                ),
            ],
        )
        html = exporter.export_html({}, result)
        assert "<img" not in html
        assert "&lt;img" in html

    def test_html_escapes_script_in_summary(self):
        """summary 中的恶意内容应被转义"""
        exporter = ReportExporter()
        result = AnalysisResult(
            summary='<script>document.cookie</script>',
        )
        html = exporter.export_html({}, result)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_html_escapes_recommendation(self):
        """recommendation 中的恶意内容应被转义"""
        exporter = ReportExporter()
        result = AnalysisResult(
            issues=[
                AnalysisIssue(
                    severity="Warning",
                    category="Security",
                    title="问题",
                    description="描述",
                    recommendation='<a href="evil">点击</a>',
                ),
            ],
        )
        html = exporter.export_html({}, result)
        assert '<a href="evil">' not in html

    def test_html_escapes_assessment(self):
        """overall_assessment 中的恶意内容应被转义"""
        exporter = ReportExporter()
        result = AnalysisResult(
            summary="摘要",
            overall_assessment='<b onmouseover="alert(1)">危险</b>',
        )
        html = exporter.export_html({}, result)
        assert "<b onmouseover" not in html
        assert "&lt;b" in html

    def test_json_output_preserves_special_chars(self):
        """JSON 输出应保留特殊字符（不做 HTML 转义）"""
        exporter = ReportExporter()
        result = AnalysisResult(
            summary='<script>alert("xss")</script>',
            issues=[
                AnalysisIssue(
                    severity="Info",
                    category="Protocol",
                    title='<tag>special & chars</tag>',
                    description='"quotes" & <tags>',
                ),
            ],
        )
        json_str = exporter.export_json({}, result)
        data = json.loads(json_str)
        # JSON 输出不应做 HTML 转义
        assert data["analysis"]["summary"] == '<script>alert("xss")</script>'
        assert data["analysis"]["issues"][0]["title"] == '<tag>special & chars</tag>'

    def test_markdown_output_preserves_special_chars(self):
        """Markdown 输出应保留特殊字符（不做 HTML 转义）"""
        exporter = ReportExporter()
        result = AnalysisResult(
            summary='<script>alert("xss")</script>',
        )
        md = exporter.export_markdown({}, result)
        assert '<script>alert("xss")</script>' in md

    def test_empty_strings_handled(self):
        """空字符串应安全处理"""
        exporter = ReportExporter()
        result = AnalysisResult(
            summary="",
            overall_assessment="",
            issues=[
                AnalysisIssue(
                    severity="Info",
                    category="Protocol",
                    title="",
                    description="",
                    recommendation="",
                ),
            ],
        )
        # 不应抛出异常
        html = exporter.export_html({}, result)
        assert isinstance(html, str)

        md = exporter.export_markdown({}, result)
        assert isinstance(md, str)

    def test_none_assessment_handled(self):
        """None assessment 应安全处理"""
        exporter = ReportExporter()
        result = AnalysisResult(overall_assessment=None)
        html = exporter.export_html({}, result)
        assert "未评估" in html

        md = exporter.export_markdown({}, result)
        assert "未评估" in md


class TestReportExporterMarkdownNestedList:
    """Markdown 嵌套列表父项 bullet — 修复8回归测试"""

    def _build_result_with_flow_issues(self) -> AnalysisResult:
        from app.models.analysis_result import FlowAnalysis
        return AnalysisResult(
            summary="带逐流分析的结果",
            flow_analyses=[
                FlowAnalysis(
                    flow_id="flow-A",
                    verdict="suspicious",
                    confidence=0.82,
                    evidence=["证据1", "证据2"],
                    issues=[
                        AnalysisIssue(
                            severity="Critical",
                            category="Security",
                            title="可疑外联",
                            description="目标 IP 不在白名单",
                        ),
                        AnalysisIssue(
                            severity="Warning",
                            category="Performance",
                            title="高频请求",
                            description="请求频率超阈值",
                        ),
                    ],
                ),
            ],
        )

    def test_markdown_renders_parent_bullet_for_flow_issues(self):
        """flow_analyses 中包含 issues 时应输出『- **问题**:』父项 bullet"""
        exporter = ReportExporter()
        result = self._build_result_with_flow_issues()
        md = exporter.export_markdown({}, result)

        assert "- **问题**:" in md, "缺少『问题』父级 bullet，嵌套结构语义模糊"
        assert "  - [Critical] 可疑外联" in md
        assert "  - [Warning] 高频请求" in md

    def test_markdown_parent_bullet_precedes_indented_children(self):
        """父项 bullet 应紧邻在缩进子项之前"""
        exporter = ReportExporter()
        result = self._build_result_with_flow_issues()
        md = exporter.export_markdown({}, result)

        lines = md.splitlines()
        parent_idx = next(i for i, ln in enumerate(lines) if ln == "- **问题**:")
        # 父项后第一行必须是缩进的子 bullet
        assert lines[parent_idx + 1].startswith("  - [")

    def test_markdown_no_parent_bullet_when_no_flow_issues(self):
        """flow_analyses 中无 issues 时不应输出『问题』父项 bullet"""
        exporter = ReportExporter()
        from app.models.analysis_result import FlowAnalysis
        result = AnalysisResult(
            summary="无逐流问题",
            flow_analyses=[
                FlowAnalysis(
                    flow_id="flow-empty",
                    verdict="benign",
                    confidence=0.95,
                    evidence=["无异常"],
                    issues=[],  # 显式空列表
                ),
            ],
        )
        md = exporter.export_markdown({}, result)
        assert "- **问题**:" not in md
        assert "### 流 flow-empty" in md

    def test_markdown_evidence_and_parent_bullet_coexist(self):
        """evidence 与 issues 共存时，证据 bullet 与问题父项 bullet 都应出现"""
        exporter = ReportExporter()
        result = self._build_result_with_flow_issues()
        md = exporter.export_markdown({}, result)

        assert "- **证据**: 证据1; 证据2" in md
        assert "- **问题**:" in md
