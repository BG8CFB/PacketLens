"""报告导出（Markdown / HTML / JSON）"""

from __future__ import annotations

import html
import json
import logging
from datetime import datetime
from pathlib import Path

from app.models.analysis_result import AnalysisResult
from app.utils.path_helpers import atomic_write

logger = logging.getLogger(__name__)


class ReportExporter:
    """报告导出器"""

    # 严重级别对应的颜色值（仅允许十六进制格式，防止注入）
    _SEVERITY_COLORS = {
        "Critical": "#ff4444",
        "Warning": "#ffb020",
        "Info": "#4488ff",
        "Normal": "#44bb44",
    }
    _DEFAULT_SEVERITY_COLOR = "#cccccc"

    @staticmethod
    def _escape_html(text: str) -> str:
        """转义 HTML 特殊字符，防止 XSS"""
        if not text:
            return ""
        return html.escape(str(text), quote=True)

    def export_markdown(self, session_data: dict, result: AnalysisResult) -> str:
        """导出 Markdown 报告"""
        lines = [
            f"# PacketLens 抓包分析报告",
            f"",
            f"**分析时间**: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            f"**分析模式**: {'快速' if result.analysis_mode == 'quick' else '深度'}",
            f"**总包数**: {session_data.get('packet_count', 'N/A')}",
            f"**总流数**: {session_data.get('flow_count', 'N/A')}",
            f"**网卡**: {session_data.get('interface', 'N/A')}",
            f"**时长**: {session_data.get('duration', 'N/A')}s",
            f"",
            f"## 概览",
            f"",
            result.summary,
            f"",
            f"**整体评估**: {result.overall_assessment or '未评估'}",
            f"",
        ]

        if result.issues:
            lines.append("## 发现")
            lines.append("")
            if result.risk_level:
                lines.append(f"**风险等级**: {result.risk_level}")
                lines.append("")
            for i, issue in enumerate(result.issues, 1):
                lines.append(f"### {i}. [{issue.severity}] {issue.title}")
                lines.append("")
                lines.append(f"- **分类**: {issue.category}")
                lines.append(f"- **描述**: {issue.description}")
                if issue.recommendation:
                    lines.append(f"- **建议**: {issue.recommendation}")
                if issue.affected_flows:
                    lines.append(f"- **相关流**: {', '.join(issue.affected_flows)}")
                if issue.affected_ips:
                    lines.append(f"- **相关 IP**: {', '.join(issue.affected_ips)}")
                lines.append("")

        if result.flow_analyses:
            lines.append("## 逐流深度分析")
            lines.append("")
            for fa in result.flow_analyses:
                lines.append(f"### 流 {fa.flow_id}")
                lines.append(f"- **判定**: {fa.verdict} (置信度: {fa.confidence:.0%})")
                if fa.evidence:
                    lines.append(f"- **证据**: {'; '.join(fa.evidence)}")
                if fa.issues:
                    # 显式父项 bullet，避免缩进列表渲染时无父项导致语义模糊
                    lines.append(f"- **问题**:")
                    for issue in fa.issues:
                        lines.append(f"  - [{issue.severity}] {issue.title}: {issue.description}")
                lines.append("")

        return "\n".join(lines)

    def export_html(self, session_data: dict, result: AnalysisResult) -> str:
        """导出 HTML 报告"""
        issues_html = ""
        for issue in result.issues:
            color = self._SEVERITY_COLORS.get(issue.severity, self._DEFAULT_SEVERITY_COLOR)
            severity_esc = self._escape_html(issue.severity)
            title_esc = self._escape_html(issue.title)
            desc_esc = self._escape_html(issue.description)
            rec_esc = self._escape_html(issue.recommendation) if issue.recommendation else ""
            flows_esc = self._escape_html(", ".join(issue.affected_flows)) if issue.affected_flows else ""
            ips_esc = self._escape_html(", ".join(issue.affected_ips)) if issue.affected_ips else ""
            issues_html += f"""
            <div style="border-left: 4px solid {color}; padding: 12px; margin: 8px 0; background: #f8f9fa;">
                <strong style="color: {color};">[{severity_esc}]</strong> {title_esc}
                <p>{desc_esc}</p>
                {f'<p><em>建议: {rec_esc}</em></p>' if rec_esc else ''}
                {f'<p style="color:#666; font-size:0.9em;">相关流: {flows_esc}</p>' if flows_esc else ''}
                {f'<p style="color:#666; font-size:0.9em;">相关 IP: {ips_esc}</p>' if ips_esc else ''}
            </div>"""

        # Layer 2 逐流分析结果
        flow_analyses_html = ""
        if result.flow_analyses:
            for fa in result.flow_analyses:
                verdict_color = "#ff4444" if fa.verdict == "malicious" else "#ffb020" if fa.verdict == "suspicious" else "#44bb44"
                evidence_esc = self._escape_html("; ".join(fa.evidence)) if fa.evidence else ""
                flow_analyses_html += f"""
                <div style="border: 1px solid #ddd; padding: 10px; margin: 6px 0; border-radius: 4px;">
                    <strong>流 {self._escape_html(fa.flow_id)}</strong> —
                    <span style="color:{verdict_color};">{self._escape_html(fa.verdict)}</span>
                    <span style="color:#666;">(置信度: {fa.confidence:.0%})</span>
                    {f'<p style="font-size:0.9em; color:#555;">证据: {evidence_esc}</p>' if evidence_esc else ''}
                </div>"""

        risk_level_esc = self._escape_html(result.risk_level) if result.risk_level else ""
        summary_esc = self._escape_html(result.summary)
        assessment_esc = self._escape_html(result.overall_assessment or "未评估")
        html_content = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>PacketLens 分析报告</title>
<style>body {{ font-family: sans-serif; max-width: 900px; margin: 40px auto; padding: 20px; }}
h1 {{ color: #333; }} .meta {{ color: #666; }}</style>
</head><body>
<h1>PacketLens 抓包分析报告</h1>
<div class="meta">
    <p>分析时间: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')} |
    模式: {'快速' if result.analysis_mode == 'quick' else '深度'} |
    总包数: {self._escape_html(str(session_data.get('packet_count', 'N/A')))} |
    总流数: {self._escape_html(str(session_data.get('flow_count', 'N/A')))}</p>
</div>
<h2>概览</h2>
<p>{summary_esc}</p>
<p><strong>整体评估</strong>: {assessment_esc}</p>
{f'<p><strong>风险等级</strong>: {risk_level_esc}</p>' if risk_level_esc else ''}
<h2>发现</h2>
{issues_html if issues_html else '<p>无异常发现</p>'}
{f'<h2>逐流深度分析</h2>{flow_analyses_html}' if flow_analyses_html else ''}
</body></html>"""
        return html_content

    def export_json(self, session_data: dict, result: AnalysisResult) -> str:
        """导出 JSON 报告"""
        data = {
            "session": session_data,
            "analysis": {
                "mode": result.analysis_mode,
                "timestamp": result.timestamp.isoformat(),
                "summary": result.summary,
                "overall_assessment": result.overall_assessment,
                "risk_level": result.risk_level,
                "issues": [
                    {
                        "severity": i.severity,
                        "category": i.category,
                        "title": i.title,
                        "description": i.description,
                        "affected_flows": i.affected_flows,
                        "affected_ips": i.affected_ips,
                        "recommendation": i.recommendation,
                    }
                    for i in result.issues
                ],
                "protocol_insights": result.protocol_insights,
                "flow_analyses": [
                    {
                        "flow_id": fa.flow_id,
                        "verdict": fa.verdict,
                        "confidence": fa.confidence,
                        "issues": [
                            {
                                "severity": i.severity,
                                "title": i.title,
                                "description": i.description,
                            }
                            for i in fa.issues
                        ],
                        "evidence": fa.evidence,
                    }
                    for fa in result.flow_analyses
                ],
            },
        }
        return json.dumps(data, ensure_ascii=False, indent=2)

    def save_report(self, content: str, filepath: str | Path) -> str:
        """保存报告到文件（原子写入）"""
        path = Path(filepath)
        atomic_write(path, content)
        logger.info(f"报告已保存: {path}")
        return str(path)
