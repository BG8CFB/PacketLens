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
            for i, issue in enumerate(result.issues, 1):
                lines.append(f"### {i}. [{issue.severity}] {issue.title}")
                lines.append("")
                lines.append(f"- **分类**: {issue.category}")
                lines.append(f"- **描述**: {issue.description}")
                if issue.recommendation:
                    lines.append(f"- **建议**: {issue.recommendation}")
                if issue.affected_flows:
                    lines.append(f"- **相关流**: {', '.join(issue.affected_flows)}")
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
            issues_html += f"""
            <div style="border-left: 4px solid {color}; padding: 12px; margin: 8px 0; background: #f8f9fa;">
                <strong style="color: {color};">[{severity_esc}]</strong> {title_esc}
                <p>{desc_esc}</p>
                {f'<p><em>建议: {rec_esc}</em></p>' if rec_esc else ''}
            </div>"""

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
    总包数: {session_data.get('packet_count', 'N/A')} |
    总流数: {session_data.get('flow_count', 'N/A')}</p>
</div>
<h2>概览</h2>
<p>{summary_esc}</p>
<p><strong>整体评估</strong>: {assessment_esc}</p>
<h2>发现</h2>
{issues_html if issues_html else '<p>无异常发现</p>'}
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
                "issues": [
                    {
                        "severity": i.severity,
                        "category": i.category,
                        "title": i.title,
                        "description": i.description,
                        "affected_flows": i.affected_flows,
                        "recommendation": i.recommendation,
                    }
                    for i in result.issues
                ],
                "protocol_insights": result.protocol_insights,
            },
        }
        return json.dumps(data, ensure_ascii=False, indent=2)

    def save_report(self, content: str, filepath: str | Path) -> str:
        """保存报告到文件（原子写入）"""
        path = Path(filepath)
        atomic_write(path, content)
        logger.info(f"报告已保存: {path}")
        return str(path)
