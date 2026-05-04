"""AI 分析结果卡片组件"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from app.constants import SEVERITY_COLORS
from app.models.analysis_result import AnalysisIssue


class AnalysisResultWidget(QWidget):
    """单条 AI 分析结果卡片

    展示: 严重级别标签 + 分类 + 标题 + 描述 + 建议
    点击可展开/收起详情
    """

    def __init__(self, issue: AnalysisIssue, parent=None):
        super().__init__(parent)
        self._issue = issue
        self._expanded = False

        self.setStyleSheet(self._card_style())

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(4)

        # 标题行：严重级别 + 分类 + 标题
        title_layout = QVBoxLayout()

        severity_color = SEVERITY_COLORS.get(issue.severity, "#CCCCCC")

        # 严重级别标签
        severity_label = QLabel(f"[{issue.severity}]")
        severity_label.setStyleSheet(
            f"color: {severity_color}; font-weight: bold; font-size: 12px; border: none;"
        )
        title_layout.addWidget(severity_label)

        # 标题
        title = QLabel(issue.title)
        title.setStyleSheet("font-weight: bold; font-size: 14px; border: none;")
        title.setWordWrap(True)
        title_layout.addWidget(title)

        layout.addLayout(title_layout)

        # 描述
        desc = QLabel(issue.description)
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #bac2de; font-size: 13px; border: none;")
        layout.addWidget(desc)

        # 建议（如果有）
        if issue.recommendation:
            rec_label = QLabel(f"建议: {issue.recommendation}")
            rec_label.setWordWrap(True)
            rec_label.setStyleSheet("color: #a6e3a1; font-size: 12px; border: none;")
            layout.addWidget(rec_label)

        # 受影响的流
        if issue.affected_flows:
            flows_text = "相关流: " + ", ".join(issue.affected_flows[:5])
            if len(issue.affected_flows) > 5:
                flows_text += f" 等 {len(issue.affected_flows)} 个"
            flows_label = QLabel(flows_text)
            flows_label.setStyleSheet("color: #6c7086; font-size: 11px; border: none;")
            layout.addWidget(flows_label)

    def _card_style(self) -> str:
        severity_color = SEVERITY_COLORS.get(self._issue.severity, "#CCCCCC")
        return (
            f"QWidget {{"
            f"  background-color: #1e1e2e;"
            f"  border-left: 4px solid {severity_color};"
            f"  border-top: 1px solid #313244;"
            f"  border-right: 1px solid #313244;"
            f"  border-bottom: 1px solid #313244;"
            f"  border-radius: 4px;"
            f"}}"
        )
