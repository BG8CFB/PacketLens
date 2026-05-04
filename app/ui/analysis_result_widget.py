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

        self.setCursor(Qt.PointingHandCursor)
        # 使用 objectName 精确匹配样式，避免影响子 QWidget
        self.setObjectName("analysisCard")
        self.setStyleSheet(self._card_style())

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(4)

        # 标题行：严重级别 + 标题（始终可见）
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

        # 详情容器（初始隐藏）
        self._detail_widget = QWidget()
        detail_layout = QVBoxLayout(self._detail_widget)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        detail_layout.setSpacing(4)

        # 描述
        desc = QLabel(issue.description)
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #bac2de; font-size: 13px; border: none;")
        detail_layout.addWidget(desc)

        # 建议（如果有）
        if issue.recommendation:
            rec_label = QLabel(f"建议: {issue.recommendation}")
            rec_label.setWordWrap(True)
            rec_label.setStyleSheet("color: #a6e3a1; font-size: 12px; border: none;")
            detail_layout.addWidget(rec_label)

        # 受影响的流
        if issue.affected_flows:
            flows_text = "相关流: " + ", ".join(issue.affected_flows[:5])
            if len(issue.affected_flows) > 5:
                flows_text += f" 等 {len(issue.affected_flows)} 个"
            flows_label = QLabel(flows_text)
            flows_label.setStyleSheet("color: #6c7086; font-size: 11px; border: none;")
            detail_layout.addWidget(flows_label)

        self._detail_widget.setVisible(False)
        layout.addWidget(self._detail_widget)

    def mousePressEvent(self, event):
        """点击卡片切换展开/收起状态"""
        if event.button() == Qt.LeftButton:
            self._expanded = not self._expanded
            self._detail_widget.setVisible(self._expanded)
        super().mousePressEvent(event)

    def _card_style(self) -> str:
        severity_color = SEVERITY_COLORS.get(self._issue.severity, "#CCCCCC")
        # 使用 #objectName 选择器，精确匹配卡片本身，不影响子 QWidget
        return (
            f"QWidget#analysisCard {{"
            f"  background-color: #1e1e2e;"
            f"  border-left: 4px solid {severity_color};"
            f"  border-top: 1px solid #313244;"
            f"  border-right: 1px solid #313244;"
            f"  border-bottom: 1px solid #313244;"
            f"  border-radius: 4px;"
            f"}}"
        )
