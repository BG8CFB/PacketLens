"""AI 分析结果卡片组件"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget

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
        self._flows_expanded = False

        self.setCursor(Qt.PointingHandCursor)
        # 使用 objectName 精确匹配样式，避免影响子 QWidget
        self.setObjectName("analysisCard")
        self.setStyleSheet(self._card_style())

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)

        # 标题行：严重级别 + 标题 + 折叠提示
        title_row = QHBoxLayout()
        title_row.setContentsMargins(0, 0, 0, 0)
        title_row.setSpacing(8)

        severity_color = SEVERITY_COLORS.get(issue.severity, "#CCCCCC")

        severity_label = QLabel(issue.severity)
        severity_label.setStyleSheet(
            f"color: {severity_color}; font-weight: bold; font-size: 11px; border: none;"
            f"background-color: rgba(0, 0, 0, 0.18); padding: 3px 8px; border-radius: 10px;"
        )
        title_row.addWidget(severity_label, 0, Qt.AlignTop)

        title_block = QVBoxLayout()
        title_block.setContentsMargins(0, 0, 0, 0)
        title_block.setSpacing(4)

        title = QLabel(issue.title)
        title.setStyleSheet("font-weight: bold; font-size: 14px; border: none; color: #cdd6f4;")
        title.setWordWrap(True)
        title_block.addWidget(title)

        category_text = issue.category or "未分类"
        category_label = QLabel(f"分类: {category_text}")
        category_label.setStyleSheet("color: #a6adc8; font-size: 11px; border: none;")
        title_block.addWidget(category_label)

        title_row.addLayout(title_block, 1)

        self._expand_hint = QLabel("点击收起")
        self._expand_hint.setStyleSheet("color: #6c7086; font-size: 11px; border: none;")
        title_row.addWidget(self._expand_hint, 0, Qt.AlignTop)

        layout.addLayout(title_row)

        # 详情容器（初始隐藏）
        self._detail_widget = QWidget()
        detail_layout = QVBoxLayout(self._detail_widget)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        detail_layout.setSpacing(4)

        # 描述
        desc = QLabel(issue.description)
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #bac2de; font-size: 13px; line-height: 1.5; border: none;")
        detail_layout.addWidget(desc)

        # 建议（如果有）
        if issue.recommendation:
            rec_label = QLabel(f"建议: {issue.recommendation}")
            rec_label.setWordWrap(True)
            rec_label.setStyleSheet(
                "color: #a6e3a1; font-size: 12px; border: none;"
                "background-color: rgba(166, 227, 161, 0.08); padding: 6px 8px; border-radius: 4px;"
            )
            detail_layout.addWidget(rec_label)

        # 受影响的流（可展开）
        if issue.affected_flows:
            self._flows_label = QLabel()
            self._flows_label.setStyleSheet("color: #6c7086; font-size: 11px; border: none;")
            self._flows_label.setWordWrap(True)
            detail_layout.addWidget(self._flows_label)

            if len(issue.affected_flows) > 5:
                self._expand_flows_btn = QLabel()
                self._expand_flows_btn.setStyleSheet(
                    "color: #89b4fa; font-size: 11px; border: none; text-decoration: underline;"
                )
                self._expand_flows_btn.setCursor(Qt.PointingHandCursor)
                self._expand_flows_btn.mousePressEvent = self._toggle_flows
                detail_layout.addWidget(self._expand_flows_btn)
            else:
                self._expand_flows_btn = None

            self._update_flows_display()
        else:
            self._flows_label = None
            self._expand_flows_btn = None

        # 受影响的 IP（如果有）
        if issue.affected_ips:
            ips_text = "相关 IP: " + ", ".join(issue.affected_ips)
            ips_label = QLabel(ips_text)
            ips_label.setStyleSheet("color: #6c7086; font-size: 11px; border: none;")
            ips_label.setWordWrap(True)
            detail_layout.addWidget(ips_label)

        self._detail_widget.setVisible(True)
        self._expanded = True
        layout.addWidget(self._detail_widget)

    def _update_flows_display(self) -> None:
        """更新受影响流的显示文本"""
        flows = self._issue.affected_flows
        if self._flows_expanded or len(flows) <= 5:
            self._flows_label.setText("相关流: " + ", ".join(flows))
        else:
            self._flows_label.setText("相关流: " + ", ".join(flows[:5]))

        if self._expand_flows_btn:
            if self._flows_expanded:
                self._expand_flows_btn.setText(f"收起（共 {len(flows)} 个）")
            else:
                self._expand_flows_btn.setText(f"展开全部 {len(flows)} 个")

    def _toggle_flows(self, event=None) -> None:
        """切换流列表展开/收起"""
        self._flows_expanded = not self._flows_expanded
        self._update_flows_display()

    def mousePressEvent(self, event):
        """点击卡片切换展开/收起状态"""
        if event.button() == Qt.LeftButton:
            self._expanded = not self._expanded
            self._detail_widget.setVisible(self._expanded)
            self._expand_hint.setText("点击收起" if self._expanded else "点击展开")
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
            f"  border-bottom: 1px solid {severity_color};"
            f"  border-radius: 6px;"
            f"}}"
        )
