"""AI 分析结果展示面板"""

from __future__ import annotations

import logging

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QLabel,
    QPushButton,
    QScrollArea,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.constants import SEVERITY_COLORS
from app.models.analysis_result import AnalysisResult
from app.ui.analysis_result_widget import AnalysisResultWidget

logger = logging.getLogger(__name__)

# 流式输出最大保留字符数（防止极端情况下内存无限增长）
MAX_STREAM_CHARS = 100000


class AnalysisPanel(QWidget):
    """AI 分析结果面板

    包含: 概览摘要 + 流式输出区 + 结果卡片列表 + 操作按钮
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._result: AnalysisResult | None = None
        self._stream_text = ""

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # 概览标签
        self._summary_label = QLabel("等待分析...")
        self._summary_label.setWordWrap(True)
        self._summary_label.setStyleSheet("font-size: 14px; padding: 8px;")
        layout.addWidget(self._summary_label)

        # 流式输出区域（替代之前的固定截断文本）
        self._stream_output = QTextEdit()
        self._stream_output.setReadOnly(True)
        self._stream_output.setMaximumHeight(120)
        self._stream_output.setStyleSheet(
            "QTextEdit {"
            "  background-color: #181825;"
            "  border: 1px solid #313244;"
            "  border-radius: 4px;"
            "  color: #a6adc8;"
            "  font-family: 'Consolas', 'Microsoft YaHei', monospace;"
            "  font-size: 12px;"
            "  padding: 6px;"
            "}"
        )
        self._stream_output.hide()
        layout.addWidget(self._stream_output)

        # 统计标签
        self._stats_label = QLabel("")
        self._stats_label.setStyleSheet("font-size: 12px; color: #6c7086; padding: 4px;")
        layout.addWidget(self._stats_label)

        # 结果卡片滚动区
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; }")

        self._cards_container = QWidget()
        self._cards_layout = QVBoxLayout(self._cards_container)
        self._cards_layout.setSpacing(8)
        self._cards_layout.addStretch()

        scroll.setWidget(self._cards_container)
        layout.addWidget(scroll, stretch=1)

        # 操作按钮
        btn_layout = QVBoxLayout()

        self._deep_btn = QPushButton("深度分析")
        self._deep_btn.setEnabled(False)
        self._deep_btn.setStyleSheet(
            "QPushButton { background-color: #f38ba8; color: #1e1e2e; }"
            "QPushButton:hover { background-color: #eba0ac; }"
            "QPushButton:disabled { background-color: #45475a; color: #6c7086; }"
        )
        btn_layout.addWidget(self._deep_btn)

        self._reanalyze_btn = QPushButton("重新分析")
        self._reanalyze_btn.setEnabled(False)
        btn_layout.addWidget(self._reanalyze_btn)

        layout.addLayout(btn_layout)

    @property
    def deep_analysis_button(self) -> QPushButton:
        return self._deep_btn

    @property
    def reanalyze_button(self) -> QPushButton:
        return self._reanalyze_btn

    def set_loading(self) -> None:
        """设置为加载状态"""
        self._summary_label.setText("AI 分析中...")
        self._stream_text = ""
        self._stream_output.clear()
        self._stream_output.show()
        self._stats_label.setText("")
        self._clear_cards()

    def update_progress(self, chunk: str) -> None:
        """流式更新进度——完整显示，不做截断"""
        self._stream_text += chunk
        # 仅在超出上限时裁剪前端（保留最新内容）
        if len(self._stream_text) > MAX_STREAM_CHARS:
            self._stream_text = "...[早期输出已省略]\n" + self._stream_text[-MAX_STREAM_CHARS:]

        self._stream_output.setPlainText(self._stream_text)
        # 自动滚动到底部
        scrollbar = self._stream_output.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def display_results(self, result: AnalysisResult) -> None:
        """展示完整分析结果"""
        self._result = result
        self._stream_output.hide()

        # 概览
        self._summary_label.setText(result.summary or "分析完成")

        # 统计
        stats_parts = []
        for severity in ("Critical", "Warning", "Info", "Normal"):
            count = sum(1 for i in result.issues if i.severity == severity)
            if count > 0:
                stats_parts.append(f"{severity}: {count}")
        if result.duration_seconds > 0:
            stats_parts.append(f"耗时: {result.duration_seconds:.1f}s")

        self._stats_label.setText(" | ".join(stats_parts) if stats_parts else "无异常")

        # 清空旧卡片
        self._clear_cards()

        # 添加新卡片（按严重级别排序）
        severity_order = {"Critical": 0, "Warning": 1, "Info": 2, "Normal": 3}
        sorted_issues = sorted(
            result.issues,
            key=lambda i: severity_order.get(i.severity, 99),
        )

        for issue in sorted_issues:
            card = AnalysisResultWidget(issue)
            self._cards_layout.insertWidget(
                self._cards_layout.count() - 1, card  # 在 stretch 之前插入
            )

        # 启用操作按钮
        self._deep_btn.setEnabled(True)
        self._reanalyze_btn.setEnabled(True)

    def _clear_cards(self) -> None:
        """清空所有卡片"""
        while self._cards_layout.count() > 1:
            item = self._cards_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
