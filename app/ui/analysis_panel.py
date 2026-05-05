"""AI 分析结果展示面板"""

from __future__ import annotations

import logging

from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QTextCursor
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.application import SCROLLBAR_STYLE
from app.constants import SEVERITY_COLORS
from app.models.analysis_result import AnalysisResult
from app.ui.analysis_result_widget import AnalysisResultWidget

logger = logging.getLogger(__name__)

# 流式输出最大保留字符数（防止极端情况下内存无限增长）
MAX_STREAM_CHARS = 100000

# 思考动画旋转字符
_THINKING_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


class AnalysisPanel(QWidget):
    """AI 分析结果面板

    包含: 概览摘要 + 阶段标签 + 流式输出区 + 结果卡片列表 + 操作按钮
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._result: AnalysisResult | None = None
        self._stream_text = ""
        self._thinking_frame = 0
        self._stage_base_text = ""

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        header_card = QFrame()
        header_card.setStyleSheet(
            "QFrame {"
            "  background-color: #181825;"
            "  border: 1px solid #313244;"
            "  border-radius: 8px;"
            "}"
        )
        header_layout = QVBoxLayout(header_card)
        header_layout.setContentsMargins(12, 10, 12, 10)
        header_layout.setSpacing(6)

        title_row = QHBoxLayout()
        title_row.setContentsMargins(0, 0, 0, 0)
        title_row.setSpacing(8)

        title_label = QLabel("AI 流量分析")
        title_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #cdd6f4;")
        title_row.addWidget(title_label)

        title_row.addStretch()
        header_layout.addLayout(title_row)

        # 阶段标签独占一行：避免与标题挤在同一水平槽里被压缩，也不再硬限制 maxHeight
        # （此前 setMaximumHeight(24) + wordWrap=True 会把长文本裁成半截字）
        self._stage_label = QLabel("")
        self._stage_label.setWordWrap(True)
        self._stage_label.setStyleSheet(
            "font-size: 12px; color: #89b4fa; padding: 4px 10px;"
            "background-color: #11111b; border-radius: 10px;"
        )
        self._stage_label.setVisible(False)
        header_layout.addWidget(self._stage_label)

        self._summary_label = QLabel("等待分析...")
        self._summary_label.setWordWrap(True)
        self._summary_label.setStyleSheet("font-size: 14px; color: #cdd6f4; margin-top: 4px; margin-bottom: 4px;")
        header_layout.addWidget(self._summary_label)

        self._stats_label = QLabel("")
        self._stats_label.setWordWrap(True)
        self._stats_label.setStyleSheet(
            "font-size: 12px; color: #a6adc8; padding: 8px 10px;"
            "background-color: #11111b; border-radius: 6px;"
        )
        header_layout.addWidget(self._stats_label)

        actions_layout = QHBoxLayout()
        actions_layout.setContentsMargins(0, 0, 0, 0)
        actions_layout.setSpacing(10)

        self._deep_btn = QPushButton("深度分析")
        self._deep_btn.setEnabled(False)
        self._deep_btn.setStyleSheet(
            "QPushButton { background-color: #f38ba8; color: #1e1e2e; }"
            "QPushButton:hover { background-color: #eba0ac; }"
            "QPushButton:disabled { background-color: #45475a; color: #6c7086; }"
        )
        actions_layout.addWidget(self._deep_btn)

        self._reanalyze_btn = QPushButton("重新分析")
        self._reanalyze_btn.setEnabled(False)
        actions_layout.addWidget(self._reanalyze_btn)
        actions_layout.addStretch()
        header_layout.addLayout(actions_layout)

        layout.addWidget(header_card)

        # 流式输出可折叠标题
        self._stream_toggle = QLabel("▶ AI 思考过程（点击展开）")
        self._stream_toggle.setStyleSheet(
            "font-size: 12px; color: #a6adc8; padding: 6px 10px; "
            "border: 1px solid #313244; border-radius: 6px; background-color: #181825;"
        )
        self._stream_toggle.setCursor(Qt.PointingHandCursor)
        self._stream_toggle.mousePressEvent = self._toggle_stream
        self._stream_toggle.setVisible(False)
        layout.addWidget(self._stream_toggle)

        # 流式输出区域
        self._stream_output = QTextEdit()
        self._stream_output.setReadOnly(True)
        self._stream_output.setMinimumHeight(100)
        self._stream_output.setMaximumHeight(300)
        self._stream_output.setLineWrapMode(QTextEdit.WidgetWidth)
        self._stream_output.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._stream_output.setStyleSheet(
            "QTextEdit {"
            "  background-color: #181825;"
            "  border: 1px solid #313244;"
            "  border-radius: 6px;"
            "  color: #a6adc8;"
            "  font-family: 'Consolas', 'Microsoft YaHei', monospace;"
            "  font-size: 12px;"
            "  padding: 8px;"
            "}"
            + SCROLLBAR_STYLE
        )
        self._stream_output.setVisible(False)
        layout.addWidget(self._stream_output)

        results_title = QLabel("风险发现")
        results_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #cdd6f4; margin-top: 8px;")
        layout.addWidget(results_title)

        # 结果卡片滚动区
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setMinimumHeight(150)
        scroll.setStyleSheet(
            "QScrollArea { border: none; background-color: transparent; }"
            + SCROLLBAR_STYLE
        )

        self._cards_container = QWidget()
        self._cards_container.setStyleSheet("QWidget { background-color: transparent; }")
        self._cards_layout = QVBoxLayout(self._cards_container)
        self._cards_layout.setSpacing(8)
        self._cards_layout.addStretch()

        scroll.setWidget(self._cards_container)
        layout.addWidget(scroll, stretch=1)

        # 思考动画定时器
        self._thinking_timer = QTimer(self)
        self._thinking_timer.setInterval(80)
        self._thinking_timer.timeout.connect(self._on_thinking_tick)

        # 流式区域展开状态
        self._stream_expanded = False

    @property
    def deep_analysis_button(self) -> QPushButton:
        return self._deep_btn

    @property
    def reanalyze_button(self) -> QPushButton:
        return self._reanalyze_btn

    def set_loading(self) -> None:
        """设置为加载状态"""
        self._summary_label.setText("AI 分析中...")
        self._summary_label.setStyleSheet("font-size: 14px; color: #cdd6f4; margin-top: 4px; margin-bottom: 4px;")
        self._stream_text = ""
        self._stream_output.clear()
        self._stream_output.setVisible(True)
        self._stream_expanded = True
        self._stream_toggle.setVisible(False)
        self._stage_label.setVisible(True)
        self._stage_label.setText("正在初始化...")
        self._stats_label.setText("")
        self._clear_cards()
        self._deep_btn.setEnabled(False)
        self._reanalyze_btn.setEnabled(False)
        self._start_thinking_animation()

    def reset_from_error(self, error: str) -> None:
        """分析出错后恢复面板可用状态"""
        self._stop_thinking_animation()
        self._stream_output.hide()
        self._stream_toggle.hide()
        self._stage_label.setVisible(False)
        self._summary_label.setText(f"分析失败: {error[:200]}")
        self._summary_label.setStyleSheet("font-size: 14px; color: #FF4444; margin-top: 4px; margin-bottom: 4px;")
        self._stats_label.setText("请检查模型配置、网络连通性或 API 返回结果后再试。")
        self._deep_btn.setEnabled(True)
        self._reanalyze_btn.setEnabled(True)
        self._stream_text = ""

    def update_progress(self, chunk: str) -> None:
        """流式更新进度"""
        self._stream_text += chunk
        if len(self._stream_text) > MAX_STREAM_CHARS:
            self._stream_text = "...[早期输出已省略]\n" + self._stream_text[-MAX_STREAM_CHARS:]
            self._stream_output.setPlainText(self._stream_text)
        else:
            cursor = self._stream_output.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            cursor.insertText(chunk)

        scrollbar = self._stream_output.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def update_stage(self, stage: str) -> None:
        """更新分析阶段标签"""
        self._stage_base_text = stage
        frame = _THINKING_FRAMES[self._thinking_frame % len(_THINKING_FRAMES)]
        self._stage_label.setText(f"{frame} {stage}")

    def display_results(self, result: AnalysisResult) -> None:
        """展示完整分析结果"""
        self._stop_thinking_animation()
        self._result = result

        # 折叠流式输出，但保持可访问
        self._stream_output.setVisible(False)
        self._stream_expanded = False
        if self._stream_text:
            char_count = len(self._stream_text)
            self._stream_toggle.setText(
                f"▶ AI 思考过程（{char_count:,} 字符，点击展开查看原始输出）"
            )
            self._stream_toggle.setVisible(True)
        else:
            self._stream_toggle.setVisible(False)

        # 阶段标签显示完成状态
        self._stage_label.setText("分析完成")
        self._stage_label.setStyleSheet(
            "font-size: 12px; color: #a6e3a1; padding: 4px 10px;"
            "background-color: #11111b; border-radius: 10px;"
        )

        # 概览
        summary_parts = []
        if result.summary:
            summary_parts.append(result.summary)
        if result.overall_assessment:
            summary_parts.append(f"\n整体评估: {result.overall_assessment}")
        self._summary_label.setText("\n".join(summary_parts) if summary_parts else "分析完成")

        # 统计
        stats_parts = []
        if result.risk_level:
            risk_colors = {"Critical": "#ff4444", "High": "#ff6600", "Medium": "#ffb020", "Low": "#4488ff", "Normal": "#44bb44"}
            risk_color = risk_colors.get(result.risk_level, "#6c7086")
            stats_parts.append(f"风险等级: <span style='color:{risk_color};font-weight:bold;'>{result.risk_level}</span>")
        for severity in ("Critical", "Warning", "Info", "Normal"):
            count = sum(1 for i in result.issues if i.severity == severity)
            if count > 0:
                sev_color = SEVERITY_COLORS.get(severity, "#CCCCCC")
                stats_parts.append(f"{severity}: <span style='color:{sev_color};'>{count}</span>")
        if result.duration_seconds > 0:
            stats_parts.append(f"耗时: {result.duration_seconds:.1f}s")
        if result.flow_analyses:
            stats_parts.append(f"深度分析流: {len(result.flow_analyses)} 条")

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
                self._cards_layout.count() - 1, card
            )

        # 启用操作按钮
        self._deep_btn.setEnabled(True)
        self._reanalyze_btn.setEnabled(True)

    def _toggle_stream(self, event=None) -> None:
        """切换流式输出的展开/折叠"""
        self._stream_expanded = not self._stream_expanded

        char_count = len(self._stream_text) if self._stream_text else 0

        if self._stream_expanded:
            # 展开：确保文本与 _stream_text 同步（防止跨线程信号时序导致的遗漏）
            if self._stream_text and self._stream_output.toPlainText() != self._stream_text:
                self._stream_output.setPlainText(self._stream_text)
            self._stream_output.setVisible(True)
            if char_count > 0:
                self._stream_toggle.setText(f"▼ AI 思考过程（{char_count:,} 字符，点击收起）")
            else:
                self._stream_toggle.setText("▼ AI 思考过程（点击收起）")
        else:
            self._stream_output.setVisible(False)
            if char_count > 0:
                self._stream_toggle.setText(f"▶ AI 思考过程（{char_count:,} 字符，点击展开查看原始输出）")
            else:
                self._stream_toggle.setText("▶ AI 思考过程（点击展开）")

    def _start_thinking_animation(self) -> None:
        """启动思考动画"""
        self._thinking_frame = 0
        self._thinking_timer.start()

    def _stop_thinking_animation(self) -> None:
        """停止思考动画"""
        self._thinking_timer.stop()

    def _on_thinking_tick(self) -> None:
        """思考动画定时器回调：只切换动画字符，基础文本不变"""
        self._thinking_frame += 1
        frame = _THINKING_FRAMES[self._thinking_frame % len(_THINKING_FRAMES)]
        self._stage_label.setText(f"{frame} {self._stage_base_text}")

    def _clear_cards(self) -> None:
        """清空所有卡片"""
        while self._cards_layout.count() > 1:
            item = self._cards_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
