"""抓包控制工具栏"""

from __future__ import annotations

import logging
from datetime import datetime

from PySide6.QtCore import QTimer, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QWidget,
)

from app.constants import DEFAULT_CAPTURE_DURATION, MAX_CAPTURE_DURATION, MIN_CAPTURE_DURATION
from app.models.nic_info import NICInfo

logger = logging.getLogger(__name__)


class CaptureControls(QWidget):
    """抓包控制面板

    包含: 网卡选择、BPF 过滤器、抓包时长、开始/停止按钮、状态标签
    """

    start_requested = Signal(str, str, int, bool)  # iface, bpf, duration, promisc
    stop_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._is_capturing = False
        self._start_time: datetime | None = None

        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)

        # 网卡选择
        layout.addWidget(QLabel("网卡:"))
        self._nic_combo = QComboBox()
        self._nic_combo.setMinimumWidth(250)
        layout.addWidget(self._nic_combo)

        # BPF 过滤器
        layout.addWidget(QLabel("BPF:"))
        self._bpf_input = QLineEdit()
        self._bpf_input.setPlaceholderText("例: port 80, host 192.168.1.1")
        self._bpf_input.setMinimumWidth(180)
        layout.addWidget(self._bpf_input)

        # 时长
        layout.addWidget(QLabel("时长:"))
        self._duration_combo = QComboBox()
        self._duration_combo.addItems(
            ["10秒", "30秒", "60秒", "120秒", "300秒"]
        )
        self._duration_combo.setCurrentIndex(2)  # 默认 60秒
        self._duration_combo.setMinimumWidth(80)
        layout.addWidget(self._duration_combo)

        # 混杂模式
        self._promisc_cb = QCheckBox("混杂模式")
        self._promisc_cb.setChecked(True)
        self._promisc_cb.setToolTip("启用混杂模式可捕获非本机流量")
        layout.addWidget(self._promisc_cb)

        # 开始/停止按钮
        self._start_btn = QPushButton("开始抓包")
        self._start_btn.setMinimumWidth(100)
        self._start_btn.clicked.connect(self._on_toggle)
        layout.addWidget(self._start_btn)

        # 状态标签
        self._status_label = QLabel("就绪")
        layout.addWidget(self._status_label)

        # 已用时间标签
        self._elapsed_label = QLabel("")
        layout.addWidget(self._elapsed_label)

        layout.addStretch()

        # 已用时间更新定时器
        self._elapsed_timer = QTimer()
        self._elapsed_timer.setInterval(1000)
        self._elapsed_timer.timeout.connect(self._update_elapsed)

    def populate_nics(self, nics: list[NICInfo]) -> None:
        """填充网卡列表"""
        self._nic_combo.clear()
        for nic in nics:
            self._nic_combo.addItem(nic.display_name, nic.name)

    def get_selected_iface(self) -> str:
        """获取选中的网卡名称"""
        return self._nic_combo.currentData() or ""

    def get_duration(self) -> int:
        """获取抓包时长（秒）"""
        text = self._duration_combo.currentText()
        # "60秒" → 60
        try:
            return int(text.replace("秒", ""))
        except ValueError:
            return DEFAULT_CAPTURE_DURATION

    def get_bpf_filter(self) -> str:
        return self._bpf_input.text().strip()

    def set_default_duration(self, seconds: int) -> None:
        """根据配置设置默认抓包时长"""
        duration_map = {10: 0, 30: 1, 60: 2, 120: 3, 300: 4}
        index = duration_map.get(seconds, 2)
        self._duration_combo.setCurrentIndex(index)

    def set_capturing(self, capturing: bool) -> None:
        """设置抓包状态"""
        self._is_capturing = capturing
        if capturing:
            self._start_btn.setText("停止抓包")
            self._nic_combo.setEnabled(False)
            self._bpf_input.setEnabled(False)
            self._duration_combo.setEnabled(False)
            self._status_label.setText("抓包中...")
            self._start_time = datetime.now()
            self._elapsed_timer.start()
        else:
            self._start_btn.setText("开始抓包")
            self._nic_combo.setEnabled(True)
            self._bpf_input.setEnabled(True)
            self._duration_combo.setEnabled(True)
            self._status_label.setText("就绪")
            self._elapsed_label.setText("")
            self._start_time = None
            self._elapsed_timer.stop()

    def update_packet_count(self, count: int) -> None:
        self._status_label.setText(f"抓包中... 已捕获 {count} 个包")

    def _on_toggle(self) -> None:
        if self._is_capturing:
            self.stop_requested.emit()
        else:
            iface = self.get_selected_iface()
            if not iface:
                QMessageBox.warning(self, "提示", "请先选择一个网卡")
                return
            bpf = self.get_bpf_filter()
            duration = self.get_duration()
            self.start_requested.emit(iface, bpf, duration, self._promisc_cb.isChecked())

    def _update_elapsed(self) -> None:
        if self._start_time:
            elapsed = (datetime.now() - self._start_time).total_seconds()
            mins, secs = divmod(int(elapsed), 60)
            self._elapsed_label.setText(f"{mins:02d}:{secs:02d}")
