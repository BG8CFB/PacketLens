"""包列表视图 — QTableView 子类"""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QHeaderView, QTableView


class PacketTableView(QTableView):
    """数据包列表视图

    - 交替行色
    - 行选择模式
    - 双击信号
    - 最后一列自动拉伸
    """

    packet_double_clicked = Signal(int)  # 行号
    packet_selected = Signal(int)  # 行号

    def __init__(self, parent=None):
        super().__init__(parent)

        self.setSelectionBehavior(QTableView.SelectRows)
        self.setSelectionMode(QTableView.SingleSelection)
        self.setAlternatingRowColors(True)
        self.setShowGrid(False)
        self.setSortingEnabled(True)
        self.verticalHeader().setDefaultSectionSize(24)
        self.verticalHeader().hide()

        # 列宽设置
        header = self.horizontalHeader()
        header.setMinimumSectionSize(50)
        header.setStretchLastSection(True)

        # 连接信号
        self.doubleClicked.connect(self._on_double_click)
        self.clicked.connect(self._on_click)

    def _on_double_click(self, index):
        self.packet_double_clicked.emit(index.row())

    def _on_click(self, index):
        self.packet_selected.emit(index.row())

    def set_model_columns_width(self):
        """设置各列初始宽度"""
        header = self.horizontalHeader()
        # No. | Time | Source | Dest | Proto | Length | Info
        widths = [60, 90, 150, 150, 60, 60, 0]
        for i, w in enumerate(widths):
            if w > 0:
                header.resizeSection(i, w)
