"""包列表视图 — QTableView 子类"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QHeaderView, QTableView


class PacketTableView(QTableView):
    """数据包列表视图

    - 交替行色
    - 行选择模式
    - 双击信号
    - 最后一列自动拉伸
    - 键盘/鼠标导航均触发 packet_selected
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
        self.setWordWrap(False)
        # 行内容较长时右侧省略，避免撑高行高影响扫描效率
        self.setTextElideMode(Qt.ElideRight)
        self.verticalHeader().setDefaultSectionSize(24)
        self.verticalHeader().hide()

        # 列宽设置
        header = self.horizontalHeader()
        header.setMinimumSectionSize(50)
        header.setStretchLastSection(True)
        self.setHorizontalScrollMode(QTableView.ScrollPerPixel)
        self.setVerticalScrollMode(QTableView.ScrollPerPixel)

        # 连接信号
        self.doubleClicked.connect(self._on_double_click)

    def setModel(self, model) -> None:
        """重写 setModel，在设置模型后连接 selectionModel 的 currentChanged 信号"""
        super().setModel(model)
        # selectionModel 在 setModel 后才可用
        sel_model = self.selectionModel()
        if sel_model is not None:
            sel_model.currentChanged.connect(self._on_current_changed)

    def _on_double_click(self, index):
        self.packet_double_clicked.emit(index.row())

    def _on_current_changed(self, current, _previous):
        """选中行变化时触发（支持键盘导航和鼠标点击）"""
        if current.isValid():
            self.packet_selected.emit(current.row())

    def set_model_columns_width(self):
        """设置各列初始宽度"""
        header = self.horizontalHeader()
        # No. | Time | Source | Dest | Proto | Length | Info
        widths = [60, 90, 150, 150, 60, 60, 0]
        for i, w in enumerate(widths):
            if w > 0:
                header.resizeSection(i, w)
