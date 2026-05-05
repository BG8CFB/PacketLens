"""流列表 Table Model"""

from __future__ import annotations

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt

from app.models.flow_record import FlowRecord


class FlowTableModel(QAbstractTableModel):
    """流聚合列表模型"""

    COLUMNS = [
        "源地址", "目标地址", "源端口", "目标端口",
        "协议", "包数", "字节", "时长(s)", "服务",
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._flows: list[FlowRecord] = []

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._flows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(self.COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.COLUMNS[section]
        return None

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid() or role not in (Qt.DisplayRole, Qt.ToolTipRole):
            return None

        row = index.row()
        if row < 0 or row >= len(self._flows):
            return None

        flow = self._flows[row]
        col = index.column()

        if col == 0:
            return flow.src_ip
        elif col == 1:
            return flow.dst_ip
        elif col == 2:
            return str(flow.src_port)
        elif col == 3:
            return str(flow.dst_port)
        elif col == 4:
            return flow.protocol
        elif col == 5:
            return str(flow.packet_count)
        elif col == 6:
            return _format_bytes(flow.byte_count)
        elif col == 7:
            return f"{flow.duration:.1f}"
        elif col == 8:
            return flow.service or "-"

        return None

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid():
            return None

        if role == Qt.TextAlignmentRole:
            col = index.column()
            if col in (2, 3, 5, 6, 7):
                return Qt.AlignRight | Qt.AlignVCenter
            return Qt.AlignLeft | Qt.AlignVCenter

        if role not in (Qt.DisplayRole, Qt.ToolTipRole):
            return None

        row = index.row()
        if row < 0 or row >= len(self._flows):
            return None

        flow = self._flows[row]
        col = index.column()

        if col == 0:
            return flow.src_ip
        elif col == 1:
            return flow.dst_ip
        elif col == 2:
            return str(flow.src_port)
        elif col == 3:
            return str(flow.dst_port)
        elif col == 4:
            return flow.protocol
        elif col == 5:
            return str(flow.packet_count)
        elif col == 6:
            return _format_bytes(flow.byte_count)
        elif col == 7:
            return f"{flow.duration:.1f}"
        elif col == 8:
            return flow.service or "-"

        return None

    def sort(self, column: int, order=Qt.AscendingOrder) -> None:
        """排序"""
        if column < 0:
            return

        self.layoutAboutToBeChanged.emit()
        reverse = order == Qt.DescendingOrder

        key_funcs = {
            0: lambda f: f.src_ip,
            1: lambda f: f.dst_ip,
            2: lambda f: f.src_port,
            3: lambda f: f.dst_port,
            4: lambda f: f.protocol,
            5: lambda f: f.packet_count,
            6: lambda f: f.byte_count,
            7: lambda f: f.duration,
            8: lambda f: f.service or "",
        }

        key_func = key_funcs.get(column, lambda f: f.packet_count)
        self._flows.sort(key=key_func, reverse=reverse)
        self.layoutChanged.emit()

    def set_flows(self, flows: list[FlowRecord]) -> None:
        """设置流数据"""
        self.beginResetModel()
        self._flows = list(flows)
        self.endResetModel()

    def get_flow(self, row: int) -> FlowRecord | None:
        if 0 <= row < len(self._flows):
            return self._flows[row]
        return None

    def clear(self) -> None:
        self.beginResetModel()
        self._flows = []
        self.endResetModel()


def _format_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    elif n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    else:
        return f"{n / 1024 / 1024:.1f} MB"
