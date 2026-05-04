"""包列表 Table Model — QAbstractTableModel + 无限制列表"""

from __future__ import annotations

import time
from datetime import datetime

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QColor

from app.constants import PROTOCOL_COLORS
from app.models.packet_record import PacketRecord


class PacketTableModel(QAbstractTableModel):
    """数据包列表模型

    使用普通 list 存储，无数量上限。
    QTableView 懒渲染机制保证 UI 性能（只绘制可见行）。
    所有模型操作必须在主线程执行（由 QTimer 轮询保证）。
    """

    COLUMNS = ["No.", "时间", "源地址", "目标地址", "协议", "长度", "信息"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._packets: list[PacketRecord] = []
        self._sort_column = -1
        self._sort_order = Qt.AscendingOrder

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._packets)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(self.COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.COLUMNS[section]
        return None

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid() or role not in (Qt.DisplayRole, Qt.ToolTipRole, Qt.TextAlignmentRole, Qt.ForegroundRole):
            return None

        row = index.row()
        if row < 0 or row >= len(self._packets):
            return None

        pkt = self._packets[row]
        col = index.column()

        if role == Qt.TextAlignmentRole:
            if col == 5:
                return Qt.AlignRight | Qt.AlignVCenter
            return Qt.AlignLeft | Qt.AlignVCenter

        if role == Qt.ForegroundRole:
            if col == 4:
                color = PROTOCOL_COLORS.get(pkt.protocol, "#CCCCCC")
                return QColor(color)
            return None

        if role == Qt.ToolTipRole:
            return f"#{pkt.index} {pkt.src_ip}:{pkt.src_port or ''} → {pkt.dst_ip}:{pkt.dst_port or ''} [{pkt.protocol}] {pkt.info}"

        # DisplayRole
        if col == 0:
            return str(pkt.index)
        elif col == 1:
            return _format_timestamp(pkt.timestamp)
        elif col == 2:
            return _format_endpoint(pkt.src_ip, pkt.src_port)
        elif col == 3:
            return _format_endpoint(pkt.dst_ip, pkt.dst_port)
        elif col == 4:
            return pkt.protocol
        elif col == 5:
            return str(pkt.length)
        elif col == 6:
            return pkt.info

        return None

    def add_packets(self, packets: list[PacketRecord]) -> None:
        """批量添加数据包（仅从主线程调用）"""
        if not packets:
            return

        start = len(self._packets)
        self.beginInsertRows(QModelIndex(), start, start + len(packets) - 1)
        self._packets.extend(packets)
        self.endInsertRows()

    def clear(self) -> None:
        """清空所有数据"""
        self.beginResetModel()
        self._packets.clear()
        self.endResetModel()

    def get_packet(self, row: int) -> PacketRecord | None:
        """获取指定行的数据包"""
        if 0 <= row < len(self._packets):
            return self._packets[row]
        return None

    def all_packets(self) -> list[PacketRecord]:
        """返回所有包的列表"""
        return list(self._packets)

    def sort(self, column: int, order=Qt.AscendingOrder) -> None:
        """排序"""
        self._sort_column = column
        self._sort_order = order

        if column < 0:
            return

        self.layoutAboutToBeChanged.emit()
        reverse = order == Qt.DescendingOrder

        key_funcs = {
            0: lambda p: p.index,
            1: lambda p: p.timestamp,
            2: lambda p: p.src_ip,
            3: lambda p: p.dst_ip,
            4: lambda p: p.protocol,
            5: lambda p: p.length,
            6: lambda p: p.info,
        }

        key_func = key_funcs.get(column, lambda p: p.index)
        self._packets.sort(key=key_func, reverse=reverse)
        self.layoutChanged.emit()

    @property
    def total_count(self) -> int:
        """返回总包数"""
        return len(self._packets)


def _format_timestamp(ts: float) -> str:
    """格式化时间戳为 HH:MM:SS.mmm"""
    dt = datetime.fromtimestamp(ts)
    return dt.strftime("%H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


def _format_endpoint(ip: str, port: int | None) -> str:
    """格式化端点地址"""
    if port is not None:
        return f"{ip}:{port}"
    return ip
