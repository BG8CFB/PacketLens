"""PacketTableModel 真实测试 — 使用真实 PySide6 Qt 模型"""

import time

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from app.models.packet_record import PacketRecord
from app.ui.packet_table_model import PacketTableModel

# 确保 QApplication 存在
@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _make_packet(index=1, src="10.0.0.1", dst="10.0.0.2", protocol="TCP",
                 src_port=12345, dst_port=80, length=64, info="SYN"):
    return PacketRecord(
        index=index,
        timestamp=time.time(),
        src_ip=src,
        dst_ip=dst,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        length=length,
        info=info,
        raw_bytes=b"\x00" * length,
    )


class TestPacketTableModelBasic:
    """基本模型操作测试"""

    def test_initial_empty(self, qapp):
        """初始状态为空"""
        model = PacketTableModel()
        assert model.rowCount() == 0
        assert model.columnCount() == 7

    def test_header_data(self, qapp):
        """列标题正确"""
        model = PacketTableModel()
        expected = ["No.", "时间", "源地址", "目标地址", "协议", "长度", "信息"]
        for i, name in enumerate(expected):
            assert model.headerData(i, Qt.Horizontal) == name

    def test_add_packets(self, qapp):
        """添加包后 rowCount 增加"""
        model = PacketTableModel()
        pkts = [_make_packet(i) for i in range(1, 6)]
        model.add_packets(pkts)
        assert model.rowCount() == 5

    def test_data_display(self, qapp):
        """data() 返回正确的显示内容"""
        model = PacketTableModel()
        pkt = _make_packet(index=1, src="192.168.1.1", dst="10.0.0.1",
                           protocol="TCP", src_port=12345, dst_port=80,
                           length=128, info="SYN seq=1000")
        model.add_packets([pkt])

        # index 列
        idx = model.index(0, 0)
        assert model.data(idx, Qt.DisplayRole) == "1"

        # 源地址
        idx = model.index(0, 2)
        assert "192.168.1.1" in model.data(idx, Qt.DisplayRole)

        # 协议
        idx = model.index(0, 4)
        assert model.data(idx, Qt.DisplayRole) == "TCP"

        # 长度
        idx = model.index(0, 5)
        assert model.data(idx, Qt.DisplayRole) == "128"

        # 信息
        idx = model.index(0, 6)
        assert "SYN seq=1000" in model.data(idx, Qt.DisplayRole)

    def test_data_tooltip(self, qapp):
        """toolTip 包含完整包信息"""
        model = PacketTableModel()
        model.add_packets([_make_packet()])
        idx = model.index(0, 0)
        tip = model.data(idx, Qt.ToolTipRole)
        assert tip is not None
        assert "10.0.0.1" in tip

    def test_get_packet(self, qapp):
        """get_packet 返回正确的包"""
        model = PacketTableModel()
        pkts = [_make_packet(i, src=f"10.0.0.{i}") for i in range(1, 4)]
        model.add_packets(pkts)

        pkt = model.get_packet(1)
        assert pkt is not None
        assert pkt.src_ip == "10.0.0.2"

    def test_get_packet_out_of_range(self, qapp):
        """越界索引返回 None"""
        model = PacketTableModel()
        model.add_packets([_make_packet()])
        assert model.get_packet(99) is None

    def test_all_packets(self, qapp):
        """all_packets 返回完整列表"""
        model = PacketTableModel()
        pkts = [_make_packet(i) for i in range(1, 4)]
        model.add_packets(pkts)
        all_pkts = model.all_packets()
        assert len(all_pkts) == 3


class TestPacketTableModelClear:
    """清空操作测试"""

    def test_clear(self, qapp):
        """清空后模型为空"""
        model = PacketTableModel()
        model.add_packets([_make_packet(i) for i in range(1, 10)])
        assert model.rowCount() == 9

        model.clear()
        assert model.rowCount() == 0
        assert model.all_packets() == []


class TestPacketTableModelSort:
    """排序测试"""

    def test_sort_by_index(self, qapp):
        """按序号排序"""
        model = PacketTableModel()
        pkts = [_make_packet(i, length=100 - i) for i in [3, 1, 2]]
        model.add_packets(pkts)

        model.sort(0, Qt.AscendingOrder)
        first = model.get_packet(0)
        assert first.index == 1

    def test_sort_by_length(self, qapp):
        """按长度排序"""
        model = PacketTableModel()
        pkts = [_make_packet(i, length=100 * i) for i in [3, 1, 2]]
        model.add_packets(pkts)

        model.sort(5, Qt.AscendingOrder)
        first = model.get_packet(0)
        assert first.length == 100  # packet 1

    def test_sort_by_protocol(self, qapp):
        """按协议排序"""
        model = PacketTableModel()
        model.add_packets([
            _make_packet(1, protocol="UDP"),
            _make_packet(2, protocol="TCP"),
            _make_packet(3, protocol="ARP"),
        ])

        model.sort(4, Qt.AscendingOrder)
        first = model.get_packet(0)
        assert first.protocol == "ARP"


class TestPacketTableModelBatchAdd:
    """批量添加测试"""

    def test_batch_add_large(self, qapp):
        """批量添加大量包，无上限"""
        model = PacketTableModel()
        pkts = [_make_packet(i) for i in range(1, 10001)]
        model.add_packets(pkts)

        assert model.rowCount() == 10000

    def test_batch_add_small(self, qapp):
        """批量添加多个包"""
        model = PacketTableModel()
        pkts = [_make_packet(i) for i in range(1, 101)]
        model.add_packets(pkts)

        assert model.rowCount() == 100

    def test_total_count(self, qapp):
        """total_count 属性返回正确的总数"""
        model = PacketTableModel()
        pkts = [_make_packet(i) for i in range(1, 51)]
        model.add_packets(pkts)

        assert model.total_count == 50
