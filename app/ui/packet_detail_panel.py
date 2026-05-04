"""协议解析树 + Hex 视图面板"""

from __future__ import annotations

import logging

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QTextCharFormat, QColor
from PySide6.QtWidgets import (
    QHeaderView,
    QLabel,
    QSplitter,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.models.packet_record import PacketRecord

logger = logging.getLogger(__name__)


class PacketDetailPanel(QWidget):
    """数据包详情面板

    上方: 协议层解析树（Ethernet → IP → TCP/UDP → Payload）
    下方: Hex 视图（原始字节十六进制 + ASCII）
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        splitter = QSplitter(Qt.Vertical)

        # 协议树
        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(["字段", "值"])
        self._tree.header().setStretchLastSection(True)
        self._tree.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self._tree.setAlternatingRowColors(True)
        splitter.addWidget(self._tree)

        # Hex 视图
        self._hex_label = QLabel("选择一个数据包查看详情")
        self._hex_label.setFont(QFont("Consolas", 10))
        self._hex_label.setWordWrap(True)
        self._hex_label.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self._hex_label.setStyleSheet("padding: 8px; background-color: #11111b;")
        self._hex_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        splitter.addWidget(self._hex_label)

        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 1)

        layout.addWidget(splitter)

    def display_packet(self, packet: PacketRecord | None) -> None:
        """展示数据包的协议树和 Hex 视图"""
        self._tree.clear()

        if packet is None:
            self._hex_label.setText("选择一个数据包查看详情")
            return

        # 解析协议层
        self._parse_protocol_tree(packet)

        # 生成 Hex 视图
        self._hex_label.setText(self._format_hex(packet.raw_bytes))

    def _parse_protocol_tree(self, packet: PacketRecord) -> None:
        """从原始字节解析协议树"""
        try:
            from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP, raw

            # 重新解析原始包
            raw_bytes = packet.raw_bytes
            if not raw_bytes:
                return

            pkt = Ether(raw_bytes)

            # Ethernet 层
            eth = pkt
            eth_item = QTreeWidgetItem(self._tree, ["Ethernet II"])
            eth_item.setExpanded(True)
            self._add_field(eth_item, "源 MAC", eth.src)
            self._add_field(eth_item, "目标 MAC", eth.dst)
            self._add_field(eth_item, "类型", hex(eth.type))

            # IP 层
            if pkt.haslayer(IP):
                ip = pkt[IP]
                ip_item = QTreeWidgetItem(self._tree, ["Internet Protocol (IPv4)"])
                ip_item.setExpanded(True)
                self._add_field(ip_item, "版本", str(ip.version))
                self._add_field(ip_item, "头部长度", f"{ip.ihl * 4} bytes")
                self._add_field(ip_item, "总长度", f"{ip.len} bytes")
                self._add_field(ip_item, "TTL", str(ip.ttl))
                self._add_field(ip_item, "协议", f"{ip.proto} ({packet.protocol})")
                self._add_field(ip_item, "源地址", ip.src)
                self._add_field(ip_item, "目标地址", ip.dst)
                self._add_field(ip_item, "标识", hex(ip.id))

                # TCP 层
                if pkt.haslayer(TCP):
                    tcp = pkt[TCP]
                    tcp_item = QTreeWidgetItem(ip_item, ["Transmission Control Protocol"])
                    tcp_item.setExpanded(True)
                    self._add_field(tcp_item, "源端口", str(tcp.sport))
                    self._add_field(tcp_item, "目标端口", str(tcp.dport))
                    self._add_field(tcp_item, "序列号", str(tcp.seq))
                    self._add_field(tcp_item, "确认号", str(tcp.ack))
                    self._add_field(tcp_item, "标志", str(tcp.flags))
                    self._add_field(tcp_item, "窗口大小", str(tcp.window))
                    payload_len = len(tcp.payload) if tcp.payload else 0
                    if payload_len > 0:
                        self._add_field(tcp_item, "载荷长度", f"{payload_len} bytes")

                # UDP 层
                elif pkt.haslayer(UDP):
                    udp = pkt[UDP]
                    udp_item = QTreeWidgetItem(ip_item, ["User Datagram Protocol"])
                    udp_item.setExpanded(True)
                    self._add_field(udp_item, "源端口", str(udp.sport))
                    self._add_field(udp_item, "目标端口", str(udp.dport))
                    self._add_field(udp_item, "长度", f"{udp.len} bytes")

                # ICMP 层
                elif pkt.haslayer(ICMP):
                    icmp = pkt[ICMP]
                    icmp_item = QTreeWidgetItem(ip_item, ["Internet Control Message Protocol"])
                    icmp_item.setExpanded(True)
                    self._add_field(icmp_item, "类型", str(icmp.type))
                    self._add_field(icmp_item, "代码", str(icmp.code))
                    self._add_field(icmp_item, "校验和", hex(icmp.chksum))

            # ARP 层
            elif pkt.haslayer(ARP):
                arp = pkt[ARP]
                arp_item = QTreeWidgetItem(self._tree, ["Address Resolution Protocol"])
                arp_item.setExpanded(True)
                self._add_field(arp_item, "操作", str(arp.op))
                self._add_field(arp_item, "发送方 MAC", arp.hwsrc)
                self._add_field(arp_item, "发送方 IP", arp.psrc)
                self._add_field(arp_item, "目标 MAC", arp.hwdst)
                self._add_field(arp_item, "目标 IP", arp.pdst)

        except Exception as e:
            logger.warning(f"协议树解析失败: {e}")

    def _add_field(self, parent: QTreeWidgetItem, name: str, value: str) -> None:
        """添加字段到协议树"""
        item = QTreeWidgetItem(parent, [name, value])

    @staticmethod
    def _format_hex(data: bytes, bytes_per_line: int = 16) -> str:
        """格式化为 Hex 视图（偏移 + Hex + ASCII）"""
        if not data:
            return "无数据"

        lines = []
        for offset in range(0, len(data), bytes_per_line):
            chunk = data[offset : offset + bytes_per_line]

            # 偏移量
            hex_part = f"{offset:08x}  "

            # Hex 部分
            hex_bytes = " ".join(f"{b:02x}" for b in chunk)
            hex_part += f"{hex_bytes:<{bytes_per_line * 3}}  "

            # ASCII 部分
            ascii_part = ""
            for b in chunk:
                if 32 <= b <= 126:
                    ascii_part += chr(b)
                else:
                    ascii_part += "."

            lines.append(hex_part + ascii_part)

        return "\n".join(lines)
