"""风暴检测轻量级增量计数器

在抓包过程中实时统计各类包数量，O(1) 内存开销。
"""

from __future__ import annotations

from app.models.packet_record import PacketRecord


class StormCounter:
    """轻量级计数器 — 在 CaptureEngine._on_poll() 中增量更新"""

    def __init__(self) -> None:
        # 广播
        self.broadcast_count: int = 0
        self.broadcast_bytes: int = 0

        # 组播
        self.multicast_count: int = 0
        self.multicast_bytes: int = 0

        # ARP
        self.arp_count: int = 0
        self.arp_request: int = 0
        self.arp_reply: int = 0

        # ICMP
        self.icmp_count: int = 0
        self.icmp_echo_request: int = 0
        self.icmp_echo_reply: int = 0

    def update(self, pkt: PacketRecord) -> None:
        """处理单个包，更新对应计数器"""
        if pkt.is_broadcast:
            self.broadcast_count += 1
            self.broadcast_bytes += pkt.length

        if pkt.is_multicast:
            self.multicast_count += 1
            self.multicast_bytes += pkt.length

        if pkt.protocol == "ARP":
            self.arp_count += 1
            if pkt.arp_op == 1:
                self.arp_request += 1
            elif pkt.arp_op == 2:
                self.arp_reply += 1

        if pkt.protocol == "ICMP":
            self.icmp_count += 1
            if pkt.icmp_type == 8:
                self.icmp_echo_request += 1
            elif pkt.icmp_type == 0:
                self.icmp_echo_reply += 1

    def reset(self) -> None:
        """重置所有计数器"""
        self.__init__()
