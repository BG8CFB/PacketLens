"""Scapy sniff 后台线程"""

from __future__ import annotations

import logging
import queue
import threading
from typing import Callable

from app.constants import SNAPLEN
from app.models.packet_record import PacketRecord

logger = logging.getLogger(__name__)


class SniffThread(threading.Thread):
    """Scapy 抓包后台线程

    使用 store=False + prn 回调实现零内存抓包。
    解析后的 PacketRecord 放入 capture_queue 供主线程消费。
    原始字节放入 pcap_queue 供 PCAPWriter 消费。
    """

    def __init__(
        self,
        iface: str,
        capture_queue: queue.Queue[PacketRecord],
        pcap_queue: queue.Queue,
        bpf_filter: str = "",
        promisc: bool = True,
        on_error: Callable[[str], None] | None = None,
    ):
        super().__init__(daemon=True)
        self._iface = iface
        self._capture_queue = capture_queue
        self._pcap_queue = pcap_queue
        self._bpf_filter = bpf_filter
        self._promisc = promisc
        self._on_error = on_error
        self._stop_event = threading.Event()
        self._packet_index = 0
        self._dropped_count = 0  # 队列满时丢弃的包数
        self._index_lock = threading.Lock()
        self._error_occurred = False

    @property
    def error_occurred(self) -> bool:
        return self._error_occurred

    def run(self) -> None:
        """线程主循环：执行 Scapy sniff"""
        try:
            from scapy.all import sniff

            logger.info(f"开始抓包: iface={self._iface}, filter={self._bpf_filter or '(无)'}")

            sniff(
                iface=self._iface,
                filter=self._bpf_filter or None,
                prn=self._on_packet,
                store=False,
                stop_filter=self._stop_check,
                promisc=self._promisc,
            )

            logger.info("抓包线程正常结束")

        except Exception as e:
            self._error_occurred = True
            error_msg = f"抓包错误: {e}"
            logger.error(error_msg)
            if self._on_error:
                self._on_error(error_msg)

    def _on_packet(self, pkt) -> None:
        """Scapy prn 回调：解析包并放入队列

        当队列满时丢弃数据包，但 packet_index 仍递增（代表网卡实际捕获数量）。
        dropped_count 追踪因队列满而丢弃的包数，供上层了解丢包情况。

        优化：先尝试 pcap_queue，成功后再创建 PacketRecord，避免 pcap 队列满时
        浪费解析开销。
        """
        with self._index_lock:
            self._packet_index += 1
            idx = self._packet_index

        # pcap 优先策略：pcap 队列满则直接丢弃，跳过 record 创建
        try:
            self._pcap_queue.put_nowait(pkt)
        except queue.Full:
            logger.warning(f"pcap_queue 已满，丢弃数据包 #{idx}")
            with self._index_lock:
                self._dropped_count += 1
            return

        try:
            record = PacketRecord.from_scapy_packet(idx, pkt)
            try:
                self._capture_queue.put_nowait(record)
            except queue.Full:
                logger.warning(f"capture_queue 已满，丢弃数据包 #{idx}")
                with self._index_lock:
                    self._dropped_count += 1

        except Exception as e:
            logger.warning(f"解析数据包 #{idx} 失败: {e}")
            with self._index_lock:
                self._dropped_count += 1

    def _stop_check(self, _pkt) -> bool:
        """Scapy stop_filter 回调：检查停止信号"""
        return self._stop_event.is_set()

    def stop(self, timeout: float = 5.0) -> None:
        """停止抓包线程"""
        with self._index_lock:
            total = self._packet_index
            dropped = self._dropped_count
        logger.info(f"请求停止抓包，已捕获 {total} 个包（丢弃 {dropped} 个）")
        self._stop_event.set()
        self.join(timeout=timeout)
        if self.is_alive():
            logger.warning("抓包线程未能在超时内停止")

    @property
    def packet_count(self) -> int:
        """实际从网卡捕获的包数（含丢弃的）"""
        with self._index_lock:
            return self._packet_index

    @property
    def dropped_count(self) -> int:
        """因队列满而丢弃的包数"""
        with self._index_lock:
            return self._dropped_count
