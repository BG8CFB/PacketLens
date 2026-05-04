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
        """Scapy prn 回调：解析包并放入队列"""
        with self._index_lock:
            self._packet_index += 1
            idx = self._packet_index

        try:
            record = PacketRecord.from_scapy_packet(idx, pkt)
            # pcap 优先策略：pcap 失败则 capture 也跳过，保持一致性
            pcap_ok = True
            try:
                self._pcap_queue.put_nowait(pkt)
            except queue.Full:
                logger.warning(f"pcap_queue 已满，丢弃数据包 #{idx}")
                pcap_ok = False

            if pcap_ok:
                try:
                    self._capture_queue.put_nowait(record)
                except queue.Full:
                    logger.warning(f"capture_queue 已满，丢弃数据包 #{idx}")
        except Exception as e:
            logger.warning(f"解析数据包 #{idx} 失败: {e}")

    def _stop_check(self, _pkt) -> bool:
        """Scapy stop_filter 回调：检查停止信号"""
        return self._stop_event.is_set()

    def stop(self, timeout: float = 5.0) -> None:
        """停止抓包线程"""
        logger.info(f"请求停止抓包，已捕获 {self._packet_index} 个包")
        self._stop_event.set()
        self.join(timeout=timeout)
        if self.is_alive():
            logger.warning("抓包线程未能在超时内停止")

    @property
    def packet_count(self) -> int:
        with self._index_lock:
            return self._packet_index
