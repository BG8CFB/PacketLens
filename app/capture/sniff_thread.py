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
        """线程主循环：执行 Scapy AsyncSniffer 并主动轮询停止信号

        改用 AsyncSniffer 替代阻塞式 sniff()，避免 stop_filter 仅在新包到达
        时才回调的限制（闲置网卡或受限 BPF 会让停止信号无法及时生效）。
        """
        sniffer = None
        try:
            from scapy.all import AsyncSniffer

            logger.info(f"开始抓包: iface={self._iface}, filter={self._bpf_filter or '(无)'}")

            sniffer = AsyncSniffer(
                iface=self._iface,
                filter=self._bpf_filter or None,
                prn=self._on_packet,
                store=False,
                promisc=self._promisc,
            )
            sniffer.start()

            # 200ms 轮询一次 stop_event；同时检查 sniffer 是否因异常自行退出
            while not self._stop_event.wait(timeout=0.2):
                # Windows libpcap 打开 iface 失败时，scapy 会把异常存到
                # sniffer.exception，但 sniffer.running 仍保持 True（不清除标志），
                # 因此必须每轮独立检查 exception，而不能仅在 not running 分支里读。
                exc = getattr(sniffer, "exception", None)
                if exc is not None:
                    raise exc
                if not sniffer.running:
                    # AsyncSniffer 已退出。先 join 内部线程清理资源，避免
                    # running=False 与 exception 赋值之间的竞争窗口。
                    try:
                        sniffer.join(timeout=1.0)
                    except Exception:
                        pass
                    exc = getattr(sniffer, "exception", None)
                    if exc is not None:
                        raise exc
                    # 未收到停止信号但 AsyncSniffer 已退出 —— 视为异常退出。
                    # 在我们的用法下不设 count/timeout，正常情况只会被 stop()
                    # 主动结束；自行退出且无异常通常意味着初始化失败被静默处理。
                    raise RuntimeError(
                        f"AsyncSniffer 意外退出 (iface={self._iface})，可能是接口不可用"
                    )

            logger.info("抓包线程正常结束")

        except Exception as e:
            self._error_occurred = True
            error_msg = f"抓包错误: {e}"
            logger.error(error_msg)
            if self._on_error:
                self._on_error(error_msg)
        finally:
            # 即使遇到异常也尝试停止 sniffer，防止网卡资源残留
            if sniffer is not None:
                try:
                    if sniffer.running:
                        sniffer.stop()
                except Exception as stop_err:
                    logger.warning(f"停止 AsyncSniffer 失败: {stop_err}")

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

    def stop(self, timeout: float = 5.0) -> bool:
        """停止抓包线程

        Returns:
            True  — 线程在超时内干净退出
            False — 线程仍存活（join 超时），调用方需决定如何处理（daemon 线程
                    会在进程退出时被 OS 回收，但当前会话内仍占用网卡）
        """
        with self._index_lock:
            total = self._packet_index
            dropped = self._dropped_count
        logger.info(f"请求停止抓包，已捕获 {total} 个包（丢弃 {dropped} 个）")
        self._stop_event.set()
        # 未启动的线程不能 join（threading.Thread.join 会抛 RuntimeError）
        # 已结束或从未启动的情况下都视为"已停止"，直接返回 True
        if not self.is_alive():
            return True
        self.join(timeout=timeout)
        if self.is_alive():
            logger.warning("抓包线程未能在超时内停止")
            return False
        return True

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
