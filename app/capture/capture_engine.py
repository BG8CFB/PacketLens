"""抓包编排器 — 串联 sniff + pcap + model 的核心控制器"""

from __future__ import annotations

import logging
import queue
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Callable

from PySide6.QtCore import QObject, QTimer, Signal

from app.constants import CAPTURE_POLL_INTERVAL_MS, DEFAULT_CAPTURE_DURATION
from app.capture.sniff_thread import SniffThread
from app.capture.pcap_writer import PCAPWriter
from app.models.packet_record import PacketRecord
from app.preprocessing.flow_aggregator import FlowAggregator
from app.preprocessing.stats_computer import StatsComputer
from app.preprocessing.anomaly_marker import AnomalyMarker
from app.ui.packet_table_model import PacketTableModel
from app.utils.path_helpers import get_captures_dir

logger = logging.getLogger(__name__)


class CaptureSignals(QObject):
    """Qt 信号桥接（因 CaptureEngine 非 QObject）"""

    capture_started = Signal()
    capture_stopped = Signal(int)  # 总包数
    packet_captured = Signal(int)  # 当前包数
    capture_error = Signal(str)
    preprocessing_done = Signal(dict)  # 统计结果
    _stop_requested = Signal()  # 内部：跨线程停止请求


class CaptureEngine:
    """抓包引擎编排器

    管理 SniffThread、PCAPWriter、PacketTableModel 之间的协作。
    使用 QTimer 轮询 capture_queue 驱动模型更新。
    抓包停止后自动执行预处理（流聚合 + 统计 + 异常检测）。
    """

    def __init__(self, table_model: PacketTableModel):
        self._model = table_model
        self._signals = CaptureSignals()

        self._sniff_thread: SniffThread | None = None
        self._pcap_writer: PCAPWriter | None = None
        self._capture_queue: queue.Queue[PacketRecord] = queue.Queue(maxsize=50000)
        self._pcap_queue: queue.Queue = queue.Queue(maxsize=50000)

        self._poll_timer = QTimer()
        self._poll_timer.setInterval(CAPTURE_POLL_INTERVAL_MS)
        self._poll_timer.timeout.connect(self._on_poll)

        self._duration_timer = QTimer()
        self._duration_timer.setSingleShot(True)
        self._duration_timer.timeout.connect(self.stop_capture)

        # 跨线程安全：工作线程通过信号请求主线程执行 stop_capture
        self._signals._stop_requested.connect(self.stop_capture)

        # 预处理组件
        self._flow_aggregator = FlowAggregator()
        self._stats_computer = StatsComputer()
        self._anomaly_marker = AnomalyMarker()

        self._stop_lock = threading.Lock()
        self._capture_active = threading.Event()
        self._start_time: datetime | None = None
        self._pcap_path: str | None = None
        self._total_captured = 0
        self._on_capture_complete: Callable | None = None

        # 增量统计计数器（不受环形缓冲区淘汰影响）
        self._running_proto_dist: Counter = Counter()
        self._running_src_counter: Counter = Counter()
        self._running_dst_counter: Counter = Counter()
        self._running_total_packets: int = 0
        self._running_total_bytes: int = 0
        self._running_first_ts: float | None = None
        self._running_last_ts: float | None = None

        # 预处理结果
        self._flows = []
        self._stats: dict = {}
        self._anomalies: list[dict] = []

        # 异步预处理
        self._preprocess_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="preprocess")
        self._preprocess_timer: QTimer | None = None

    @property
    def signals(self) -> CaptureSignals:
        return self._signals

    @property
    def is_capturing(self) -> bool:
        return self._capture_active.is_set()

    @property
    def total_captured(self) -> int:
        return self._total_captured

    @property
    def start_time(self) -> datetime | None:
        return self._start_time

    @property
    def pcap_path(self) -> str | None:
        return self._pcap_path

    @property
    def elapsed_seconds(self) -> float:
        if self._start_time is None:
            return 0.0
        return (datetime.now() - self._start_time).total_seconds()

    @property
    def flows(self) -> list:
        return self._flows

    @property
    def stats(self) -> dict:
        return self._stats

    @property
    def anomalies(self) -> list[dict]:
        return self._anomalies

    def start_capture(
        self,
        iface: str,
        bpf_filter: str = "",
        duration: int = DEFAULT_CAPTURE_DURATION,
        promisc: bool = True,
        on_complete: Callable | None = None,
    ) -> bool:
        """开始抓包"""
        if self._capture_active.is_set():
            logger.warning("已在抓包中，忽略重复启动请求")
            return False

        self._on_capture_complete = on_complete
        self._total_captured = 0
        self._start_time = datetime.now()
        self._model.clear()
        self._flow_aggregator.reset()
        self._flows = []
        self._stats = {}
        self._anomalies = []

        # 重置增量统计
        self._running_proto_dist = Counter()
        self._running_src_counter = Counter()
        self._running_dst_counter = Counter()
        self._running_total_packets = 0
        self._running_total_bytes = 0
        self._running_first_ts = None
        self._running_last_ts = None

        # 生成 PCAP 文件路径
        timestamp = self._start_time.strftime("%Y%m%d_%H%M%S")
        pcap_dir = get_captures_dir()
        self._pcap_path = str(pcap_dir / f"capture_{timestamp}.pcap")

        # 清空队列
        while not self._capture_queue.empty():
            self._capture_queue.get_nowait()
        while not self._pcap_queue.empty():
            self._pcap_queue.get_nowait()

        # 启动 PCAP 写入线程
        self._pcap_writer = PCAPWriter(self._pcap_path, self._pcap_queue)
        self._pcap_writer.start()

        # 启动抓包线程
        self._sniff_thread = SniffThread(
            iface=iface,
            capture_queue=self._capture_queue,
            pcap_queue=self._pcap_queue,
            bpf_filter=bpf_filter,
            promisc=promisc,
            on_error=self._on_sniff_error,
        )
        self._sniff_thread.start()

        # 启动轮询定时器
        self._poll_timer.start()

        # 启动时长定时器
        if duration > 0:
            self._duration_timer.start(duration * 1000)

        self._capture_active.set()
        self._signals.capture_started.emit()
        logger.info(f"抓包已启动: iface={iface}, duration={duration}s, filter={bpf_filter or '(无)'}")
        return True

    def stop_capture(self) -> None:
        """停止抓包（线程安全，仅主线程执行）"""
        # 非阻塞锁：如果已在停止过程中，直接返回
        if not self._stop_lock.acquire(blocking=False):
            return
        try:
            if not self._capture_active.is_set():
                return

            self._capture_active.clear()
            self._poll_timer.stop()
            self._duration_timer.stop()

            # 停止抓包线程
            dropped = 0
            if self._sniff_thread:
                self._sniff_thread.stop(timeout=5.0)
                dropped = self._sniff_thread.dropped_count
                self._sniff_thread = None

            # 最后一次轮询，确保所有包被处理
            self._on_poll()

            # 停止 PCAP 写入线程
            if self._pcap_writer:
                self._pcap_writer.stop(timeout=10.0)
                if self._pcap_writer.error:
                    logger.error(f"PCAP 写入出现错误: {self._pcap_writer.error}")
                    self._signals.capture_error.emit(
                        f"PCAP 写入错误: {self._pcap_writer.error}"
                    )
                else:
                    written = self._pcap_writer.total_written
                    logger.info(f"PCAP 文件写入: {written} 个包 → {self._pcap_path}")
                self._pcap_writer = None

            # 丢包警告
            if dropped > 0:
                logger.warning(f"抓包过程中因队列满丢弃 {dropped} 个包")

            # 异步执行预处理（避免阻塞主线程）
            future = self._preprocess_executor.submit(self._run_preprocessing)

            self._preprocess_timer = QTimer()
            self._preprocess_timer.setInterval(50)

            def _on_preprocess_done():
                self._preprocess_timer.stop()
                self._preprocess_timer = None
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"预处理失败: {e}")
                self._signals.capture_stopped.emit(self._total_captured)
                logger.info(f"抓包已停止，共 {self._total_captured} 个包（丢弃 {dropped} 个）")
                if self._on_capture_complete:
                    self._on_capture_complete()

            self._preprocess_timer.timeout.connect(_on_preprocess_done)
            self._preprocess_timer.start()
        finally:
            self._stop_lock.release()

    def _on_poll(self) -> None:
        """QTimer 轮询回调：从 capture_queue 批量取出包并更新模型和流聚合

        单次轮询最多处理 POLL_BATCH_SIZE 个包，防止队列积压时阻塞主线程。
        """
        batch: list[PacketRecord] = []
        max_batch = 1000  # 单次轮询批量上限，防止主线程卡顿
        while len(batch) < max_batch:
            try:
                pkt = self._capture_queue.get_nowait()
                batch.append(pkt)
            except queue.Empty:
                break

        if batch:
            self._model.add_packets(batch)
            self._flow_aggregator.update_batch(batch)
            self._total_captured += len(batch)
            self._signals.packet_captured.emit(self._total_captured)

            # 增量更新全局统计（不受环形缓冲区淘汰影响）
            for pkt in batch:
                self._running_proto_dist[pkt.protocol] += 1
                if pkt.src_ip:
                    self._running_src_counter[pkt.src_ip] += 1
                if pkt.dst_ip:
                    self._running_dst_counter[pkt.dst_ip] += 1
                self._running_total_packets += 1
                self._running_total_bytes += pkt.length
                if self._running_first_ts is None:
                    self._running_first_ts = pkt.timestamp
                self._running_last_ts = pkt.timestamp

    def _run_preprocessing(self) -> None:
        """执行批量预处理（抓包停止后）"""
        self._flows = self._flow_aggregator.get_flows()

        # 使用增量统计而非环形缓冲区（修复 >5000 包时数据不一致）
        self._stats = self._stats_computer.compute_from_counters(
            flows=self._flows,
            protocol_dist=self._running_proto_dist,
            src_counter=self._running_src_counter,
            dst_counter=self._running_dst_counter,
            total_packets=self._running_total_packets,
            total_bytes=self._running_total_bytes,
            first_ts=self._running_first_ts,
            last_ts=self._running_last_ts,
        )
        self._anomalies = self._anomaly_marker.mark(self._flows)

        logger.info(
            f"预处理完成: {len(self._flows)} 条流, "
            f"{self._stats.get('total_packets', 0)} 包, "
            f"{len(self._anomalies)} 个异常"
        )

        self._signals.preprocessing_done.emit(self._stats)

    def _on_sniff_error(self, error_msg: str) -> None:
        """抓包线程错误回调 — 通过信号转发到主线程执行 stop_capture"""
        self._signals.capture_error.emit(error_msg)
        if self._capture_active.is_set():
            self._signals._stop_requested.emit()

    def cleanup(self) -> None:
        """清理资源，关闭线程池"""
        if self._capture_active.is_set():
            self.stop_capture()
        # 等待预处理完成后再关闭线程池，避免丢失预处理结果
        self._preprocess_executor.shutdown(wait=True)
