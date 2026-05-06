"""PCAP 文件异步写入线程"""

from __future__ import annotations

import logging
import queue
import threading
from pathlib import Path

from app.constants import MAX_PCAP_FILE_SIZE_MB

logger = logging.getLogger(__name__)


class PCAPWriter(threading.Thread):
    """后台 PCAP 文件写入线程

    使用 scapy.utils.PcapWriter 流式写入，一次打开文件持续写入。
    避免了 wrpcap 批量追加时的全量读写问题。
    """

    def __init__(
        self,
        filepath: str | Path,
        write_queue: queue.Queue,
    ):
        super().__init__(daemon=True)
        self._filepath = Path(filepath)
        self._write_queue = write_queue
        self._stop_event = threading.Event()
        self._total_written = 0
        self._lock = threading.Lock()
        self._error: str | None = None

    def run(self) -> None:
        """线程主循环：从队列读取包并流式写入文件"""
        self._filepath.parent.mkdir(parents=True, exist_ok=True)
        logger.info(f"PCAP 写入线程启动: {self._filepath}")

        try:
            from scapy.utils import PcapWriter as ScapyPcapWriter

            with ScapyPcapWriter(str(self._filepath), sync=True) as writer:
                while not self._stop_event.is_set() or not self._write_queue.empty():
                    try:
                        pkt = self._write_queue.get(timeout=0.5)
                        writer.write(pkt)
                        with self._lock:
                            self._total_written += 1
                            if self._total_written % 1000 == 0:
                                try:
                                    size_mb = self._filepath.stat().st_size / (1024 * 1024)
                                    if size_mb > MAX_PCAP_FILE_SIZE_MB:
                                        logger.warning(f"PCAP 文件超过 {MAX_PCAP_FILE_SIZE_MB}MB 限制，停止写入")
                                        self._error = f"PCAP 文件超过 {MAX_PCAP_FILE_SIZE_MB}MB 限制"
                                        break
                                except OSError:
                                    pass
                    except queue.Empty:
                        continue

            logger.info(f"PCAP 写入完成: {self._total_written} 个包")

        except Exception as e:
            with self._lock:
                self._error = str(e)
            logger.error(f"PCAP 写入错误: {e}")

    @property
    def error(self) -> str | None:
        with self._lock:
            return self._error

    def stop(self, timeout: float = 10.0) -> None:
        """停止写入线程"""
        self._stop_event.set()
        self.join(timeout=timeout)
        if self.is_alive():
            logger.warning("PCAP 写入线程未能在超时内停止")

    @property
    def total_written(self) -> int:
        with self._lock:
            return self._total_written
