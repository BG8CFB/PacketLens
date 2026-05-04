"""抓包线程真实测试 — 不使用 mock，实际抓取回环接口流量"""

import queue
import time

import pytest
from scapy.all import IP, ICMP, Ether, sendp, sr1

from app.capture.sniff_thread import SniffThread
from app.models.packet_record import PacketRecord


class TestSniffThread:
    """抓包线程真实捕获测试"""

    def test_thread_starts_and_stops(self):
        """线程能正常启动和停止"""
        capture_q = queue.Queue()
        pcap_q = queue.Queue()

        thread = SniffThread(
            iface="\\Device\\NPF_Loopback",
            capture_queue=capture_q,
            pcap_queue=pcap_q,
        )
        thread.start()
        assert thread.is_alive()
        time.sleep(0.5)
        thread.stop(timeout=5)
        assert not thread.is_alive()

    def test_captures_loopback_icmp(self):
        """在回环接口上抓取 ICMP 包"""
        capture_q = queue.Queue()
        pcap_q = queue.Queue()

        thread = SniffThread(
            iface="\\Device\\NPF_Loopback",
            capture_queue=capture_q,
            pcap_queue=pcap_q,
        )
        thread.start()
        time.sleep(0.3)

        # 发送真实 ICMP 包
        try:
            from scapy.all import send
            send(IP(src="127.0.0.1", dst="127.0.0.1") / ICMP(), verbose=0, count=3)
        except Exception:
            pass

        time.sleep(1)
        thread.stop(timeout=5)

        # 验证捕获队列有数据
        captured = []
        while not capture_q.empty():
            captured.append(capture_q.get_nowait())

        assert len(captured) > 0, "未捕获到任何包"
        assert all(isinstance(p, PacketRecord) for p in captured)

    def test_packet_count_increases(self):
        """packet_count 应随捕获包数增加"""
        capture_q = queue.Queue()
        pcap_q = queue.Queue()

        thread = SniffThread(
            iface="\\Device\\NPF_Loopback",
            capture_queue=capture_q,
            pcap_queue=pcap_q,
        )
        thread.start()
        time.sleep(0.3)

        try:
            from scapy.all import send
            send(IP(src="127.0.0.1", dst="127.0.0.1") / ICMP(), verbose=0, count=5)
        except Exception:
            pass

        time.sleep(1)
        thread.stop(timeout=5)

        assert thread.packet_count > 0

    def test_bpf_filter_blocks_traffic(self):
        """BPF 过滤器应屏蔽不匹配的流量"""
        capture_q = queue.Queue()
        pcap_q = queue.Queue()

        # 只允许 UDP
        thread = SniffThread(
            iface="\\Device\\NPF_Loopback",
            capture_queue=capture_q,
            pcap_queue=pcap_q,
            bpf_filter="udp",
        )
        thread.start()
        time.sleep(0.3)

        # 发送 ICMP（应被过滤）
        try:
            from scapy.all import send
            send(IP(src="127.0.0.1", dst="127.0.0.1") / ICMP(), verbose=0, count=3)
        except Exception:
            pass

        time.sleep(1)
        thread.stop(timeout=5)

        # 捕获的包中不应有 ICMP
        captured = []
        while not capture_q.empty():
            captured.append(capture_q.get_nowait())

        for pkt in captured:
            assert pkt.protocol != "ICMP", f"BPF 过滤失败：捕获到 ICMP 包 #{pkt.index}"

    def test_no_error_on_normal_run(self):
        """正常运行不应有错误"""
        capture_q = queue.Queue()
        pcap_q = queue.Queue()

        thread = SniffThread(
            iface="\\Device\\NPF_Loopback",
            capture_queue=capture_q,
            pcap_queue=pcap_q,
        )
        thread.start()
        time.sleep(0.5)
        thread.stop(timeout=5)

        assert thread.error_occurred is False
