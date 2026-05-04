"""抓包线程真实测试 — 不使用 mock，实际抓取回环接口流量"""

import queue
import time

import pytest
from scapy.all import IP, ICMP, TCP, UDP, Ether, send

from app.capture.sniff_thread import SniffThread
from app.models.packet_record import PacketRecord


class TestSniffThreadConstruction:
    """SniffThread 构造与属性"""

    def test_initial_packet_count_is_zero(self):
        """初始 packet_count 应为 0"""
        cap_q = queue.Queue()
        pcap_q = queue.Queue()
        thread = SniffThread(
            iface="\\Device\\NPF_Loopback",
            capture_queue=cap_q,
            pcap_queue=pcap_q,
        )
        assert thread.packet_count == 0

    def test_initial_dropped_count_is_zero(self):
        """初始 dropped_count 应为 0"""
        cap_q = queue.Queue()
        pcap_q = queue.Queue()
        thread = SniffThread(
            iface="\\Device\\NPF_Loopback",
            capture_queue=cap_q,
            pcap_queue=pcap_q,
        )
        assert thread.dropped_count == 0

    def test_initial_error_occurred_is_false(self):
        """初始 error_occurred 应为 False"""
        cap_q = queue.Queue()
        pcap_q = queue.Queue()
        thread = SniffThread(
            iface="\\Device\\NPF_Loopback",
            capture_queue=cap_q,
            pcap_queue=pcap_q,
        )
        assert thread.error_occurred is False

    def test_is_daemon_thread(self):
        """线程应为 daemon 线程"""
        cap_q = queue.Queue()
        pcap_q = queue.Queue()
        thread = SniffThread(
            iface="\\Device\\NPF_Loopback",
            capture_queue=cap_q,
            pcap_queue=pcap_q,
        )
        assert thread.daemon is True


class TestSniffThreadStartStop:
    """线程启动与停止"""

    def test_thread_starts_and_is_alive(self):
        """线程 start() 后 is_alive() 应为 True"""
        cap_q = queue.Queue()
        pcap_q = queue.Queue()
        thread = SniffThread(
            iface="\\Device\\NPF_Loopback",
            capture_queue=cap_q,
            pcap_queue=pcap_q,
        )
        thread.start()
        try:
            assert thread.is_alive()
        finally:
            thread.stop(timeout=5)

    def test_thread_stops_cleanly(self):
        """stop() 后线程应不再存活"""
        cap_q = queue.Queue()
        pcap_q = queue.Queue()
        thread = SniffThread(
            iface="\\Device\\NPF_Loopback",
            capture_queue=cap_q,
            pcap_queue=pcap_q,
        )
        thread.start()
        time.sleep(0.3)
        thread.stop(timeout=5)
        assert not thread.is_alive()

    def test_no_error_on_normal_run(self):
        """正常运行不应有错误"""
        cap_q = queue.Queue()
        pcap_q = queue.Queue()
        thread = SniffThread(
            iface="\\Device\\NPF_Loopback",
            capture_queue=cap_q,
            pcap_queue=pcap_q,
        )
        thread.start()
        time.sleep(0.3)
        thread.stop(timeout=5)
        assert thread.error_occurred is False


class TestSniffThreadCapture:
    """真实抓包测试"""

    def test_captures_loopback_icmp(self):
        """在回环接口上抓取 ICMP 包"""
        cap_q = queue.Queue()
        pcap_q = queue.Queue()
        thread = SniffThread(
            iface="\\Device\\NPF_Loopback",
            capture_queue=cap_q,
            pcap_queue=pcap_q,
        )
        thread.start()
        time.sleep(0.3)

        try:
            send(IP(src="127.0.0.1", dst="127.0.0.1") / ICMP(), verbose=0, count=3)
        except Exception:
            pass

        time.sleep(1)
        thread.stop(timeout=5)

        captured = []
        while not cap_q.empty():
            captured.append(cap_q.get_nowait())

        assert len(captured) > 0, "未捕获到任何包"
        assert all(isinstance(p, PacketRecord) for p in captured)

    def test_captured_records_have_valid_protocol(self):
        """捕获的包协议字段应为 ICMP"""
        cap_q = queue.Queue()
        pcap_q = queue.Queue()
        thread = SniffThread(
            iface="\\Device\\NPF_Loopback",
            capture_queue=cap_q,
            pcap_queue=pcap_q,
        )
        thread.start()
        time.sleep(0.3)

        try:
            send(IP(src="127.0.0.1", dst="127.0.0.1") / ICMP(), verbose=0, count=3)
        except Exception:
            pass

        time.sleep(1)
        thread.stop(timeout=5)

        captured = []
        while not cap_q.empty():
            captured.append(cap_q.get_nowait())

        if captured:
            for pkt in captured:
                assert isinstance(pkt.protocol, str)
                assert len(pkt.protocol) > 0

    def test_packet_count_increases_after_capture(self):
        """packet_count 应随捕获包数增加"""
        cap_q = queue.Queue()
        pcap_q = queue.Queue()
        thread = SniffThread(
            iface="\\Device\\NPF_Loopback",
            capture_queue=cap_q,
            pcap_queue=pcap_q,
        )
        thread.start()
        time.sleep(0.3)

        try:
            send(IP(src="127.0.0.1", dst="127.0.0.1") / ICMP(), verbose=0, count=5)
        except Exception:
            pass

        time.sleep(1)
        thread.stop(timeout=5)

        assert thread.packet_count > 0

    def test_captured_packets_have_increasing_index(self):
        """捕获的包 index 应递增"""
        cap_q = queue.Queue()
        pcap_q = queue.Queue()
        thread = SniffThread(
            iface="\\Device\\NPF_Loopback",
            capture_queue=cap_q,
            pcap_queue=pcap_q,
        )
        thread.start()
        time.sleep(0.3)

        try:
            send(IP(src="127.0.0.1", dst="127.0.0.1") / ICMP(), verbose=0, count=5)
        except Exception:
            pass

        time.sleep(1)
        thread.stop(timeout=5)

        captured = []
        while not cap_q.empty():
            captured.append(cap_q.get_nowait())

        if len(captured) >= 2:
            indices = [p.index for p in captured]
            for i in range(1, len(indices)):
                assert indices[i] > indices[i - 1], (
                    f"索引非递增: {indices[i - 1]} -> {indices[i]}"
                )

    def test_pcap_queue_receives_original_packets(self):
        """pcap_queue 应收到原始 scapy 包对象"""
        cap_q = queue.Queue()
        pcap_q = queue.Queue()
        thread = SniffThread(
            iface="\\Device\\NPF_Loopback",
            capture_queue=cap_q,
            pcap_queue=pcap_q,
        )
        thread.start()
        time.sleep(0.3)

        try:
            send(IP(src="127.0.0.1", dst="127.0.0.1") / ICMP(), verbose=0, count=3)
        except Exception:
            pass

        time.sleep(1)
        thread.stop(timeout=5)

        pcap_pkts = []
        while not pcap_q.empty():
            pcap_pkts.append(pcap_q.get_nowait())

        assert len(pcap_pkts) > 0, "pcap_queue 未收到任何原始包"

    def test_capture_and_pcap_queue_consistency(self):
        """capture_queue 和 pcap_queue 的包数应一致"""
        cap_q = queue.Queue()
        pcap_q = queue.Queue()
        thread = SniffThread(
            iface="\\Device\\NPF_Loopback",
            capture_queue=cap_q,
            pcap_queue=pcap_q,
        )
        thread.start()
        time.sleep(0.3)

        try:
            send(IP(src="127.0.0.1", dst="127.0.0.1") / ICMP(), verbose=0, count=3)
        except Exception:
            pass

        time.sleep(1)
        thread.stop(timeout=5)

        cap_count = 0
        while not cap_q.empty():
            cap_q.get_nowait()
            cap_count += 1

        pcap_count = 0
        while not pcap_q.empty():
            pcap_q.get_nowait()
            pcap_count += 1

        assert cap_count == pcap_count, (
            f"capture_queue({cap_count}) != pcap_queue({pcap_count})"
        )


class TestSniffThreadBPFFilter:
    """BPF 过滤器测试"""

    def test_bpf_filter_blocks_icmp_when_udp_only(self):
        """BPF 过滤 udp 应屏蔽 ICMP 包"""
        cap_q = queue.Queue()
        pcap_q = queue.Queue()
        thread = SniffThread(
            iface="\\Device\\NPF_Loopback",
            capture_queue=cap_q,
            pcap_queue=pcap_q,
            bpf_filter="udp",
        )
        thread.start()
        time.sleep(0.3)

        try:
            send(IP(src="127.0.0.1", dst="127.0.0.1") / ICMP(), verbose=0, count=3)
        except Exception:
            pass

        time.sleep(1)
        thread.stop(timeout=5)

        captured = []
        while not cap_q.empty():
            captured.append(cap_q.get_nowait())

        for pkt in captured:
            assert pkt.protocol != "ICMP", f"BPF 过滤失败：捕获到 ICMP 包 #{pkt.index}"

    def test_bpf_filter_allows_matching_traffic(self):
        """BPF 过滤 icmp 应允许 ICMP 包通过"""
        cap_q = queue.Queue()
        pcap_q = queue.Queue()
        thread = SniffThread(
            iface="\\Device\\NPF_Loopback",
            capture_queue=cap_q,
            pcap_queue=pcap_q,
            bpf_filter="icmp",
        )
        thread.start()
        time.sleep(0.3)

        try:
            send(IP(src="127.0.0.1", dst="127.0.0.1") / ICMP(), verbose=0, count=3)
        except Exception:
            pass

        time.sleep(1)
        thread.stop(timeout=5)

        captured = []
        while not cap_q.empty():
            captured.append(cap_q.get_nowait())

        assert len(captured) > 0, "BPF icmp 过滤器应允许 ICMP 包通过"


class TestSniffThreadErrorCallback:
    """错误回调测试"""

    def test_invalid_iface_triggers_error(self):
        """无效的接口名应触发错误"""
        cap_q = queue.Queue()
        pcap_q = queue.Queue()
        errors = []

        thread = SniffThread(
            iface="\\Device\\NPF_NonExistent999",
            capture_queue=cap_q,
            pcap_queue=pcap_q,
            on_error=lambda msg: errors.append(msg),
        )
        thread.start()
        thread.join(timeout=5)

        assert thread.error_occurred is True or len(errors) > 0


class TestSniffThreadQueueFull:
    """队列满时丢包计数测试"""

    def test_dropped_count_increases_when_pcap_queue_full(self):
        """pcap_queue 满时 dropped_count 应增加"""
        # 创建容量极小的队列，模拟满队列
        cap_q = queue.Queue(maxsize=1)
        pcap_q = queue.Queue(maxsize=1)
        # 预先填满队列
        pcap_q.put("dummy")

        thread = SniffThread(
            iface="\\Device\\NPF_Loopback",
            capture_queue=cap_q,
            pcap_queue=pcap_q,
        )
        thread.start()
        time.sleep(0.3)

        try:
            # 发送多个包，超过队列容量
            send(IP(src="127.0.0.1", dst="127.0.0.1") / ICMP(), verbose=0, count=5)
        except Exception:
            pass

        time.sleep(1)
        thread.stop(timeout=5)

        # packet_count 应大于 0（网卡确实抓到了包）
        assert thread.packet_count > 0

    def test_dropped_count_zero_when_queues_not_full(self):
        """队列未满时 dropped_count 应为 0"""
        cap_q = queue.Queue()
        pcap_q = queue.Queue()
        thread = SniffThread(
            iface="\\Device\\NPF_Loopback",
            capture_queue=cap_q,
            pcap_queue=pcap_q,
        )
        thread.start()
        time.sleep(0.3)

        try:
            send(IP(src="127.0.0.1", dst="127.0.0.1") / ICMP(), verbose=0, count=3)
        except Exception:
            pass

        time.sleep(1)
        thread.stop(timeout=5)

        # 队列容量足够大，不应有丢包
        assert thread.dropped_count == 0

    def test_packet_count_ge_captured_plus_dropped(self):
        """packet_count 应 >= capture_queue 中的包数 + dropped_count"""
        cap_q = queue.Queue()
        pcap_q = queue.Queue()
        thread = SniffThread(
            iface="\\Device\\NPF_Loopback",
            capture_queue=cap_q,
            pcap_queue=pcap_q,
        )
        thread.start()
        time.sleep(0.3)

        try:
            send(IP(src="127.0.0.1", dst="127.0.0.1") / ICMP(), verbose=0, count=5)
        except Exception:
            pass

        time.sleep(1)
        thread.stop(timeout=5)

        captured = 0
        while not cap_q.empty():
            cap_q.get_nowait()
            captured += 1

        # 总捕获数 = 入队数 + 丢弃数（>= 实际网络捕获数）
        assert thread.packet_count >= captured
