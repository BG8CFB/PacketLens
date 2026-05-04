"""PCAP 文件真实读写测试 — 不使用 mock，实际写文件再用 scapy 读回验证"""

import queue
import time
from pathlib import Path

import pytest
from scapy.all import Ether, IP, TCP, UDP, ICMP, wrpcap, rdpcap

from app.capture.pcap_writer import PCAPWriter


# 显式指定 MAC 地址，避免 scapy 触发 ARP 解析导致超时
_ETH_SRC = "00:11:22:33:44:55"
_ETH_DST = "66:77:88:99:aa:bb"


def _make_tcp_pkt(src="10.0.0.1", dst="10.0.0.2", sport=12345, dport=80):
    return Ether(src=_ETH_SRC, dst=_ETH_DST) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S")


def _make_udp_pkt(src="10.0.0.1", dst="8.8.8.8", sport=54321, dport=53):
    return Ether(src=_ETH_SRC, dst=_ETH_DST) / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)


def _drain_and_stop(writer, write_queue, timeout=15):
    """等待队列排空后停止写入线程"""
    deadline = time.monotonic() + timeout
    while not write_queue.empty() and time.monotonic() < deadline:
        time.sleep(0.1)
    writer.stop(timeout=timeout)


class TestPCAPWriter:
    """PCAP 文件写入线程真实测试"""

    def test_write_single_packet(self, tmp_path):
        """写入 1 个包并读回验证"""
        pcap_file = tmp_path / "test_one.pcap"
        q = queue.Queue()
        writer = PCAPWriter(pcap_file, q)

        pkt = _make_tcp_pkt()
        q.put(pkt)

        writer.start()
        _drain_and_stop(writer, q)

        assert pcap_file.exists()
        assert pcap_file.stat().st_size > 0

        read_pkts = rdpcap(str(pcap_file))
        assert len(read_pkts) == 1
        assert read_pkts[0][IP].src == "10.0.0.1"
        assert read_pkts[0][TCP].dport == 80

    def test_write_multiple_packets(self, tmp_path):
        """写入 50 个包并读回验证数量"""
        pcap_file = tmp_path / "test_multi.pcap"
        q = queue.Queue()
        writer = PCAPWriter(pcap_file, q)

        count = 50
        for i in range(count):
            pkt = _make_tcp_pkt(sport=40000 + i, dport=80 + (i % 10))
            q.put(pkt)

        writer.start()
        _drain_and_stop(writer, q)

        assert pcap_file.exists()
        read_pkts = rdpcap(str(pcap_file))
        assert len(read_pkts) == count

    def test_write_mixed_protocols(self, tmp_path):
        """写入 TCP + UDP + ICMP 混合包"""
        pcap_file = tmp_path / "test_mixed.pcap"
        q = queue.Queue()
        writer = PCAPWriter(pcap_file, q)

        q.put(_make_tcp_pkt())
        q.put(_make_udp_pkt())
        q.put(Ether(src=_ETH_SRC, dst=_ETH_DST) / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP())

        writer.start()
        _drain_and_stop(writer, q)

        read_pkts = rdpcap(str(pcap_file))
        assert len(read_pkts) == 3
        protocols = {pkt[IP].proto for pkt in read_pkts}
        assert 6 in protocols   # TCP
        assert 17 in protocols  # UDP
        assert 1 in protocols   # ICMP

    def test_writer_handles_empty_queue(self, tmp_path):
        """队列为空时正常停止，不崩溃且计数器为 0"""
        pcap_file = tmp_path / "test_empty.pcap"
        q = queue.Queue()
        writer = PCAPWriter(pcap_file, q)

        writer.start()
        writer.stop(timeout=5)

        # 验证：不崩溃、计数器为 0、无错误
        assert writer.total_written == 0
        assert writer.error is None
        # 文件可能被创建但为空 PCAP 头（24 字节），或因无包而未写入
        if pcap_file.exists():
            # 即使创建了文件，也应是空的 PCAP（无数据包记录）
            read_pkts = rdpcap(str(pcap_file))
            assert len(read_pkts) == 0

    def test_total_written_counter(self, tmp_path):
        """验证 total_written 计数正确"""
        pcap_file = tmp_path / "test_counter.pcap"
        q = queue.Queue()
        writer = PCAPWriter(pcap_file, q)

        for i in range(25):
            q.put(_make_tcp_pkt(sport=40000 + i))

        writer.start()
        _drain_and_stop(writer, q)

        assert writer.total_written == 25
