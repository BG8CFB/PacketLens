"""FlowAggregator 单元测试"""

import threading
import time

from app.models.packet_record import PacketRecord
from app.preprocessing.flow_aggregator import FlowAggregator, TCP_FLOW_TIMEOUT


def _make_pkt(index, src_ip, dst_ip, src_port, dst_port, protocol, length, timestamp,
              flags=None, raw_bytes=None, tcp_seq=None, tcp_ack=None, tcp_window=None):
    """辅助函数：快速创建 PacketRecord"""
    return PacketRecord(
        index=index, timestamp=timestamp,
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        protocol=protocol, length=length,
        info="", raw_bytes=raw_bytes or b"\x00" * length,
        flags=flags, tcp_seq=tcp_seq, tcp_ack=tcp_ack, tcp_window=tcp_window,
    )


class TestFlowAggregator:

    def test_empty_aggregator(self):
        agg = FlowAggregator()
        assert agg.get_flow_count() == 0
        assert agg.get_total_packets() == 0
        assert agg.get_total_bytes() == 0
        assert agg.get_flows() == []

    def test_single_packet_creates_flow(self):
        agg = FlowAggregator()
        pkt = _make_pkt(0, "10.0.0.1", "10.0.0.2", 12345, 80,
                        "TCP", 100, 1000.0, flags="S")
        agg.update(pkt)

        flows = agg.get_flows()
        assert len(flows) == 1
        f = flows[0]
        assert f.src_ip == "10.0.0.1"
        assert f.dst_ip == "10.0.0.2"
        assert f.src_port == 12345
        assert f.dst_port == 80
        assert f.protocol == "TCP"
        assert f.packet_count == 1
        assert f.byte_count == 100
        # flags_set 存储拆分后的单字符：flags="S" → {"S"}
        assert "S" in f.flags_set

    def test_same_flow_aggregates(self):
        agg = FlowAggregator()
        for i in range(5):
            pkt = _make_pkt(i, "10.0.0.1", "10.0.0.2", 12345, 80,
                            "TCP", 100 + i * 10, 1000.0 + i, flags="SA")
            agg.update(pkt)

        assert agg.get_flow_count() == 1
        assert agg.get_total_packets() == 5
        assert agg.get_total_bytes() == 100 * 5 + 10 * (0 + 1 + 2 + 3 + 4)

        f = agg.get_flows()[0]
        assert f.packet_count == 5
        assert f.first_seen == 1000.0
        assert f.last_seen == 1004.0
        # flags="SA" 拆分后 flags_set = {"S", "A"}
        assert "S" in f.flags_set
        assert "A" in f.flags_set

    def test_direction_independent(self):
        """A->B 和 B->A 应归入同一条流"""
        agg = FlowAggregator()
        agg.update(_make_pkt(0, "10.0.0.1", "10.0.0.2", 12345, 80,
                             "TCP", 100, 0.0, flags="S"))
        agg.update(_make_pkt(1, "10.0.0.2", "10.0.0.1", 80, 12345,
                             "TCP", 150, 1.0, flags="SA"))

        assert agg.get_flow_count() == 1
        f = agg.get_flows()[0]
        assert f.packet_count == 2
        assert f.byte_count == 250

    def test_different_protocols_separate(self):
        agg = FlowAggregator()
        agg.update(_make_pkt(0, "10.0.0.1", "10.0.0.2", 53, 53,
                             "UDP", 80, 0.0))
        agg.update(_make_pkt(1, "10.0.0.1", "10.0.0.2", 53, 53,
                             "TCP", 100, 1.0))

        assert agg.get_flow_count() == 2

    def test_different_ports_separate(self):
        agg = FlowAggregator()
        agg.update(_make_pkt(0, "10.0.0.1", "10.0.0.2", 80, 443,
                             "TCP", 100, 0.0))
        agg.update(_make_pkt(1, "10.0.0.1", "10.0.0.2", 80, 8080,
                             "TCP", 100, 1.0))

        assert agg.get_flow_count() == 2

    def test_different_ips_separate(self):
        agg = FlowAggregator()
        agg.update(_make_pkt(0, "10.0.0.1", "10.0.0.2", 80, 443,
                             "TCP", 100, 0.0))
        agg.update(_make_pkt(1, "10.0.0.1", "10.0.0.3", 80, 443,
                             "TCP", 100, 1.0))

        assert agg.get_flow_count() == 2

    def test_update_batch(self):
        agg = FlowAggregator()
        packets = [
            _make_pkt(i, "10.0.0.1", "10.0.0.2", 12345, 80, "TCP", 100, float(i))
            for i in range(10)
        ]
        agg.update_batch(packets)
        assert agg.get_flow_count() == 1
        assert agg.get_total_packets() == 10

    def test_reset(self):
        agg = FlowAggregator()
        agg.update(_make_pkt(0, "10.0.0.1", "10.0.0.2", 80, 443,
                             "TCP", 100, 0.0))
        assert agg.get_flow_count() == 1

        agg.reset()
        assert agg.get_flow_count() == 0
        assert agg.get_total_packets() == 0

    def test_flows_sorted_by_packet_count(self):
        agg = FlowAggregator()
        # flow1: 1 packet
        agg.update(_make_pkt(0, "10.0.0.1", "10.0.0.2", 80, 443, "TCP", 100, 0.0))
        # flow2: 3 packets
        for i in range(3):
            agg.update(_make_pkt(i + 1, "10.0.0.2", "10.0.0.3", 22, 22, "TCP", 100, float(i)))
        # flow3: 2 packets
        for i in range(2):
            agg.update(_make_pkt(i + 4, "10.0.0.3", "10.0.0.4", 53, 53, "UDP", 80, float(i)))

        flows = agg.get_flows()
        assert flows[0].packet_count == 3
        assert flows[1].packet_count == 2
        assert flows[2].packet_count == 1

    def test_has_payload(self):
        agg = FlowAggregator()
        # 小包 (无 payload，TCP 最小帧 54 字节)
        agg.update(_make_pkt(0, "1.1.1.1", "2.2.2.2", 80, 443, "TCP", 54, 0.0))
        assert agg.get_flows()[0].has_payload is False

        # 大包 (有 payload)
        agg.update(_make_pkt(1, "1.1.1.1", "2.2.2.2", 80, 443, "TCP", 1500, 1.0))
        assert agg.get_flows()[0].has_payload is True

    def test_skip_packets_without_ip(self):
        agg = FlowAggregator()
        agg.update(PacketRecord(
            index=0, timestamp=0.0, src_ip="", dst_ip="",
            src_port=None, dst_port=None, protocol="ARP",
            length=42, info="arp", raw_bytes=b"\x00" * 42,
        ))
        assert agg.get_flow_count() == 0

    def test_zero_ports(self):
        agg = FlowAggregator()
        agg.update(_make_pkt(0, "10.0.0.1", "10.0.0.2", None, None,
                             "ICMP", 84, 0.0))
        assert agg.get_flow_count() == 1
        f = agg.get_flows()[0]
        assert f.src_port == 0
        assert f.dst_port == 0

    def test_flags_set_split_into_individual_chars(self):
        """TCP flags 字符串应拆分为单字符存储：'SA' -> {'S', 'A'}"""
        agg = FlowAggregator()
        agg.update(_make_pkt(0, "10.0.0.1", "10.0.0.2", 80, 443,
                             "TCP", 100, 0.0, flags="SA"))
        f = agg.get_flows()[0]
        assert f.flags_set == {"S", "A"}

    def test_flags_set_accumulates_across_packets(self):
        """多包流的 flags_set 应累积所有不同 flag 字符"""
        agg = FlowAggregator()
        agg.update(_make_pkt(0, "10.0.0.1", "10.0.0.2", 80, 443,
                             "TCP", 100, 0.0, flags="S"))
        agg.update(_make_pkt(1, "10.0.0.1", "10.0.0.2", 80, 443,
                             "TCP", 100, 1.0, flags="SA"))
        agg.update(_make_pkt(2, "10.0.0.1", "10.0.0.2", 80, 443,
                             "TCP", 100, 2.0, flags="FA"))
        f = agg.get_flows()[0]
        assert f.flags_set == {"S", "A", "F"}

    def test_flow_timeout_creates_new_flow(self):
        """超时后新包应创建新流，旧流归档"""
        agg = FlowAggregator()
        # 第一个包
        agg.update(_make_pkt(0, "10.0.0.1", "10.0.0.2", 80, 443,
                             "TCP", 100, 0.0, flags="S"))
        assert agg.get_flow_count() == 1

        # 超时后的包（TCP_FLOW_TIMEOUT 秒后）
        agg.update(_make_pkt(1, "10.0.0.1", "10.0.0.2", 80, 443,
                             "TCP", 100, TCP_FLOW_TIMEOUT + 1.0, flags="S"))
        # 应有 2 条流（1 活跃 + 1 归档）
        assert agg.get_flow_count() == 2
        assert agg.get_total_packets() == 2

    def test_no_timeout_within_threshold(self):
        """未超时的新包应续接旧流"""
        agg = FlowAggregator()
        agg.update(_make_pkt(0, "10.0.0.1", "10.0.0.2", 80, 443,
                             "TCP", 100, 0.0))
        # 超时阈值内的包
        agg.update(_make_pkt(1, "10.0.0.1", "10.0.0.2", 80, 443,
                             "TCP", 100, TCP_FLOW_TIMEOUT - 1.0))
        assert agg.get_flow_count() == 1
        assert agg.get_total_packets() == 2

    def test_get_flows_returns_copy(self):
        """get_flows() 不应暴露内部可变列表"""
        agg = FlowAggregator()
        agg.update(_make_pkt(0, "10.0.0.1", "10.0.0.2", 80, 443,
                             "TCP", 100, 0.0))
        flows1 = agg.get_flows()
        flows2 = agg.get_flows()
        # 两次调用返回不同的列表对象
        assert flows1 is not flows2

    def test_service_classification(self):
        """流应正确推断服务名"""
        agg = FlowAggregator()
        agg.update(_make_pkt(0, "10.0.0.1", "10.0.0.2", 12345, 80,
                             "TCP", 100, 0.0))
        assert agg.get_flows()[0].service == "HTTP"

        agg.reset()
        agg.update(_make_pkt(0, "10.0.0.1", "10.0.0.2", 12345, 53,
                             "UDP", 80, 0.0))
        assert agg.get_flows()[0].service == "DNS"

    def test_concurrent_updates(self):
        """多线程并发 update 不应抛异常且数据应一致"""
        agg = FlowAggregator()
        num_threads = 4
        packets_per_thread = 100

        def worker(thread_id):
            for i in range(packets_per_thread):
                pkt = _make_pkt(
                    thread_id * packets_per_thread + i,
                    "10.0.0.1", "10.0.0.2", 12345, 80,
                    "TCP", 100, float(i),
                )
                agg.update(pkt)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # 所有线程操作同一五元组，应聚合为 1 条流
        assert agg.get_flow_count() == 1
        assert agg.get_total_packets() == num_threads * packets_per_thread

    def test_ip_sorting_numeric_not_lexical(self):
        """方向归一化应使用数值 IP 比较，而非字符串比较"""
        agg = FlowAggregator()
        # "9.0.0.1" 字符串大于 "10.0.0.1"，但数值上 9.x < 10.x
        agg.update(_make_pkt(0, "9.0.0.1", "10.0.0.2", 80, 443,
                             "TCP", 100, 0.0))
        agg.update(_make_pkt(1, "10.0.0.2", "9.0.0.1", 443, 80,
                             "TCP", 100, 1.0))
        # 应归为同一条流
        assert agg.get_flow_count() == 1
        assert agg.get_total_packets() == 2

    def test_udp_min_frame_size(self):
        """UDP 最小帧 42 字节，小于此值 has_payload=False"""
        agg = FlowAggregator()
        agg.update(_make_pkt(0, "10.0.0.1", "10.0.0.2", 53, 53,
                             "UDP", 42, 0.0))
        assert agg.get_flows()[0].has_payload is False

        agg.update(_make_pkt(1, "10.0.0.1", "10.0.0.2", 53, 53,
                             "UDP", 100, 1.0))
        assert agg.get_flows()[0].has_payload is True

    def test_empty_flags_not_added(self):
        """flags=None 的包不应向 flags_set 添加任何元素"""
        agg = FlowAggregator()
        agg.update(_make_pkt(0, "10.0.0.1", "10.0.0.2", 53, 53,
                             "UDP", 100, 0.0))
        assert agg.get_flows()[0].flags_set == set()


class TestTcpHealthBidirectional:
    """TCP 健康度追踪：双向流序列号方向隔离测试

    核心验证：A→B 和 B→A 的序列号不能交叉比较，
    否则双向 TCP 流中约 50% 的包会被误判为重传。
    """

    def test_bidirectional_no_false_retransmit(self):
        """双向 TCP 流：两端各自递增序列号，不应被误判为重传"""
        agg = FlowAggregator()
        # 客户端 → 服务器 (seq 从 1000 递增)
        for i in range(5):
            agg.update(_make_pkt(
                i, "10.0.0.1", "10.0.0.2", 12345, 80,
                "TCP", 200, float(i), flags="A",
                tcp_seq=1000 + i * 100,
            ))
        # 服务器 → 客户端 (seq 从 5000 递增，不同序列号空间)
        for i in range(5):
            agg.update(_make_pkt(
                5 + i, "10.0.0.2", "10.0.0.1", 80, 12345,
                "TCP", 300, float(5 + i), flags="A",
                tcp_seq=5000 + i * 200,
            ))

        flows = agg.get_flows()
        assert len(flows) == 1
        f = flows[0]
        assert f.packet_count == 10
        # 关键断言：双向流的序列号不应交叉误判为重传
        assert f.retransmit_count == 0, (
            f"期望 0 重传，实际 {f.retransmit_count}（双向序列号交叉对比 Bug）"
        )

    def test_true_retransmit_detected_per_direction(self):
        """同一方向的真实重传应被检测到"""
        agg = FlowAggregator()
        # 正常递增
        agg.update(_make_pkt(
            0, "10.0.0.1", "10.0.0.2", 12345, 80,
            "TCP", 200, 0.0, flags="A", tcp_seq=1000,
        ))
        agg.update(_make_pkt(
            1, "10.0.0.1", "10.0.0.2", 12345, 80,
            "TCP", 200, 1.0, flags="A", tcp_seq=1200,
        ))
        # 真实重传：seq 回退
        agg.update(_make_pkt(
            2, "10.0.0.1", "10.0.0.2", 12345, 80,
            "TCP", 200, 2.0, flags="A", tcp_seq=1000,
        ))

        flows = agg.get_flows()
        assert len(flows) == 1
        assert flows[0].retransmit_count == 1

    def test_pure_ack_not_counted_as_retransmit(self):
        """纯 ACK（无 payload，length < 54）不计为重传"""
        agg = FlowAggregator()
        agg.update(_make_pkt(
            0, "10.0.0.1", "10.0.0.2", 12345, 80,
            "TCP", 200, 0.0, flags="A", tcp_seq=1000,
        ))
        # 纯 ACK：seq 回退但无 payload（length=40 < 54）
        agg.update(_make_pkt(
            1, "10.0.0.1", "10.0.0.2", 12345, 80,
            "TCP", 40, 1.0, flags="A", tcp_seq=500,
        ))

        flows = agg.get_flows()
        assert len(flows) == 1
        assert flows[0].retransmit_count == 0

    def test_dup_ack_per_direction(self):
        """重复 ACK 应按方向独立计数"""
        agg = FlowAggregator()
        # 正向：同一个 ack 出现 3 次 → 触发 dup_ack
        for i in range(3):
            agg.update(_make_pkt(
                i, "10.0.0.1", "10.0.0.2", 12345, 80,
                "TCP", 40, float(i), flags="A",
                tcp_seq=100, tcp_ack=5000,
            ))
        # 反向：同一个 ack 出现 3 次 → 也触发 dup_ack
        for i in range(3):
            agg.update(_make_pkt(
                3 + i, "10.0.0.2", "10.0.0.1", 80, 12345,
                "TCP", 40, float(3 + i), flags="A",
                tcp_seq=5000, tcp_ack=200,
            ))

        flows = agg.get_flows()
        assert len(flows) == 1
        # 两个方向各触发一次 dup_ack
        assert flows[0].dup_ack_count == 2

    def test_cross_direction_ack_no_false_dup(self):
        """跨方向相同 ACK 值不应触发重复 ACK 误判"""
        agg = FlowAggregator()
        # 正向 ack=1000 两次
        agg.update(_make_pkt(
            0, "10.0.0.1", "10.0.0.2", 12345, 80,
            "TCP", 40, 0.0, flags="A", tcp_seq=100, tcp_ack=1000,
        ))
        # 反向 ack=1000 一次（与正向 ack 值相同但方向不同，不应叠加）
        agg.update(_make_pkt(
            1, "10.0.0.2", "10.0.0.1", 80, 12345,
            "TCP", 40, 1.0, flags="A", tcp_seq=5000, tcp_ack=1000,
        ))

        flows = agg.get_flows()
        assert len(flows) == 1
        assert flows[0].dup_ack_count == 0

    def test_zero_window_detected(self):
        """零窗口应被正确检测"""
        agg = FlowAggregator()
        agg.update(_make_pkt(
            0, "10.0.0.1", "10.0.0.2", 12345, 80,
            "TCP", 40, 0.0, flags="A", tcp_seq=100, tcp_window=0,
        ))
        agg.update(_make_pkt(
            1, "10.0.0.1", "10.0.0.2", 12345, 80,
            "TCP", 40, 1.0, flags="A", tcp_seq=101, tcp_window=65535,
        ))
        agg.update(_make_pkt(
            2, "10.0.0.1", "10.0.0.2", 12345, 80,
            "TCP", 40, 2.0, flags="A", tcp_seq=102, tcp_window=0,
        ))

        flows = agg.get_flows()
        assert flows[0].zero_window_count == 2

    def test_rst_detected(self):
        """RST 包应被正确计数"""
        agg = FlowAggregator()
        agg.update(_make_pkt(
            0, "10.0.0.1", "10.0.0.2", 12345, 80,
            "TCP", 40, 0.0, flags="R", tcp_seq=100,
        ))
        agg.update(_make_pkt(
            1, "10.0.0.1", "10.0.0.2", 12345, 80,
            "TCP", 200, 1.0, flags="A", tcp_seq=1000,
        ))

        flows = agg.get_flows()
        assert flows[0].rst_count == 1
        assert flows[0].retransmit_count == 0

    def test_seq_wrap_around_handled(self):
        """32 位序列号回绕应正确处理"""
        agg = FlowAggregator()
        # seq 接近最大值
        agg.update(_make_pkt(
            0, "10.0.0.1", "10.0.0.2", 12345, 80,
            "TCP", 200, 0.0, flags="A", tcp_seq=0xFFFFFFF0,
        ))
        # seq 回绕到小值（正常前进）
        agg.update(_make_pkt(
            1, "10.0.0.1", "10.0.0.2", 12345, 80,
            "TCP", 200, 1.0, flags="A", tcp_seq=0x00000100,
        ))

        flows = agg.get_flows()
        assert flows[0].retransmit_count == 0, (
            "序列号回绕后的正常前进不应被判为重传"
        )
