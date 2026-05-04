"""BPF 过滤器真实验证测试 — 不使用 mock，直接用 scapy 验证"""

import pytest

from app.capture.bpf_validator import validate_bpf


class TestBPFValidator:
    """BPF 过滤器语法真实验证"""

    def test_empty_filter_is_valid(self):
        ok, msg = validate_bpf("")
        assert ok is True
        assert msg == ""

    def test_whitespace_filter_is_valid(self):
        ok, msg = validate_bpf("   ")
        assert ok is True

    def test_none_like_filter(self):
        ok, msg = validate_bpf("")
        assert ok is True

    def test_valid_port_filter(self):
        ok, msg = validate_bpf("port 80")
        assert ok is True

    def test_valid_host_filter(self):
        ok, msg = validate_bpf("host 192.168.1.1")
        assert ok is True

    def test_valid_tcp_filter(self):
        ok, msg = validate_bpf("tcp")
        assert ok is True

    def test_valid_udp_filter(self):
        ok, msg = validate_bpf("udp")
        assert ok is True

    def test_valid_icmp_filter(self):
        ok, msg = validate_bpf("icmp")
        assert ok is True

    def test_valid_compound_filter(self):
        ok, msg = validate_bpf("host 10.0.0.1 and tcp port 443")
        assert ok is True

    def test_valid_port_range_filter(self):
        ok, msg = validate_bpf("portrange 80-443")
        assert ok is True

    def test_valid_src_dst_filter(self):
        ok, msg = validate_bpf("src host 192.168.1.1 and dst port 80")
        assert ok is True

    def test_valid_net_filter(self):
        ok, msg = validate_bpf("net 192.168.0.0/16")
        assert ok is True

    def test_invalid_syntax(self):
        ok, msg = validate_bpf("INVALID [[[syntax")
        assert ok is False
        assert len(msg) > 0

    def test_invalid_random_text(self):
        ok, msg = validate_bpf("hello world")
        assert ok is False

    def test_invalid_port_negative(self):
        ok, msg = validate_bpf("port -1")
        assert ok is False

    def test_invalid_double_and(self):
        ok, msg = validate_bpf("tcp && udp")
        assert ok is False
