"""BPF 过滤器真实验证测试 — 不使用 mock，直接用 scapy 验证"""

import pytest

from app.capture.bpf_validator import validate_bpf


class TestBPFValidatorReturnType:
    """返回值类型与结构验证"""

    def test_returns_tuple_of_two(self):
        """validate_bpf 应返回包含两个元素的 tuple"""
        result = validate_bpf("tcp")
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_first_element_is_bool(self):
        """第一个返回值应为 bool"""
        ok, msg = validate_bpf("tcp")
        assert isinstance(ok, bool)

    def test_second_element_is_str(self):
        """第二个返回值应为 str"""
        ok, msg = validate_bpf("tcp")
        assert isinstance(msg, str)


class TestBPFValidatorEmptyFilter:
    """空过滤器应始终有效"""

    def test_empty_string_is_valid(self):
        ok, msg = validate_bpf("")
        assert ok is True
        assert msg == ""

    def test_whitespace_only_is_valid(self):
        ok, msg = validate_bpf("   ")
        assert ok is True
        assert msg == ""

    def test_tab_only_is_valid(self):
        ok, msg = validate_bpf("\t")
        assert ok is True

    def test_mixed_whitespace_is_valid(self):
        ok, msg = validate_bpf("  \t  \n  ")
        assert ok is True


class TestBPFValidatorValidFilters:
    """合法 BPF 过滤器应通过验证"""

    def test_valid_tcp(self):
        ok, msg = validate_bpf("tcp")
        assert ok is True
        assert msg == ""

    def test_valid_udp(self):
        ok, msg = validate_bpf("udp")
        assert ok is True

    def test_valid_icmp(self):
        ok, msg = validate_bpf("icmp")
        assert ok is True

    def test_valid_port_80(self):
        ok, msg = validate_bpf("port 80")
        assert ok is True

    def test_valid_host_filter(self):
        ok, msg = validate_bpf("host 192.168.1.1")
        assert ok is True

    def test_valid_src_host(self):
        ok, msg = validate_bpf("src host 10.0.0.1")
        assert ok is True

    def test_valid_dst_host(self):
        ok, msg = validate_bpf("dst host 10.0.0.1")
        assert ok is True

    def test_valid_compound_and(self):
        ok, msg = validate_bpf("host 10.0.0.1 and tcp port 443")
        assert ok is True

    def test_valid_compound_or(self):
        ok, msg = validate_bpf("tcp or udp")
        assert ok is True

    def test_valid_port_range(self):
        ok, msg = validate_bpf("portrange 80-443")
        assert ok is True

    def test_valid_src_dst_filter(self):
        ok, msg = validate_bpf("src host 192.168.1.1 and dst port 80")
        assert ok is True

    def test_valid_net_filter(self):
        ok, msg = validate_bpf("net 192.168.0.0/16")
        assert ok is True

    def test_valid_dst_net(self):
        ok, msg = validate_bpf("dst net 10.0.0.0/8")
        assert ok is True

    def test_valid_not_filter(self):
        ok, msg = validate_bpf("not port 22")
        assert ok is True

    def test_valid_port_443(self):
        ok, msg = validate_bpf("port 443")
        assert ok is True

    def test_valid_src_port(self):
        ok, msg = validate_bpf("src port 8080")
        assert ok is True

    def test_valid_dst_port(self):
        ok, msg = validate_bpf("dst port 53")
        assert ok is True

    def test_valid_arp(self):
        ok, msg = validate_bpf("arp")
        assert ok is True

    def test_valid_parenthesized_filter(self):
        ok, msg = validate_bpf("(tcp or udp) and port 53")
        assert ok is True

    def test_valid_less_than(self):
        ok, msg = validate_bpf("less 100")
        assert ok is True

    def test_valid_greater_than(self):
        ok, msg = validate_bpf("greater 1000")
        assert ok is True

    def test_valid_ip_only(self):
        ok, msg = validate_bpf("ip")
        assert ok is True

    def test_valid_ip6(self):
        ok, msg = validate_bpf("ip6")
        assert ok is True


class TestBPFValidatorInvalidFilters:
    """非法 BPF 过滤器应被拒绝"""

    def test_invalid_random_text(self):
        ok, msg = validate_bpf("hello world")
        assert ok is False
        assert len(msg) > 0

    def test_invalid_syntax_brackets(self):
        ok, msg = validate_bpf("INVALID [[[syntax")
        assert ok is False
        assert len(msg) > 0

    def test_invalid_double_and(self):
        """BPF 使用 'and' 而非 '&&'"""
        ok, msg = validate_bpf("tcp && udp")
        assert ok is False

    def test_invalid_double_or(self):
        """libpcap 实际接受 '||' 作为 'or' 的别名"""
        ok, msg = validate_bpf("tcp || udp")
        assert ok is True  # libpcap 接受 || 语法

    def test_invalid_negative_port(self):
        ok, msg = validate_bpf("port -1")
        assert ok is False

    def test_invalid_nonexistent_protocol(self):
        ok, msg = validate_bpf("xyzproto")
        assert ok is False

    def test_incomplete_host_filter(self):
        """host 后缺少 IP 地址"""
        ok, msg = validate_bpf("host")
        assert ok is False

    def test_incomplete_port_filter(self):
        """port 后缺少端口号"""
        ok, msg = validate_bpf("port")
        assert ok is False

    def test_invalid_ip_format(self):
        ok, msg = validate_bpf("host 999.999.999.999")
        assert ok is False

    def test_empty_parens(self):
        ok, msg = validate_bpf("()")
        assert ok is False
