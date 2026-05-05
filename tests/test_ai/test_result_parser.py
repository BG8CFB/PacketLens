"""ResultParser 单元测试 — 覆盖 normalize 函数、JSON 提取、降级处理"""

import json

from app.ai.result_parser import (
    ResultParser,
    normalize_severity,
    normalize_category,
    VALID_SEVERITIES,
    VALID_CATEGORIES,
)
from app.models.analysis_result import AnalysisResult, AnalysisIssue


# ── normalize_severity 测试 ──


class TestNormalizeSeverity:
    """严重级别规范化"""

    def test_valid_severity_critical(self):
        assert normalize_severity("Critical") == "Critical"

    def test_valid_severity_warning(self):
        assert normalize_severity("Warning") == "Warning"

    def test_valid_severity_info(self):
        assert normalize_severity("Info") == "Info"

    def test_valid_severity_normal(self):
        assert normalize_severity("Normal") == "Normal"

    def test_case_insensitive_lowercase(self):
        """小写输入经 .title() 后应匹配"""
        assert normalize_severity("critical") == "Critical"
        assert normalize_severity("warning") == "Warning"
        assert normalize_severity("info") == "Info"
        assert normalize_severity("normal") == "Normal"

    def test_case_insensitive_uppercase(self):
        """大写输入经 .title() 后应匹配"""
        assert normalize_severity("CRITICAL") == "Critical"
        assert normalize_severity("WARNING") == "Warning"

    def test_case_insensitive_mixed_case(self):
        assert normalize_severity("cRITICAL") == "Critical"
        assert normalize_severity("WaRnInG") == "Warning"

    def test_alias_crit(self):
        assert normalize_severity("Crit") == "Critical"

    def test_alias_warn(self):
        assert normalize_severity("Warn") == "Warning"

    def test_alias_informational(self):
        assert normalize_severity("Informational") == "Info"

    def test_alias_information(self):
        assert normalize_severity("Information") == "Info"

    def test_alias_case_insensitive(self):
        """别名也应支持大小写不敏感"""
        assert normalize_severity("crit") == "Critical"
        assert normalize_severity("WARN") == "Warning"
        assert normalize_severity("informational") == "Info"

    def test_whitespace_stripped(self):
        """前后空白应被去除"""
        assert normalize_severity("  Critical  ") == "Critical"
        assert normalize_severity("\tWarning\n") == "Warning"

    def test_unknown_value_defaults_to_info(self):
        """未识别的值应回退到 Info"""
        assert normalize_severity("Unknown") == "Info"
        assert normalize_severity("High") == "Info"
        assert normalize_severity("Low") == "Info"
        assert normalize_severity("Medium") == "Info"
        assert normalize_severity("") == "Info"

    def test_all_valid_severities_in_frozenset(self):
        """验证 VALID_SEVERITIES 包含全部有效值"""
        assert VALID_SEVERITIES == frozenset({"Critical", "Warning", "Info", "Normal"})


# ── normalize_category 测试 ──


class TestNormalizeCategory:
    """分类规范化"""

    def test_valid_category_security(self):
        assert normalize_category("Security") == "Security"

    def test_valid_category_performance(self):
        assert normalize_category("Performance") == "Performance"

    def test_valid_category_anomaly(self):
        assert normalize_category("Anomaly") == "Anomaly"

    def test_valid_category_protocol(self):
        assert normalize_category("Protocol") == "Protocol"

    def test_valid_category_configuration(self):
        assert normalize_category("Configuration") == "Configuration"

    def test_valid_category_general(self):
        assert normalize_category("General") == "General"

    def test_case_insensitive(self):
        assert normalize_category("security") == "Security"
        assert normalize_category("PERFORMANCE") == "Performance"
        assert normalize_category("anOmALy") == "Anomaly"

    def test_alias_net(self):
        assert normalize_category("Net") == "Anomaly"

    def test_alias_traffic(self):
        assert normalize_category("Traffic") == "Anomaly"

    def test_alias_malware(self):
        assert normalize_category("Malware") == "Security"

    def test_alias_vuln(self):
        assert normalize_category("Vuln") == "Security"

    def test_alias_case_insensitive(self):
        """别名也应支持大小写不敏感"""
        assert normalize_category("net") == "Anomaly"
        assert normalize_category("TRAFFIC") == "Anomaly"
        assert normalize_category("malware") == "Security"
        assert normalize_category("vuln") == "Security"

    def test_whitespace_stripped(self):
        assert normalize_category("  Security  ") == "Security"
        assert normalize_category("\tAnomaly\n") == "Anomaly"

    def test_unknown_value_defaults_to_general(self):
        """未识别的值应回退到 General"""
        assert normalize_category("Unknown") == "General"
        assert normalize_category("Network") == "General"
        assert normalize_category("") == "General"
        assert normalize_category("Crypto") == "General"

    def test_all_valid_categories_in_frozenset(self):
        assert VALID_CATEGORIES == frozenset({
            "Security", "Performance", "Anomaly", "Protocol", "Configuration", "General", "System", "Fault",
        })


# ── JSON 提取测试 ──


class TestExtractJson:
    """_extract_json 方法的各种 JSON 提取策略"""

    def test_pure_json_object(self):
        parser = ResultParser()
        data = '{"key": "value"}'
        result = parser._extract_json(data)
        assert result == {"key": "value"}

    def test_json_code_block_with_json_tag(self):
        parser = ResultParser()
        data = '```json\n{"key": "value"}\n```'
        result = parser._extract_json(data)
        assert result == {"key": "value"}

    def test_json_code_block_without_tag(self):
        parser = ResultParser()
        data = '```\n{"key": "value"}\n```'
        result = parser._extract_json(data)
        assert result == {"key": "value"}

    def test_json_embedded_in_text(self):
        """JSON 前后有普通文字时，通过找最外层 {} 来提取"""
        parser = ResultParser()
        data = '这是结果:\n{"key": "value"}\n谢谢'
        result = parser._extract_json(data)
        assert result == {"key": "value"}

    def test_invalid_text_returns_none(self):
        parser = ResultParser()
        assert parser._extract_json("纯文本内容") is None

    def test_empty_string_returns_none(self):
        parser = ResultParser()
        assert parser._extract_json("") is None

    def test_whitespace_only_returns_none(self):
        parser = ResultParser()
        assert parser._extract_json("   \n\t  ") is None

    def test_broken_json_returns_none(self):
        """不完整的 JSON 无法解析时应返回 None"""
        parser = ResultParser()
        assert parser._extract_json('{"key": ') is None

    def test_nested_json(self):
        """嵌套 JSON 对象"""
        parser = ResultParser()
        data = '{"outer": {"inner": 42}}'
        result = parser._extract_json(data)
        assert result == {"outer": {"inner": 42}}


# ── parse 方法完整测试 ──


class TestResultParserParse:
    """parse 方法的完整流程测试"""

    def test_parse_pure_json(self):
        parser = ResultParser()
        data = json.dumps({
            "summary": "一切正常",
            "overall_assessment": "无安全风险",
            "issues": [
                {
                    "severity": "Info",
                    "category": "Protocol",
                    "title": "HTTP 明文传输",
                    "description": "检测到 HTTP 流量",
                    "recommendation": "建议使用 HTTPS",
                }
            ],
        })
        result = parser.parse(data, session_id="s1", mode="quick")

        assert isinstance(result, AnalysisResult)
        assert result.summary == "一切正常"
        assert result.overall_assessment == "无安全风险"
        assert len(result.issues) == 1
        assert result.issues[0].title == "HTTP 明文传输"
        assert result.issues[0].severity == "Info"
        assert result.issues[0].category == "Protocol"
        assert result.session_id == "s1"
        assert result.analysis_mode == "quick"
        assert result.raw_ai_response == data

    def test_parse_code_block_json(self):
        parser = ResultParser()
        data = """这是一些前置文字
```json
{
"summary": "发现异常",
"issues": [
    {"severity": "Critical", "category": "Security", "title": "异常扫描", "description": "端口扫描"}
],
"overall_assessment": "需处理"
}
```
后续文字"""
        result = parser.parse(data)
        assert result.summary == "发现异常"
        assert len(result.issues) == 1
        assert result.issues[0].severity == "Critical"
        assert result.issues[0].category == "Security"

    def test_parse_plain_code_block(self):
        """没有 'json' 标记的代码块"""
        parser = ResultParser()
        data = """```
{"summary": "结果", "issues": [], "overall_assessment": "OK"}
```"""
        result = parser.parse(data)
        assert result.summary == "结果"
        assert result.issues == []

    def test_parse_json_with_surrounding_text(self):
        parser = ResultParser()
        data = '这是结果:\n{"summary": "分析完成", "issues": [], "overall_assessment": "安全"}\n谢谢阅读'
        result = parser.parse(data)
        assert result.summary == "分析完成"
        assert result.overall_assessment == "安全"

    def test_parse_with_severity_alias_mapping(self):
        """AI 返回的 severity 别名应被正确映射"""
        parser = ResultParser()
        data = json.dumps({
            "summary": "测试别名",
            "issues": [
                {"severity": "Crit", "category": "Security", "title": "T1", "description": "D1"},
                {"severity": "Warn", "category": "Performance", "title": "T2", "description": "D2"},
                {"severity": "Informational", "category": "Protocol", "title": "T3", "description": "D3"},
                {"severity": "Information", "category": "General", "title": "T4", "description": "D4"},
            ],
        })
        result = parser.parse(data)
        assert result.issues[0].severity == "Critical"
        assert result.issues[1].severity == "Warning"
        assert result.issues[2].severity == "Info"
        assert result.issues[3].severity == "Info"

    def test_parse_with_category_alias_mapping(self):
        """AI 返回的 category 别名应被正确映射"""
        parser = ResultParser()
        data = json.dumps({
            "summary": "测试别名",
            "issues": [
                {"severity": "Info", "category": "Net", "title": "T1", "description": "D1"},
                {"severity": "Info", "category": "Traffic", "title": "T2", "description": "D2"},
                {"severity": "Info", "category": "Malware", "title": "T3", "description": "D3"},
                {"severity": "Info", "category": "Vuln", "title": "T4", "description": "D4"},
            ],
        })
        result = parser.parse(data)
        assert result.issues[0].category == "Anomaly"
        assert result.issues[1].category == "Anomaly"
        assert result.issues[2].category == "Security"
        assert result.issues[3].category == "Security"

    def test_parse_unknown_severity_defaults_to_info(self):
        """未知 severity 应回退到 Info"""
        parser = ResultParser()
        data = json.dumps({
            "issues": [
                {"severity": "High", "category": "Security", "title": "T", "description": "D"},
            ],
        })
        result = parser.parse(data)
        assert result.issues[0].severity == "Info"

    def test_parse_unknown_category_defaults_to_general(self):
        """未知 category 应回退到 General"""
        parser = ResultParser()
        data = json.dumps({
            "issues": [
                {"severity": "Info", "category": "Crypto", "title": "T", "description": "D"},
            ],
        })
        result = parser.parse(data)
        assert result.issues[0].category == "General"

    def test_parse_multiple_issues_with_full_fields(self):
        parser = ResultParser()
        data = json.dumps({
            "summary": "多问题",
            "issues": [
                {
                    "severity": "Critical",
                    "category": "Security",
                    "title": "端口扫描",
                    "description": "检测到端口扫描行为",
                    "affected_flows": ["f1", "f2"],
                    "recommendation": "封禁源 IP",
                },
                {
                    "severity": "Warning",
                    "category": "Performance",
                    "title": "高延迟",
                    "description": "TCP 重传率高",
                },
            ],
            "protocol_insights": {"tcp_analysis": "重传率 5%"},
            "overall_assessment": "需关注",
        })
        result = parser.parse(data)
        assert len(result.issues) == 2

        issue0 = result.issues[0]
        assert issue0.severity == "Critical"
        assert issue0.category == "Security"
        assert issue0.title == "端口扫描"
        assert issue0.description == "检测到端口扫描行为"
        assert issue0.affected_flows == ["f1", "f2"]
        assert issue0.recommendation == "封禁源 IP"

        issue1 = result.issues[1]
        assert issue1.severity == "Warning"
        assert issue1.category == "Performance"
        assert issue1.affected_flows == []
        assert issue1.recommendation == ""

        assert result.protocol_insights == {"tcp_analysis": "重传率 5%"}

    def test_fallback_on_invalid_json(self):
        parser = ResultParser()
        data = "这不是 JSON，AI 返回了纯文本结果。"
        result = parser.parse(data, session_id="s2", mode="deep")

        assert isinstance(result, AnalysisResult)
        assert len(result.issues) == 1
        assert result.issues[0].severity == "Info"
        assert result.issues[0].category == "System"
        assert "解析失败" in result.issues[0].title
        assert result.issues[0].description == data[:500]
        assert result.issues[0].raw_detail == data
        assert result.summary == "AI 响应解析失败，显示原始内容"
        assert result.session_id == "s2"
        assert result.analysis_mode == "deep"
        assert result.raw_ai_response == data

    def test_fallback_on_empty(self):
        parser = ResultParser()
        result = parser.parse("")
        assert len(result.issues) == 1
        assert "解析失败" in result.issues[0].title

    def test_issue_defaults_when_fields_missing(self):
        """JSON 中 issue 缺少字段时应使用默认值"""
        parser = ResultParser()
        data = json.dumps({
            "issues": [
                {"title": "仅标题"},
            ],
        })
        result = parser.parse(data)
        assert len(result.issues) == 1
        issue = result.issues[0]
        assert issue.severity == "Info"
        assert issue.category == "General"
        assert issue.description == ""
        assert issue.affected_flows == []
        assert issue.recommendation == ""

    def test_skip_non_dict_issues(self):
        parser = ResultParser()
        data = json.dumps({
            "issues": [
                {"severity": "Info", "category": "General", "title": "T", "description": "D"},
                "not a dict",
                123,
                None,
                [],
            ],
        })
        result = parser.parse(data)
        assert len(result.issues) == 1

    def test_empty_issues_list(self):
        parser = ResultParser()
        data = json.dumps({"summary": "OK", "issues": []})
        result = parser.parse(data)
        assert result.issues == []
        assert result.summary == "OK"

    def test_no_issues_key_in_json(self):
        """JSON 中缺少 issues 字段时应返回空列表"""
        parser = ResultParser()
        data = json.dumps({"summary": "无问题"})
        result = parser.parse(data)
        assert result.issues == []
        assert result.summary == "无问题"

    def test_protocol_insights_and_overall_assessment(self):
        parser = ResultParser()
        data = json.dumps({
            "summary": "发现异常",
            "protocol_insights": {
                "tcp_analysis": "TCP 重传率异常",
                "udp_analysis": "正常",
                "dns_analysis": "可疑域名",
            },
            "overall_assessment": "需立即处理",
            "issues": [],
        })
        result = parser.parse(data)
        assert result.protocol_insights["tcp_analysis"] == "TCP 重传率异常"
        assert result.protocol_insights["dns_analysis"] == "可疑域名"
        assert result.overall_assessment == "需立即处理"

    def test_timestamp_is_set(self):
        """解析结果应包含有效的时间戳"""
        parser = ResultParser()
        data = json.dumps({"summary": "OK", "issues": []})
        result = parser.parse(data)
        assert result.timestamp is not None

    def test_fallback_description_truncated_at_500_chars(self):
        """降级时 description 应截断到 500 字符"""
        parser = ResultParser()
        long_text = "A" * 1000
        result = parser.parse(long_text)
        assert len(result.issues[0].description) == 500
        assert result.issues[0].raw_detail == long_text
