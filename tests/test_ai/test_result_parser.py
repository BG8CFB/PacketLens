"""ResultParser 单元测试"""

import json
from app.models.analysis_result import AnalysisIssue, AnalysisResult
from app.ai.result_parser import ResultParser


class TestResultParser:

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
        assert result.session_id == "s1"
        assert result.analysis_mode == "quick"

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

    def test_parse_code_block_plain(self):
        """测试没有 'json' 标记的代码块"""
        parser = ResultParser()
        data = """```
{"summary": "结果", "issues": [], "overall_assessment": "OK"}
```"""
        result = parser.parse(data)
        assert result.summary == "结果"

    def test_parse_json_with_surrounding_text(self):
        """JSON 被普通文字包裹 — 通过找最外层 {} 来解析"""
        parser = ResultParser()
        data = '这是结果:\n{"summary": "分析完成", "issues": [], "overall_assessment": "安全"}\n谢谢阅读'
        result = parser.parse(data)
        assert result.summary == "分析完成"
        assert result.overall_assessment == "安全"

    def test_parse_multiple_issues(self):
        parser = ResultParser()
        data = json.dumps({
            "summary": "多问题",
            "issues": [
                {"severity": "Critical", "category": "Security", "title": "T1", "description": "D1",
                 "affected_flows": ["f1"], "recommendation": "R1"},
                {"severity": "Warning", "category": "Performance", "title": "T2", "description": "D2"},
            ],
        })
        result = parser.parse(data)
        assert len(result.issues) == 2
        assert result.issues[0].affected_flows == ["f1"]
        assert result.issues[0].recommendation == "R1"

    def test_fallback_on_invalid_json(self):
        parser = ResultParser()
        data = "这不是 JSON，AI 返回了纯文本结果。"
        result = parser.parse(data, session_id="s2", mode="deep")

        assert isinstance(result, AnalysisResult)
        assert len(result.issues) == 1
        assert result.issues[0].severity == "Info"
        assert result.issues[0].category == "System"
        assert "解析失败" in result.issues[0].title
        assert result.summary == "AI 响应解析失败，显示原始内容"
        assert result.session_id == "s2"
        assert result.analysis_mode == "deep"
        assert result.raw_ai_response == data

    def test_fallback_on_empty(self):
        parser = ResultParser()
        result = parser.parse("")
        assert len(result.issues) == 1
        assert "解析失败" in result.issues[0].title

    def test_issue_defaults(self):
        """JSON 中缺少字段时应使用默认值"""
        parser = ResultParser()
        data = json.dumps({
            "issues": [
                {"title": "仅标题"},
            ],
        })
        result = parser.parse(data)
        assert len(result.issues) == 1
        assert result.issues[0].severity == "Info"  # default
        assert result.issues[0].category == "General"  # default
        assert result.issues[0].description == ""  # default

    def test_skip_non_dict_issues(self):
        parser = ResultParser()
        data = json.dumps({
            "issues": [
                {"severity": "Info", "category": "G", "title": "T", "description": "D"},
                "not a dict",
                123,
            ],
        })
        result = parser.parse(data)
        assert len(result.issues) == 1  # 只看字典

    def test_empty_issues(self):
        parser = ResultParser()
        data = json.dumps({"summary": "OK", "issues": []})
        result = parser.parse(data)
        assert result.issues == []
