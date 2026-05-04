"""AI Engine 真实测试 — 调用真实 API"""

import pytest

from app.ai.ai_engine import AIEngine
from app.ai.result_parser import ResultParser
from app.storage.config_manager import ConfigManager


def _get_active_api_config() -> dict:
    """从 ConfigManager 获取当前激活 provider 的配置"""
    config = ConfigManager()
    return config.get_ai_config()


class TestAIEngineConnection:
    """真实 API 连接测试"""

    def test_connection_succeeds(self):
        """test_connection 应返回成功"""
        cfg = _get_active_api_config()
        engine = AIEngine(
            api_key=cfg["api_key"],
            base_url=cfg["base_url"],
            model=cfg["model"],
        )
        ok, msg = engine.test_connection()
        assert ok is True, f"API 连接失败: {msg}"
        assert cfg["model"] in msg

    def test_invalid_api_key_fails(self):
        """错误的 API Key 应返回失败"""
        cfg = _get_active_api_config()
        engine = AIEngine(
            api_key="sk-invalid-key-12345",
            base_url=cfg["base_url"],
            model=cfg["model"],
        )
        ok, msg = engine.test_connection()
        assert ok is False
        assert "失败" in msg


class TestAIEngineAnalyze:
    """真实 API 分析调用"""

    def test_sync_analyze_returns_text(self):
        """同步分析应返回非空文本"""
        cfg = _get_active_api_config()
        engine = AIEngine(
            api_key=cfg["api_key"],
            base_url=cfg["base_url"],
            model=cfg["model"],
        )
        result = engine.analyze(
            prompt="请用一句话回答：1+1等于几？",
            system_prompt="你是一个数学助手，只回答数字。",
            max_tokens=20,
        )
        assert isinstance(result, str)
        assert len(result) > 0

    def test_sync_analyze_with_network_data(self):
        """使用网络流量数据进行真实分析"""
        cfg = _get_active_api_config()
        engine = AIEngine(
            api_key=cfg["api_key"],
            base_url=cfg["base_url"],
            model=cfg["model"],
        )
        prompt = """以下是网络流量摘要：
- 总包数: 100
- 协议分布: TCP 60%, UDP 30%, ICMP 10%
- 源 IP 192.168.1.100 向 10.0.0.1 的 80, 443, 8080, 8443, 9090 端口发送了 SYN 包
- 检测到 5 个流

请判断是否存在安全风险，用 JSON 格式回答。"""
        result = engine.analyze(
            prompt=prompt,
            system_prompt="你是网络安全分析师，请用中文回答。",
            max_tokens=200,
        )
        assert isinstance(result, str)
        assert len(result) > 20  # 应该有实质内容

        # 尝试解析结果
        parser = ResultParser()
        parsed = parser.parse(result)
        # 即使解析失败，也应返回 AnalysisResult 对象
        assert parsed is not None


class TestAIEngineStream:
    """流式分析测试"""

    def test_stream_analyze_collects_chunks(self):
        """流式分析应收集所有块"""
        cfg = _get_active_api_config()
        engine = AIEngine(
            api_key=cfg["api_key"],
            base_url=cfg["base_url"],
            model=cfg["model"],
        )
        chunks = []

        result = engine.analyze_stream(
            prompt="请回答：什么是TCP协议？用一句话回答。",
            system_prompt="你是网络专家，简短回答。",
            on_chunk=lambda c: chunks.append(c),
            max_tokens=50,
        )

        assert isinstance(result, str)
        assert len(result) > 0
        assert len(chunks) > 0
        # 拼接所有块应等于最终结果
        assert "".join(chunks) == result


class TestAIEngineLargeInput:
    """超长输入测试——验证 API 错误能被正确传播"""

    def test_oversized_prompt_raises_api_error(self):
        """超长 prompt 应由 API 返回错误（不再做截断）"""
        from openai import BadRequestError

        cfg = _get_active_api_config()
        engine = AIEngine(
            api_key=cfg["api_key"],
            base_url=cfg["base_url"],
            model=cfg["model"],
        )
        long_prompt = "这是一段很长的数据。" * 50000  # ~30万字符
        with pytest.raises(BadRequestError):
            engine.analyze(
                prompt=long_prompt,
                max_tokens=10,
            )
