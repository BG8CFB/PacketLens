"""AI Engine 真实测试 — 调用真实 API（LangChain 版）"""

import logging

import pytest

from app.ai.ai_engine import AIEngine
from app.ai.result_parser import ResultParser
from app.storage.config_manager import ConfigManager


def _get_config() -> dict:
    """从 ConfigManager 获取当前激活 provider 的配置"""
    return ConfigManager().get_ai_config()


class TestAIEngineConnection:
    """真实 API 连接测试"""

    def test_connection_succeeds(self):
        """test_connection 应返回成功"""
        cfg = _get_config()
        engine = AIEngine(
            provider_type=cfg.get("provider_type", "openai"),
            api_key=cfg["api_key"],
            base_url=cfg["base_url"],
            model=cfg["model"],
        )
        ok, msg = engine.test_connection()
        assert ok is True, f"API 连接失败: {msg}"
        assert cfg["model"] in msg

    def test_invalid_api_key_fails(self):
        """错误的 API Key 应返回失败"""
        cfg = _get_config()
        engine = AIEngine(
            provider_type=cfg.get("provider_type", "openai"),
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
        cfg = _get_config()
        engine = AIEngine(
            provider_type=cfg.get("provider_type", "openai"),
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
        cfg = _get_config()
        engine = AIEngine(
            provider_type=cfg.get("provider_type", "openai"),
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
        assert len(result) > 20

        parser = ResultParser()
        parsed = parser.parse(result)
        assert parsed is not None


class TestAIEngineStream:
    """流式分析测试"""

    def test_stream_analyze_collects_chunks(self):
        """流式分析应收集所有块"""
        cfg = _get_config()
        engine = AIEngine(
            provider_type=cfg.get("provider_type", "openai"),
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
        assert "".join(chunks) == result


class TestAIEngineLargeInput:
    """超长输入测试——验证 API 错误能被正确传播"""

    def test_oversized_prompt_raises_api_error(self):
        """超长 prompt 应由 API 返回错误"""
        cfg = _get_config()
        engine = AIEngine(
            provider_type=cfg.get("provider_type", "openai"),
            api_key=cfg["api_key"],
            base_url=cfg["base_url"],
            model=cfg["model"],
        )
        long_prompt = "这是一段很长的数据。" * 50000  # ~30万字符
        with pytest.raises(Exception) as exc_info:
            engine.analyze(
                prompt=long_prompt,
                max_tokens=10,
            )
        error_msg = str(exc_info.value).lower()
        assert "token" in error_msg or "context" in error_msg or "limit" in error_msg


class TestAIEngineCloneForWorker:
    """clone_for_worker 方法测试"""

    def test_clone_preserves_config(self):
        """clone_for_worker 应保留所有配置参数"""
        cfg = _get_config()
        engine = AIEngine(
            provider_type=cfg.get("provider_type", "openai"),
            api_key=cfg["api_key"],
            base_url=cfg["base_url"],
            model=cfg["model"],
            max_tokens=2000,
            max_input_chars=50000,
        )
        clone = engine.clone_for_worker(max_tokens=1000)
        assert clone._provider_type == engine._provider_type
        assert clone._api_key == engine._api_key
        assert clone._model == engine._model
        assert clone._max_tokens == 1000
        assert clone._max_input_chars == 50000

    def test_clone_independent_llm_instance(self):
        """clone 应创建独立的 LLM 实例"""
        cfg = _get_config()
        engine = AIEngine(
            provider_type=cfg.get("provider_type", "openai"),
            api_key=cfg["api_key"],
            base_url=cfg["base_url"],
            model=cfg["model"],
        )
        clone = engine.clone_for_worker()
        assert clone._llm is not engine._llm

    def test_clone_can_invoke_real_api(self):
        """clone 的实例应能独立调用真实 API"""
        cfg = _get_config()
        engine = AIEngine(
            provider_type=cfg.get("provider_type", "openai"),
            api_key=cfg["api_key"],
            base_url=cfg["base_url"],
            model=cfg["model"],
        )
        clone = engine.clone_for_worker(max_tokens=20)
        result = clone.analyze(prompt="1+1=?", max_tokens=10)
        assert isinstance(result, str)
        assert len(result) > 0


class TestAIEngineMaxInputChars:
    """max_input_chars 输入长度安全检查测试"""

    def test_default_max_input_chars(self):
        """默认 max_input_chars 应从 AI_DEFAULTS 读取"""
        cfg = _get_config()
        engine = AIEngine(
            provider_type=cfg.get("provider_type", "openai"),
            api_key=cfg["api_key"],
            base_url=cfg["base_url"],
            model=cfg["model"],
        )
        assert engine._max_input_chars > 0

    def test_custom_max_input_chars(self):
        """自定义 max_input_chars 应生效"""
        cfg = _get_config()
        engine = AIEngine(
            provider_type=cfg.get("provider_type", "openai"),
            api_key=cfg["api_key"],
            base_url=cfg["base_url"],
            model=cfg["model"],
            max_input_chars=100,
        )
        assert engine._max_input_chars == 100

    def test_oversized_input_logs_warning(self, caplog):
        """超长输入应记录警告但不阻止调用"""
        cfg = _get_config()
        engine = AIEngine(
            provider_type=cfg.get("provider_type", "openai"),
            api_key=cfg["api_key"],
            base_url=cfg["base_url"],
            model=cfg["model"],
            max_input_chars=50,
        )
        # 发送一个超过 50 字符的 prompt
        long_prompt = "这是一段很长的数据，用于测试输入长度检查。" * 10

        with caplog.at_level(logging.WARNING):
            # 使用 analyze_stream 避免 API 调用超时
            try:
                engine.analyze(
                    prompt=long_prompt,
                    max_tokens=5,
                )
            except Exception:
                pass  # API 可能返回错误，但我们只关心警告日志

        assert any("超过安全上限" in r.message for r in caplog.records)

    def test_missing_api_key_raises_before_length_check(self):
        """缺少 API Key 应在长度检查之前报错"""
        engine = AIEngine(
            api_key="",
            max_input_chars=50,
        )
        with pytest.raises(ValueError, match="API Key"):
            engine.analyze(prompt="短文本")
