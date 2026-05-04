"""AI 分析 Worker — QThread 后台 AI 调用"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone

from PySide6.QtCore import QThread, Signal

from app.ai.ai_engine import AIEngine
from app.ai.prompt_builder import PromptBuilder
from app.ai.result_parser import ResultParser
from app.config.ai_defaults import AI_DEFAULTS
from app.models.analysis_result import AnalysisResult
from app.models.flow_record import FlowRecord
from app.models.packet_record import PacketRecord

logger = logging.getLogger(__name__)

# 深度分析 Layer 2 最多钻取的可疑流数
MAX_LAYER2_FLOWS = 3


class AnalysisWorker(QThread):
    """后台 AI 分析线程

    通过 Qt 信号流式返回进度和最终结果。
    使用 requestInterruption() + isInterruptionRequested() 实现可靠取消。
    """

    analysis_started = Signal()
    analysis_progress = Signal(str)  # 流式文本块
    analysis_completed = Signal(object)  # AnalysisResult
    analysis_error = Signal(str)

    def __init__(
        self,
        engine: AIEngine,
        prompt_builder: PromptBuilder,
        result_parser: ResultParser,
        mode: str = "quick",
        flows: list[FlowRecord] | None = None,
        stats: dict | None = None,
        anomalies: list[dict] | None = None,
        packets: list[PacketRecord] | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        parent=None,
    ):
        super().__init__(parent)
        self._engine = engine
        self._prompt_builder = prompt_builder
        self._result_parser = result_parser
        self._mode = mode
        self._flows = flows or []
        self._stats = stats or {}
        self._anomalies = anomalies or []
        self._packets = packets or []
        self._temperature = temperature if temperature is not None else AI_DEFAULTS["temperature"]
        self._max_tokens = max_tokens if max_tokens is not None else AI_DEFAULTS["max_tokens"]

    def run(self) -> None:
        """执行分析"""
        session_id = str(uuid.uuid4())[:8]
        self.analysis_started.emit()

        try:
            if self._mode == "quick":
                result = self._run_quick(session_id)
            else:
                result = self._run_deep(session_id)

            if not self.isInterruptionRequested():
                self.analysis_completed.emit(result)
            else:
                logger.info("AI 分析已被取消")

        except ConnectionError as e:
            error_msg = f"网络连接失败，请检查网络: {str(e)[:200]}"
            logger.error(error_msg)
            self.analysis_error.emit(error_msg)

        except TimeoutError as e:
            error_msg = f"AI 请求超时，请稍后重试: {str(e)[:200]}"
            logger.error(error_msg)
            self.analysis_error.emit(error_msg)

        except ImportError:
            error_msg = "OpenAI SDK 未安装，请运行: pip install openai"
            logger.error(error_msg)
            self.analysis_error.emit(error_msg)

        except Exception as e:
            if not self.isInterruptionRequested():
                error_type = type(e).__name__
                error_msg = str(e)[:200]
                # 识别常见 OpenAI SDK 异常
                if "auth" in error_msg.lower() or "api key" in error_msg.lower():
                    user_msg = f"API 认证失败，请检查 API Key 设置"
                elif "rate" in error_msg.lower() or "limit" in error_msg.lower():
                    user_msg = f"API 调用频率超限，请稍后重试"
                elif "context" in error_msg.lower() or "token" in error_msg.lower():
                    user_msg = f"输入内容超出模型上下文窗口，请减少抓包量"
                else:
                    user_msg = f"AI 分析失败 ({error_type}): {error_msg}"
                logger.error(user_msg)
                self.analysis_error.emit(user_msg)

    def _run_quick(self, session_id: str) -> AnalysisResult:
        """快速模式：单次分析"""
        start = time.time()

        user_prompt, system_prompt = self._prompt_builder.build_quick_prompt(
            self._flows, self._stats, self._anomalies,
        )

        response_text = self._engine.analyze_stream(
            prompt=user_prompt,
            system_prompt=system_prompt,
            on_chunk=lambda chunk: (
                None if self.isInterruptionRequested()
                else self.analysis_progress.emit(chunk)
            ),
            temperature=self._temperature,
            max_tokens=self._max_tokens,
        )

        elapsed = time.time() - start

        result = self._result_parser.parse(response_text, session_id, "quick")
        result.duration_seconds = elapsed
        result.token_usage = self._engine.last_usage
        return result

    def _run_deep(self, session_id: str) -> AnalysisResult:
        """深度模式：Layer 1 宏观概览 + Layer 2 可疑流钻取"""
        start = time.time()

        # ── Layer 1: 宏观概览 ──
        if self.isInterruptionRequested():
            return self._empty_result(session_id, "deep", start)

        user_prompt, system_prompt = self._prompt_builder.build_deep_layer1_prompt(
            self._flows, self._stats, self._anomalies,
        )

        self.analysis_progress.emit("[Layer 1/宏观概览]\n")
        layer1_text = self._engine.analyze_stream(
            prompt=user_prompt,
            system_prompt=system_prompt,
            on_chunk=lambda chunk: (
                None if self.isInterruptionRequested()
                else self.analysis_progress.emit(chunk)
            ),
            temperature=self._temperature,
            max_tokens=self._max_tokens,
        )

        if self.isInterruptionRequested():
            return self._empty_result(session_id, "deep", start)

        layer1_result = self._result_parser.parse(layer1_text, session_id, "deep")

        # ── Layer 2: 可疑流逐包钻取 ──
        suspicious_flows = self._extract_suspicious_flows(layer1_result)
        if suspicious_flows and self._packets:
            layer2_count = min(len(suspicious_flows), MAX_LAYER2_FLOWS)
            for i, flow in enumerate(suspicious_flows[:layer2_count]):
                if self.isInterruptionRequested():
                    break

                self.analysis_progress.emit(
                    f"\n\n[Layer 2/{i + 1}] 分析流 {flow.src_ip}:{flow.src_port} → "
                    f"{flow.dst_ip}:{flow.dst_port}\n"
                )
                try:
                    layer2_result = self._run_layer2_single(flow, session_id)
                    layer1_result.issues.extend(layer2_result.issues)
                except Exception as e:
                    logger.warning(f"Layer 2 分析流 {flow.flow_id} 失败: {e}")

        elapsed = time.time() - start
        layer1_result.duration_seconds = elapsed
        layer1_result.token_usage = self._engine.last_usage
        return layer1_result

    def _run_layer2_single(self, flow: FlowRecord, session_id: str) -> AnalysisResult:
        """对单条流执行 Layer 2 深度分析"""
        user_prompt, system_prompt = self._prompt_builder.build_deep_layer2_prompt(
            flow=flow,
            packets=self._packets,
            context=f"来自 Layer 1 宏观分析的可疑流",
        )

        response_text = self._engine.analyze_stream(
            prompt=user_prompt,
            system_prompt=system_prompt,
            on_chunk=lambda chunk: (
                None if self.isInterruptionRequested()
                else self.analysis_progress.emit(chunk)
            ),
            temperature=self._temperature,
            max_tokens=self._max_tokens,
        )

        return self._result_parser.parse(response_text, session_id, "deep")

    def _extract_suspicious_flows(self, result: AnalysisResult) -> list[FlowRecord]:
        """从 Layer 1 结果中提取需要钻取的可疑流"""
        if not result.issues or not self._flows:
            return []

        mentioned_ids: set[str] = set()
        for issue in result.issues:
            if issue.severity in ("Critical", "Warning"):
                mentioned_ids.update(issue.affected_flows)

        flow_map = {f.flow_id: f for f in self._flows}
        suspicious: list[FlowRecord] = []
        for fid in mentioned_ids:
            if fid in flow_map:
                suspicious.append(flow_map[fid])

        if not suspicious:
            for anomaly in self._anomalies:
                for fid in anomaly.get("affected_flows", []):
                    if fid in flow_map and flow_map[fid] not in suspicious:
                        suspicious.append(flow_map[fid])

        return suspicious

    @staticmethod
    def _empty_result(session_id: str, mode: str, start: float) -> AnalysisResult:
        """取消时返回空结果"""
        return AnalysisResult(
            session_id=session_id,
            analysis_mode=mode,
            timestamp=datetime.now(tz=timezone.utc),
            summary="分析已被取消",
            issues=[],
            raw_ai_response="",
            duration_seconds=time.time() - start,
        )
