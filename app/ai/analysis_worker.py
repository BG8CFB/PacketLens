"""AI 分析 Worker — 三层渐进式架构

Layer 1: 全量流量分析（全部流 + 每流 5 包采样）
Layer 2: 可疑流并行深度分析（线程池并发）
Layer 3: 综合安全报告（汇总 Layer1 + Layer2）
"""

from __future__ import annotations

import logging
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from PySide6.QtCore import QThread, Signal

from app.ai.ai_engine import AIEngine
from app.ai.prompt_builder import PromptBuilder
from app.ai.result_parser import ResultParser
from app.config.ai_defaults import AI_DEFAULTS
from app.models.analysis_result import AnalysisResult, FlowAnalysis
from app.models.flow_record import FlowRecord
from app.models.packet_record import PacketRecord

logger = logging.getLogger(__name__)

# Layer 2 最多钻取的可疑流数（默认值，优先使用 AI_DEFAULTS）
MAX_LAYER2_FLOWS = AI_DEFAULTS["max_layer2_flows"]


class AnalysisWorker(QThread):
    """后台 AI 分析线程

    快速模式：仅执行 Layer 1
    深度模式：Layer 1 → Layer 2（并行）→ Layer 3

    通过 Qt 信号流式返回进度和最终结果。
    """

    analysis_started = Signal()
    analysis_progress = Signal(str)
    analysis_completed = Signal(object)  # AnalysisResult
    analysis_error = Signal(str)
    analysis_stage = Signal(str)  # 阶段描述（如 "Layer 1/3: 整体流量概览"）

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
        max_concurrency: int | None = None,
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
        self._max_concurrency = max_concurrency if max_concurrency is not None else AI_DEFAULTS["max_concurrency"]

    def run(self) -> None:
        """执行分析"""
        session_id = str(uuid.uuid4())[:8]
        self.analysis_started.emit()

        try:
            if self._mode == "quick":
                result = self._run_layer1_only(session_id)
            else:
                result = self._run_full_deep(session_id)

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
            error_msg = "LangChain 依赖未安装，请运行: pip install langchain-openai langchain-anthropic"
            logger.error(error_msg)
            self.analysis_error.emit(error_msg)

        except ValueError as e:
            # API Key 未配置等参数校验错误
            error_msg = str(e)[:200]
            logger.error(f"AI 分析参数错误: {error_msg}")
            self.analysis_error.emit(error_msg)

        except Exception as e:
            if not self.isInterruptionRequested():
                error_type = type(e).__name__
                error_msg = str(e)[:200]
                if "auth" in error_msg.lower() or "api key" in error_msg.lower() or "unauthorized" in error_msg.lower():
                    user_msg = "API 认证失败，请检查 API Key 设置"
                elif "rate" in error_msg.lower() or "limit" in error_msg.lower() or "429" in error_msg:
                    user_msg = "API 调用频率超限，请稍后重试"
                elif "context" in error_msg.lower() or "token" in error_msg.lower() or "not found" in error_msg.lower() or "404" in error_msg:
                    user_msg = "输入内容超出模型上下文窗口，请减少抓包量"
                elif "connection" in error_msg.lower() or "network" in error_msg.lower():
                    user_msg = "网络连接异常，请检查网络设置"
                else:
                    user_msg = f"AI 分析失败 ({error_type}): {error_msg}"
                logger.error(user_msg)
                self.analysis_error.emit(user_msg)

    # ── Layer 1: 全量分析 ──

    def _run_layer1_only(self, session_id: str) -> AnalysisResult:
        """快速模式：仅执行 Layer 1"""
        start = time.time()
        self.analysis_stage.emit("Layer 1/1: 整体流量概览分析中...")

        user_prompt, system_prompt = self._prompt_builder.build_layer1_prompt(
            self._flows, self._packets, self._stats, self._anomalies,
        )

        interrupted = False
        def on_chunk_wrapper(chunk: str) -> None:
            nonlocal interrupted
            if self.isInterruptionRequested():
                interrupted = True
                return
            self.analysis_progress.emit(chunk)

        response_text = self._engine.analyze_stream(
            prompt=user_prompt,
            system_prompt=system_prompt,
            on_chunk=on_chunk_wrapper,
            temperature=self._temperature,
            max_tokens=self._max_tokens,
        )

        if interrupted or self.isInterruptionRequested():
            return self._empty_result(session_id, "quick", start)

        elapsed = time.time() - start
        result = self._result_parser.parse(response_text, session_id, "quick")
        result.duration_seconds = elapsed
        result.token_usage = self._engine.last_usage
        return result

    # ── 深度模式：Layer 1 → 2 → 3 ──

    def _run_full_deep(self, session_id: str) -> AnalysisResult:
        """深度模式：三层全量分析"""
        start = time.time()

        # ── Layer 1: 全量分析 ──
        if self.isInterruptionRequested():
            return self._empty_result(session_id, "deep", start)

        self.analysis_stage.emit("Layer 1/3: 整体流量概览分析中...")
        self.analysis_progress.emit("[Layer 1/全量分析]\n")
        user_prompt, system_prompt = self._prompt_builder.build_layer1_prompt(
            self._flows, self._packets, self._stats, self._anomalies,
        )

        layer1_interrupted = False
        def on_chunk_layer1(chunk: str) -> None:
            nonlocal layer1_interrupted
            if self.isInterruptionRequested():
                layer1_interrupted = True
                return
            self.analysis_progress.emit(chunk)

        layer1_text = self._engine.analyze_stream(
            prompt=user_prompt,
            system_prompt=system_prompt,
            on_chunk=on_chunk_layer1,
            temperature=self._temperature,
            max_tokens=self._max_tokens,
        )

        if layer1_interrupted or self.isInterruptionRequested():
            return self._empty_result(session_id, "deep", start)

        layer1_result = self._result_parser.parse(layer1_text, session_id, "deep")

        # ── Layer 2: 可疑流并行深度分析 ──
        suspicious_flows = self._extract_suspicious_flows(layer1_result)
        layer2_texts: list[str] = []
        flow_analyses: list[FlowAnalysis] = []

        if suspicious_flows and self._packets:
            layer2_count = min(len(suspicious_flows), MAX_LAYER2_FLOWS)
            self.analysis_stage.emit(
                f"Layer 2/3: 深度分析可疑流 ({layer2_count} 条)..."
            )
            self.analysis_progress.emit(
                f"\n\n[Layer 2/可疑流分析] 发现 {len(suspicious_flows)} 条可疑流，"
                f"并行分析 {layer2_count} 条...\n"
            )

            layer2_texts, flow_analyses = self._run_layer2_parallel(
                suspicious_flows[:layer2_count], layer1_result, layer1_text,
            )

        if self.isInterruptionRequested():
            return self._empty_result(session_id, "deep", start)

        # ── Layer 3: 综合报告 ──
        confirmed_count = self._count_confirmed_issues(layer1_result)
        self.analysis_stage.emit("Layer 3/3: 综合安全报告生成中...")
        self.analysis_progress.emit("\n\n[Layer 3/综合报告]\n")

        user_prompt, system_prompt = self._prompt_builder.build_layer3_prompt(
            layer1_raw=layer1_text,
            layer2_results=layer2_texts,
            stats=self._stats,
            suspicious_flow_count=len(suspicious_flows),
            confirmed_flow_count=confirmed_count,
        )

        layer3_interrupted = False
        def on_chunk_layer3(chunk: str) -> None:
            nonlocal layer3_interrupted
            if self.isInterruptionRequested():
                layer3_interrupted = True
                return
            self.analysis_progress.emit(chunk)

        layer3_text = self._engine.analyze_stream(
            prompt=user_prompt,
            system_prompt=system_prompt,
            on_chunk=on_chunk_layer3,
            temperature=self._temperature,
            max_tokens=self._max_tokens,
        )

        if layer3_interrupted or self.isInterruptionRequested():
            return self._empty_result(session_id, "deep", start)

        elapsed = time.time() - start

        # 最终结果使用 Layer 3 的解析，合并所有 issues
        final_result = self._result_parser.parse(layer3_text, session_id, "deep")

        # 存入 Layer 2 逐流分析结果
        final_result.flow_analyses = flow_analyses

        # 把 Layer 2 发现的 issues 也合并进来（按 title+affected_flows 去重）
        existing_keys = {
            (i.title, tuple(sorted(i.affected_flows)))
            for i in final_result.issues
        }
        for l2_text in layer2_texts:
            l2_parsed = self._result_parser.parse(l2_text, session_id, "deep")
            for issue in l2_parsed.issues:
                key = (issue.title, tuple(sorted(issue.affected_flows)))
                if key not in existing_keys:
                    final_result.issues.append(issue)
                    existing_keys.add(key)

        final_result.duration_seconds = elapsed
        final_result.token_usage = self._engine.last_usage
        return final_result

    def _run_layer2_parallel(
        self,
        flows: list[FlowRecord],
        layer1_result: AnalysisResult,
        layer1_text: str,
    ) -> tuple[list[str], list[FlowAnalysis]]:
        """并行执行 Layer 2 分析，返回原始响应文本和 FlowAnalysis 列表

        使用线程池并发，并发数受 max_concurrency 限制。
        每个 Worker 线程独立创建 AIEngine 副本以保证线程安全。
        """
        results: dict[int, str] = {}
        context = self._build_layer2_context(layer1_result, layer1_text)

        def analyze_single_flow(idx: int, flow: FlowRecord) -> tuple[int, str]:
            """单条流的分析任务（在工作线程中执行）"""
            try:
                worker_engine = self._engine.clone_for_worker(max_tokens=self._max_tokens)

                user_prompt, system_prompt = self._prompt_builder.build_layer2_prompt(
                    flow=flow,
                    packets=self._packets,
                    context=context,
                )

                response = worker_engine.analyze_stream(
                    prompt=user_prompt,
                    system_prompt=system_prompt,
                    on_chunk=None,  # 并行时不逐块 emit，避免信号跨线程
                    temperature=self._temperature,
                    max_tokens=self._max_tokens,
                )
                return idx, response

            except Exception as e:
                logger.warning(f"Layer 2 分析流 {flow.flow_id} 失败: {e}")
                return idx, f"分析失败: {str(e)[:200]}"

        workers = min(len(flows), self._max_concurrency)
        logger.info(f"Layer 2 并行分析: {len(flows)} 条流, {workers} 并发")

        # 每条流开始前通知 UI
        for i, flow in enumerate(flows):
            self.analysis_progress.emit(
                f"  → 分析: {flow.src_ip}:{flow.src_port} → "
                f"{flow.dst_ip}:{flow.dst_port}\n"
            )

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(analyze_single_flow, i, flow): i
                for i, flow in enumerate(flows)
            }

            completed = 0
            for future in as_completed(futures):
                if self.isInterruptionRequested():
                    pool.shutdown(wait=False, cancel_futures=True)
                    break
                try:
                    idx, text = future.result()
                    results[idx] = text
                    completed += 1
                    flow = flows[idx]
                    self.analysis_progress.emit(
                        f"\n  [完成 {completed}/{len(flows)}] "
                        f"{flow.src_ip}:{flow.src_port} → {flow.dst_ip}:{flow.dst_port}\n"
                    )
                except Exception as e:
                    logger.warning(f"Layer 2 任务异常: {e}")

        # 按原始顺序返回原始文本
        ordered_texts = [results[i] for i in sorted(results.keys()) if i in results]

        # 解析每条流的 Layer 2 结果为 FlowAnalysis
        flow_analyses = []
        for text in ordered_texts:
            flow_analysis = self._result_parser.parse_layer2(text)
            flow_analyses.append(flow_analysis)

        return ordered_texts, flow_analyses

    @staticmethod
    def _build_layer2_context(
        layer1_result: AnalysisResult,
        layer1_text: str,
        max_chars: int = 3000,
    ) -> str:
        """构建 Layer 2 结构化上下文，比直接截断更信息密集"""
        parts: list[str] = ["来自 Layer 1 全量分析的可疑流。\n"]

        # 优先加入摘要
        if layer1_result.summary:
            parts.append(f"Layer 1 摘要: {layer1_result.summary}\n")

        # 加入按严重性排序的 issue 列表
        severity_order = {"Critical": 0, "Warning": 1, "Info": 2, "Normal": 3}
        sorted_issues = sorted(
            layer1_result.issues,
            key=lambda i: severity_order.get(i.severity, 99),
        )
        if sorted_issues:
            parts.append("Layer 1 发现的问题:")
            for issue in sorted_issues:
                flows_str = ", ".join(issue.affected_flows[:5])
                if len(issue.affected_flows) > 5:
                    flows_str += f" 等{len(issue.affected_flows)}个"
                parts.append(
                    f"  [{issue.severity}] {issue.title} (相关流: {flows_str})"
                )
            parts.append("")

        structured = "\n".join(parts)
        remaining = max_chars - len(structured)
        if remaining > 200 and layer1_text:
            structured += f"\nLayer 1 原始分析（截取）:\n{layer1_text[:remaining]}"

        return structured[:max_chars]

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

        # 回退：如果 AI 没标记任何流，用异常标记兜底
        if not suspicious:
            for anomaly in self._anomalies:
                for fid in anomaly.get("affected_flows", []):
                    if fid in flow_map and flow_map[fid] not in suspicious:
                        suspicious.append(flow_map[fid])

        return suspicious

    @staticmethod
    def _count_confirmed_issues(result: AnalysisResult) -> int:
        """统计确认的异常流数量"""
        flow_ids: set[str] = set()
        for issue in result.issues:
            if issue.severity in ("Critical", "Warning"):
                flow_ids.update(issue.affected_flows)
        return len(flow_ids)

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
