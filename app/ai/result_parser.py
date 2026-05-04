"""AI 响应结果解析器"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone

from app.models.analysis_result import AnalysisIssue, AnalysisResult, FlowAnalysis

VALID_SEVERITIES = frozenset({"Critical", "Warning", "Info", "Normal"})
VALID_CATEGORIES = frozenset({
    "Security", "Performance", "Anomaly", "Protocol", "Configuration", "General", "System",
})

_SEVERITY_ALIASES = {
    "Crit": "Critical",
    "Warn": "Warning",
    "Informational": "Info",
    "Information": "Info",
}

_CATEGORY_ALIASES = {
    "Net": "Anomaly",
    "Traffic": "Anomaly",
    "Malware": "Security",
    "Vuln": "Security",
}


def normalize_severity(value: str) -> str:
    """规范化严重级别：去除空白、首字母大写、映射常见变体"""
    cleaned = value.strip().title()
    if cleaned in VALID_SEVERITIES:
        return cleaned
    return _SEVERITY_ALIASES.get(cleaned, "Info")


def normalize_category(value: str) -> str:
    """规范化分类"""
    cleaned = value.strip().title()
    if cleaned in VALID_CATEGORIES:
        return cleaned
    return _CATEGORY_ALIASES.get(cleaned, "General")

logger = logging.getLogger(__name__)


class ResultParser:
    """解析 AI 返回的 JSON 结果

    支持多种格式：
    - 纯 JSON
    - ```json ... ``` 代码块包裹
    - JSON 前后有额外文字
    """

    def parse(self, response_text: str, session_id: str = "", mode: str = "quick") -> AnalysisResult:
        """解析 AI 响应文本为结构化结果"""
        parsed = self._extract_json(response_text)

        if parsed is None:
            # 解析失败，优雅降级
            return self._fallback_result(response_text, session_id, mode)

        return self._build_result(parsed, response_text, session_id, mode)

    def _extract_json(self, text: str) -> dict | None:
        """从响应文本中提取 JSON"""
        # 尝试 1: 直接解析
        text = text.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # 尝试 2: 提取 ```json ... ``` 代码块
        pattern = r"```(?:json)?\s*\n?(.*?)\n?\s*```"
        match = re.search(pattern, text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1).strip())
            except json.JSONDecodeError:
                pass

        # 尝试 3: 找最外层 { }
        brace_start = text.find("{")
        brace_end = text.rfind("}")
        if brace_start != -1 and brace_end > brace_start:
            try:
                return json.loads(text[brace_start : brace_end + 1])
            except json.JSONDecodeError:
                pass

        return None

    def _build_result(self, parsed: dict, raw: str, session_id: str, mode: str) -> AnalysisResult:
        """从解析后的字典构建 AnalysisResult"""
        issues = []
        for item in parsed.get("issues", []):
            if not isinstance(item, dict):
                continue
            issues.append(
                AnalysisIssue(
                    severity=normalize_severity(item.get("severity", "Info")),
                    category=normalize_category(item.get("category", "General")),
                    title=item.get("title", "未命名"),
                    description=item.get("description", ""),
                    affected_flows=item.get("affected_flows", []),
                    affected_ips=item.get("affected_ips", []),
                    recommendation=item.get("recommendation", ""),
                )
            )

        return AnalysisResult(
            session_id=session_id,
            analysis_mode=mode,
            timestamp=datetime.now(tz=timezone.utc),
            summary=parsed.get("summary", ""),
            issues=issues,
            protocol_insights=parsed.get("protocol_insights", {}),
            overall_assessment=parsed.get("overall_assessment", ""),
            raw_ai_response=raw,
            risk_level=parsed.get("risk_level", ""),
        )

    def parse_layer2(self, response_text: str) -> FlowAnalysis:
        """解析 Layer 2 单流分析响应为 FlowAnalysis"""
        parsed = self._extract_json(response_text)

        if parsed is None:
            return FlowAnalysis(
                flow_id="",
                verdict="inconclusive",
                confidence=0.0,
                evidence=[],
                raw_text=response_text,
            )

        # 提取 verdict 并规范化
        raw_verdict = parsed.get("verdict", "inconclusive").strip().lower()
        verdict = raw_verdict if raw_verdict in FlowAnalysis.VALID_VERDICTS else "inconclusive"

        # 提取 confidence 并钳位到 [0.0, 1.0]
        try:
            confidence = max(0.0, min(1.0, float(parsed.get("confidence", 0.0))))
        except (TypeError, ValueError):
            confidence = 0.0

        # 提取 issues
        issues = []
        for item in parsed.get("issues", []):
            if not isinstance(item, dict):
                continue
            issues.append(
                AnalysisIssue(
                    severity=normalize_severity(item.get("severity", "Info")),
                    category=normalize_category(item.get("category", "General")),
                    title=item.get("title", "未命名"),
                    description=item.get("description", ""),
                    affected_flows=item.get("affected_flows", []),
                    affected_ips=item.get("affected_ips", []),
                    recommendation=item.get("recommendation", ""),
                )
            )

        # 提取 evidence
        evidence = parsed.get("evidence", [])
        if not isinstance(evidence, list):
            evidence = [str(evidence)]

        return FlowAnalysis(
            flow_id=parsed.get("flow_id", ""),
            verdict=verdict,
            confidence=confidence,
            issues=issues,
            evidence=evidence,
            raw_text=response_text,
        )

    def _fallback_result(self, raw: str, session_id: str, mode: str) -> AnalysisResult:
        """JSON 解析失败时的降级处理"""
        return AnalysisResult(
            session_id=session_id,
            analysis_mode=mode,
            timestamp=datetime.now(tz=timezone.utc),
            summary="AI 响应解析失败，显示原始内容",
            issues=[
                AnalysisIssue(
                    severity="Info",
                    category="System",
                    title="AI 响应解析失败",
                    description=raw[:500],
                    recommendation="请检查 AI 输出格式设置",
                    raw_detail=raw,
                )
            ],
            raw_ai_response=raw,
        )
