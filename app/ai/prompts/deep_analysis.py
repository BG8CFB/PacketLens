"""Layer 2 — 可疑流逐包分析 + Layer 3 — 综合报告 提示词模板"""

LAYER2_TEMPLATE = """# 单流逐包级深度分析

## 任务目标
对指定网络流进行逐包级精细分析，验证上层分析中标记的疑似异常，给出确定性结论。

## 待分析流信息
- Flow ID: {flow_id}
- 源端点: {src_ip}:{src_port}
- 目标端点: {dst_ip}:{dst_port}
- 协议: {protocol}
- 包数: {packet_count}
- 字节数: {byte_count}
- 持续时间: {duration}s
- TCP Flags: {flags}

## 该流的关键数据包（采样）
{packets_detail}

## 上层分析上下文
{context}

## 逐包分析维度

### 1. 时序分析
- 包间间隔模式是否正常（突发 burst、规律性心跳、长间隙）
- 传输速率是否与协议/服务的预期匹配

### 2. 载荷分析
- 是否存在明文敏感信息（密码、Token、内部 IP）
- 数据传输方向是否合理（请求/响应比例）
- 是否存在可疑的应用层特征

### 3. 协议合规性
- TCP 会话是否完整（SYN/SYN-ACK/FIN 或 RST）
- 是否存在协议违规（如 HTTP 在非 HTTP 端口）
- TLS/SSL 协商是否正常（如适用）

### 4. 行为判定
- 确认异常 / 误报 / 需更多信息
- 如果是误报，说明原因

## 输出要求

1. 给出明确的正常性评估结论
2. 如确认异常，描述具体攻击类型或风险
3. 引用原始数据包中的关键特征作为证据（引用具体包序号）
4. 严格输出 JSON，格式如下：

{{
  "flow_id": "当前流的 ID",
  "verdict": "malicious|suspicious|benign|inconclusive",
  "confidence": 0.0-1.0,
  "issues": [
    {{
      "severity": "Critical|Warning|Info",
      "category": "Security|Performance|Anomaly|Protocol",
      "title": "问题标题",
      "description": "详细分析：现象 → 证据（引用包序号） → 影响",
      "affected_flows": ["当前流的 flow_id"],
      "recommendation": "处置步骤"
    }}
  ],
  "evidence": ["关键证据列表"]
}}"""


LAYER3_TEMPLATE = """# 综合安全报告生成

## 任务目标
基于 Layer 1 全量分析和 Layer 2 可疑流逐包诊断结果，生成最终综合安全报告。

## Layer 1 全量分析结果
{layer1_result}

## Layer 2 可疑流诊断结果
{layer2_results}

## 统计概览
- 总包数: {total_packets}
- 总流数: {total_flows}
- 可疑流数: {suspicious_flow_count}
- 确认异常流数: {confirmed_flow_count}

## 输出要求

生成一份结构化的综合安全报告，包含：

1. **执行摘要**：一句话概括整体安全状况
2. **关键发现**：按严重级别排列的所有确认问题
3. **威胁图谱**：各威胁类型的分布和关联关系
4. **受影响资产**：列出涉及的 IP 和服务
5. **处置建议**：按优先级排列的具体操作步骤
6. **监控建议**：需要持续关注的行为模式

严格输出 JSON，格式如下：

{{
  "summary": "一句话执行摘要",
  "risk_level": "Critical|High|Medium|Low|Normal",
  "issues": [
    {{
      "severity": "Critical|Warning|Info",
      "category": "Security|Performance|Anomaly|Protocol|Configuration",
      "title": "问题标题",
      "description": "综合分析描述",
      "affected_flows": ["flow_id_1"],
      "affected_ips": ["ip1", "ip2"],
      "recommendation": "具体处置步骤"
    }}
  ],
  "protocol_insights": {{
    "tcp_analysis": "TCP 分析总结",
    "udp_analysis": "UDP 分析总结",
    "dns_analysis": "DNS 分析总结"
  }},
  "overall_assessment": "整体评估和下一步建议"
}}"""


def get_layer2_template() -> str:
    return LAYER2_TEMPLATE


def get_layer3_template() -> str:
    return LAYER3_TEMPLATE
