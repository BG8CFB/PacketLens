"""快速分析提示词模板"""

QUICK_ANALYSIS_TEMPLATE = """# 快速流量分析任务

## 抓包数据摘要

### 基本统计
- 总包数: {total_packets}
- 总字节: {total_bytes}
- 总流数: {total_flows}
- 抓包时长: {duration}s
- 平均带宽: {bandwidth_bps} bps

### 协议分布
{protocol_distribution}

### Top 源 IP（按包数排序）
{top_src}

### Top 目标 IP（按包数排序）
{top_dst}

### Top 20 活跃流
{flow_summary}

### 预处理异常标记
{anomaly_summary}

## 分析要求

基于以上摘要数据，按以下维度进行分析：

1. **流量画像**：从统计数据推断网络类型（企业内网/家庭网络/数据中心等）和主要业务
2. **异常发现**：结合预处理标记和流量特征，识别潜在安全风险
3. **协议洞察**：各协议的通信模式是否正常
4. **整体评估**：给出明确的整体安全评估等级

注意：快速分析基于摘要数据，无法做深度包级分析。如需进一步分析特定流，请将 affected_flows 中的 flow_id 标注在 issues 中。"""


def get_quick_template() -> str:
    return QUICK_ANALYSIS_TEMPLATE
