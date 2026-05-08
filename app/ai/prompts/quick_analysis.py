"""Layer 1 — 全量流量分析提示词模板（合并原快速分析 + 深度 Layer1）"""

LAYER1_TEMPLATE = """# 全量流量分析任务

## 抓包数据摘要

### 基本统计
- 总包数: {total_packets}
- 总字节: {total_bytes}
- 总流数: {total_flows}
- 抓包时长: {duration}s (时间段: {time_range})
- 平均带宽: {bandwidth_bps} bps
- 平均包大小: {avg_packet_size} bytes
- 平均流大小: {avg_flow_size} bytes
- 流大小中位数: {flow_size_median} bytes

### 协议分布
{protocol_distribution}

### Top 源 IP（按包数排序）
{top_src}

### Top 目标 IP（按包数排序）
{top_dst}

### Top 流量流（按字节数）
{top_flows}

### 预处理异常标记
{anomaly_summary}

### TCP 健康指标
{tcp_health}

### DNS 解析状态
{dns_health}

### ICMP 错误统计
{icmp_errors}

### TTL 分布与路由异常
{ttl_distribution}

### IP 分片统计
{fragment_stats}

### 广播/组播/ARP 统计
{broadcast_multicast}

### PPS 时间线（突发检测）
{pps_timeline}

## 全部流记录（每条流含采样包）
{all_flows_with_packets}

## 分析维度（根据实际数据选择性分析，仅在发现证据时输出对应 issue）

### 1. 流量画像
从统计数据推断网络类型（企业内网/家庭网络/数据中心等）和主要业务，建立基线。

### 2. 网络故障检测
根据以下信号判断网络是否存在故障，**仅在数据中观察到明确证据时才报告**：
- **TCP 健康**：重传率（>5% Warning，>15% Critical）、零窗口、重复 ACK、RST 风暴
- **DNS 解析**：失败率（NXDOMAIN/SERVFAIL）、DNS 服务器配置错误
- **ICMP 错误**：DestUnreachable（链路/端口不可达）、TimeExceeded（路由环路/黑洞）、Redirect（路由配置错误）
- **路由/TTL**：同源 IP TTL 跨度过大（路由环路/不对称路由）
- **IP 分片**：重叠分片（MTU 错配/分片攻击）、不完整分片集
- **突发流量**：PPS 峰值是否远超正常基线（突刺比异常）
- **二层/ARP**：ARP 欺骗（同 IP 多 MAC）、ARP 泛洪（请求/应答比例异常）、广播风暴、组播泛洪

### 3. 安全威胁检测
根据以下信号判断是否存在安全威胁，**仅在数据中观察到明确证据时才报告**：
- **扫描/暴力破解**：同一源 IP 短时间内访问大量不同目标端口、同一目标端口高频短流
- **DDoS**：大量不同源 IP 汇聚同一目标、单一源超大流量脉冲
- **数据泄露**：内网 IP 向外部 IP 传输大量数据、DNS 隧道（异常长子域名/高频 TXT 查询）
- **横向移动**：内网扫描、非管理源访问管理端口（445/3389/22）
- **明文凭证**：敏感服务使用未加密协议（HTTP 登录、FTP、Telnet）

### 4. 协议异常与基线偏离
- 非标准端口服务、异常 TCP flag 组合、应该加密的协议使用明文
- 协议分布异常比例、通信时间模式异常

## 输出要求

1. **基于证据**：仅在实际发现问题时才产生 issues 条目，禁止无证据的猜测
2. 所有可疑流必须按置信度（从高到低）排列
3. 每个可疑流必须标注 flow_id，并说明需要深入分析的原因
4. 对于高置信度的问题，在 recommendation 中给出具体的处置步骤
5. **故障排查清单**：在 overall_assessment 中必须逐项说明以下故障的检测结果，未发现的也要写"未发现XX"：
   广播风暴、组播泛洪、ARP欺骗、ARP泛洪、TCP重传异常、TCP零窗口、RST风暴、DNS解析故障、ICMP错误风暴、TTL异常/路由环路、IP分片异常、突发流量异常
6. 严格输出 JSON，不要包含 JSON 之外的文字或 markdown 代码块标记"""


def get_layer1_template(override: str | None = None) -> str:
    return override if override else LAYER1_TEMPLATE
