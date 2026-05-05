"""Layer 1 — 全量流量分析提示词模板（合并原快速分析 + 深度 Layer1）"""

LAYER1_TEMPLATE = """# 全量流量分析任务

## 抓包数据摘要

### 基本统计
- 总包数: {total_packets}
- 总字节: {total_bytes}
- 总流数: {total_flows}
- 抓包时长: {duration}s
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

### PPS 时间线（突发检测）
{pps_timeline}

## 全部流记录（每条流含采样包）
{all_flows_with_packets}

## 分析维度（必须逐一覆盖）

### 1. 流量画像
从统计数据推断网络类型（企业内网/家庭网络/数据中心等）和主要业务

### 2. 攻击行为检测
- **扫描行为**：同一源 IP 短时间内访问大量不同目标端口（SYN 扫描、Connect 扫描、UDP 扫描）
- **暴力破解**：同一目标端口的短流高频连接（SSH、RDP、HTTP 登录）
- **DDoS 特征**：大量不同源 IP 汇聚同一目标，或单一源的超大流量脉冲

### 3. 数据泄露检测
- **大流量外传**：内网 IP 向外部 IP 传输大量数据
- **DNS 隧道**：DNS 查询中异常长的子域名、高频 TXT/NULL 记录查询
- **明文传输**：敏感服务使用未加密协议（HTTP 登录、FTP、Telnet）

### 4. 横向移动检测
- **内网扫描**：内网 IP 对其他内网 IP 的大量端口探测
- **服务利用**：非管理源 IP 访问管理端口（445/SMB、3389/RDP、22/SSH）

### 5. TCP 健康分析
- 重传率是否影响业务（>5% Warning，>15% Critical）
- 零窗口是否表明接收端处理能力不足
- 重复 ACK 是否暗示丢包

### 6. DNS 解析健康
- 响应失败率（NXDOMAIN/SERVFAIL）
- 是否存在 DNS 服务器配置错误

### 7. ICMP 错误分析
- DestUnreachable/TimeExceeded 是否指向链路或路由问题
- Redirect 是否表明路由配置错误

### 8. 网络层异常
- TTL 异常（同源 IP TTL 方差过大 → 路由环路或不对称路由）
- IP 分片问题（重叠/不完整 → MTU 错配或攻击）

### 9. 流量突发分析
- PPS 峰值是否超出业务正常范围
- 突发时间模式分析

### 10. 二层异常
- ARP 欺骗（同 IP 多 MAC 冲突）
- 广播/组播占比是否异常

### 11. 协议异常检测
- **非标准端口服务**：高端口运行业务服务，或标准服务运行在非标准端口
- **TCP 异常**：异常 flag 组合、大量重传、零窗口、RST 风暴
- **通信模式异常**：应该加密的协议使用明文

### 12. 基线偏离检测
- 协议分布是否存在异常比例（如 DNS 占比异常高）
- 通信时间模式是否异常（如非工作时间的大量数据传输）

## 输出要求

1. 所有可疑流必须按置信度（从高到低）排列
2. 每个可疑流必须标注 flow_id，并说明需要深入分析的原因
3. 对于高置信度的安全问题，在 recommendation 中给出具体的处置步骤
4. 严格输出 JSON，不要包含 JSON 之外的文字或 markdown 代码块标记"""


def get_layer1_template() -> str:
    return LAYER1_TEMPLATE
