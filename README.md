# PacketLens

**Windows 桌面抓包工具 + AI 流量分析**

PacketLens 是一款面向网络安全从业者和开发者的本地抓包分析工具。基于 Scapy 实时抓包，结合大语言模型（LLM）自动识别异常流量、生成安全分析报告，无需手动逐包排查。

## 特性

- **实时抓包** — 基于 Scapy 的底层抓包，支持 BPF 过滤语法，自动检测网卡
- **PCAP 存储** — 抓包同时自动写入 PCAP 文件，支持事后回放
- **三层 AI 分析** — 全量概览 → 可疑流深度分析 → 综合安全报告，渐进式分析
- **多 LLM 支持** — 内置 OpenAI / Anthropic 协议，兼容所有 OpenAI 格式中转 API
- **流量预处理** — 流聚合、统计计算、异常标记、协议分类、风暴检测、故障检测
- **流式输出** — AI 分析结果实时流式显示，无需等待分析完成
- **可视化界面** — PySide6 原生桌面体验，数据包表格、流视图、分析面板

## 快速开始

### 前置条件

- **Python 3.11+**
- **Npcap**（[下载](https://npcap.com/)，安装时勾选 "Install Npcap in WinPcap API-compatible Mode"）
- Windows 10/11

### 安装

```bash
# 创建 Conda 环境
conda create -n packetlens python=3.11 -y
conda activate packetlens

# 安装依赖
pip install -r requirements.txt
```

### 配置 AI

复制 `.env.example` 为 `.env`，填入你的 API Key：

```bash
cp .env.example .env
```

关键字段：

| 变量 | 说明 | 示例 |
|------|------|------|
| `AI_NAME` | Provider 名称 | `DeepSeek` |
| `AI_API_KEY` | API 密钥 | `sk-...` |
| `AI_API_BASE` | API 地址 | `https://api.deepseek.com/v1` |
| `AI_MODEL` | 模型名称 | `deepseek-chat` |
| `AI_PROVIDER_TYPE` | 协议类型 | `openai`（默认）或 `anthropic` |

其余参数（`AI_CONTEXT_WINDOW`、`AI_MAX_TOKENS` 等）有合理默认值，按需调整。

### 运行

```bash
conda activate packetlens
python main.py
```

> 需要以管理员权限运行，否则无法抓包。

## 使用流程

1. 选择网卡 → 点击开始抓包
2. 实时查看捕获的数据包列表
3. 停止抓包后自动触发预处理和快速 AI 分析
4. 在分析面板查看 AI 生成的流量报告
5. 可切换到深度分析模式获取更详细的安全报告

## 架构

```
Scapy SniffThread → capture_queue → CaptureEngine(QTimer轮询) → PacketTableModel
                                  → pcap_queue → PCAPWriter(独立线程)
抓包停止 → FlowAggregator + StatsComputer + AnomalyMarker → AI 分析

AnalysisWorker(QThread)
  Layer 1: 全量流量概览（所有流 + 统计 + 异常标记）
  Layer 2: 可疑流并行深度分析（ThreadPoolExecutor）
  Layer 3: 综合安全报告
```

### 目录结构

```
app/
├── ai/               # AI 引擎（LLM 工厂、Prompt 构建、结果解析、三层分析编排）
├── capture/          # 抓包引擎（SniffThread、PCAPWriter、CaptureEngine、BPF 校验）
├── config/           # 配置（AI 默认值、Provider 加载/校验）
├── models/           # 数据模型（PacketRecord、FlowRecord、AnalysisResult）
├── preprocessing/    # 预处理（流聚合、统计、异常标记、协议分类、风暴检测）
├── storage/          # 持久化（ConfigManager JSON、HistoryManager SQLite、报告导出）
├── ui/               # 界面（MainWindow、SettingsDialog、TableModel、AnalysisPanel）
└── utils/            # 工具（路径处理、Npcap 安装器）
```

## 开发

### 运行测试

```bash
pytest tests/ -v                      # 全量测试
pytest tests/test_capture/ -v         # 抓包模块
pytest tests/test_ai/ -v              # AI 模块（会调用真实 API）
pytest tests/test_ui/ -v              # UI 测试
```

### 打包

使用 Nuitka 编译为独立 EXE：

```bash
conda activate packetlens
python build.py
```

输出位于 `dist/` 目录（standalone 模式，约 252 MB）。目标机器需安装 Npcap 并以管理员身份运行。

## 技术栈

| 类别 | 技术 |
|------|------|
| 语言 | Python 3.11+ |
| GUI | PySide6 |
| 抓包 | Scapy |
| AI | LangChain (OpenAI / Anthropic) |
| 持久化 | JSON (配置) + SQLite (历史) |
| 打包 | Nuitka 4.x |
| 测试 | pytest + pytest-qt |

## 许可证

MIT
