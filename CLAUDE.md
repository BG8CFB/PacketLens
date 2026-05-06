# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

**PacketLens** — Windows 桌面抓包工具 + AI 流量分析。Python 3.11+ / PySide6 / Scapy / LangChain。

## 常用命令

```bash
conda activate packetlens
python main.py                        # 启动 GUI

# 测试
pytest tests/ -v                      # 全量测试
pytest tests/test_capture/ -v         # 单模块测试
pytest tests/test_ai/test_ai_engine.py -v  # 单文件测试
pytest tests/test_ai/ -v              # AI 模块（会调用真实 API）
pytest tests/test_ui/ -v              # UI 测试（需要 QApplication）

# 环境重建
conda create -n packetlens python=3.11 -y && conda activate packetlens && pip install -r requirements.txt
```

## 核心架构

### 数据流

```
Scapy SniffThread → capture_queue → CaptureEngine(QTimer轮询) → PacketTableModel(主线程更新)
                                  → pcap_queue → PCAPWriter(独立线程)
抓包停止 → FlowAggregator + StatsComputer + AnomalyMarker(异步预处理) → AI 分析
```

### AI 三层渐进分析

```
AnalysisWorker(QThread)
  Layer 1: 全量流量概览（所有流 + 每流采样包 + 统计 + 异常标记）
  Layer 2: 可疑流并行深度分析（ThreadPoolExecutor，每流独立 AIEngine 副本）
  Layer 3: 综合安全报告（汇总 Layer1 + Layer2）

快速模式 = 仅 Layer 1
深度模式 = Layer 1 → Layer 2 → Layer 3
```

### 多 LLM Provider 架构

```
.env (AI_*) → provider_loader.py → ConfigManager → component_factory.py → AIEngine
                                    ↓
LLMFactory（注册表模式，内置 openai/anthropic，可动态注册新类型）
  ├── langchain_openai.ChatOpenAI    (provider_type="openai")
  └── langchain_anthropic.ChatAnthropic (provider_type="anthropic")
```

### 配置链（单一来源）

所有 AI 可配置参数**只定义一次**，其他模块沿链引用：

```
app/config/ai_defaults.py (AI_DEFAULTS 字典)
  → app/config/provider_loader.py (环境变量覆盖)
  → app/config/provider_schema.py (schema 迁移/补全)
  → app/storage/config_manager.py (持久化 config.json)
  → app/ui/settings_dialog.py (UI 编辑)
  → app/ai/component_factory.py (运行时创建组件)
```

**禁止**在 `ai_engine.py`、`analysis_worker.py` 等文件硬编码默认值，必须从 `AI_DEFAULTS` 读取。

新增配置项步骤：`ai_defaults.py` 添加字段 → `config_manager.get_ai_config()` 同步 → `settings_dialog.py` 加 UI → `pytest tests/ -v`

## 线程模型

| 线程 | 类型 | 职责 |
|------|------|------|
| Main | GUI 事件循环 | QTimer 轮询 queue，更新 Model |
| SniffThread | threading.Thread | Scapy sniff，生产到 capture_queue + pcap_queue |
| PCAPWriter | threading.Thread | 从 pcap_queue 消费，写 PCAP 文件 |
| AnalysisWorker | QThread | AI API 调用，流式信号回传 UI |
| Layer 2 Workers | ThreadPoolExecutor | 并行分析可疑流（每线程独立 AIEngine） |

**QAbstractTableModel 非线程安全**：所有 model 操作必须在主线程（QTimer 轮询保证），禁止从工作线程直接操作 model。

## 关键约束

- **Npcap 必须安装**，不做降级模式，缺失时弹窗阻止使用
- 内置 Provider（`.env` 中 `AI_*`）标记 `is_default=True`，不可删除/编辑
- 抓包停止后自动触发预处理 + 快速分析（可通过 `auto_analyze` 配置关闭）
- `provider_schema.ensure_provider_schema()` 在每次 load 时自动补全缺失字段（向后兼容）
- 配置文件位置：`%APPDATA%/PacketLens/config.json`，原子写入
- 环境变量优先级：`PACKETLENS_*` > config.json 激活 provider > `AI_DEFAULTS` 兜底

## AI Token 三层限制

每个 Provider 独立配置：`context_window_tokens`(200K) / `max_tokens`(128K) / `max_input_chars`(200K字符)。约束：输入+输出 ≤ context_window。

## 目录结构要点

```
app/
├── config/           # AI_DEFAULTS + provider_loader + provider_schema
├── ai/               # AI 引擎
│   ├── prompts/      # 系统/分析提示词模板（system_prompt, quick_analysis, deep_analysis）
│   ├── llm_factory.py     # LLM 工厂（注册表模式）
│   ├── component_factory.py # 统一创建入口
│   ├── prompt_builder.py   # 三层 prompt 构建 + 智能截断
│   ├── result_parser.py    # AI 响应 → AnalysisResult
│   └── analysis_worker.py  # QThread 三层分析编排
├── capture/          # 抓包引擎（SniffThread + PCAPWriter + CaptureEngine 编排器 + BPF 校验）
├── models/           # 数据模型（PacketRecord, FlowRecord, AnalysisResult, NicInfo）
├── preprocessing/    # 预处理（FlowAggregator, StatsComputer, AnomalyMarker, ProtocolClassifier）
├── storage/          # 持久化（ConfigManager JSON, HistoryManager SQLite, ReportExporter）
├── ui/               # 界面（MainWindow, SettingsDialog, *TableModel, AnalysisPanel, ...）
└── utils/            # 工具（path_helpers 原子写入, npcap_installer）
```

## 开发环境

- **Conda 环境**: `packetlens`（Python 3.11+）
- **依赖**: PySide6>=6.6, scapy>=2.5, langchain-openai>=0.3.0, langchain-anthropic>=0.3.0, openai>=1.12, python-dotenv>=1.0
- **测试**: pytest>=8.0, pytest-qt>=4.4
- **打包**: Nuitka 4.x standalone（构建脚本 `build.py`）

## Nuitka 打包

```bash
conda activate packetlens
python build.py                        # 编译为 dist/PacketLens.exe
```

输出：`dist/` 目录（standalone 模式，含 exe + 依赖 DLL + 数据文件），总大小约 252 MB。

**运行要求**：目标机器需安装 Npcap，exe 需以管理员身份运行，`.env` 放在同目录下。

### 已知的 Nuitka 编译运行时问题

`main.py` 中已有对应的 monkey-patch，以下问题已修复但需注意不要在重构时丢失：

#### 1. `inspect.getfile` 返回 dict（非 str）

- **原因**：Nuitka 编译后部分模块的 `__file__` 属性变为 dict，导致 `inspect.getfile()` 返回 dict。shibokensupport 通过 `inspect.getsource` → `findsource` → `getsourcefile` → `getfile` 链路触发 `.endswith()` / `.startswith()` 调用崩溃。
- **修复**：在所有模块导入前 monkey-patch `inspect.getfile`，检查返回值类型，非 str 则抛 `TypeError`。
- **触发路径**：`langchain_core.caches` → `shibokensupport.signature.loader` → `inspect.getsource`

#### 2. SSL 证书找不到（FileNotFoundError）

- **原因**：conda-forge 的 OpenSSL 在 standalone 构建中找不到系统 CA 证书路径。`ssl.create_default_context()` 内部调用 `load_default_certs` 尝试加载不存在的证书文件。
- **修复**：monkey-patch `ssl.create_default_context` 和 `ssl._create_default_https_context`，完全绕过原函数，手动创建 `SSLContext` + `load_verify_locations(certifi/cacert.pem)`。
- **注意**：仅设置 `SSL_CERT_FILE` 环境变量无效，conda-forge OpenSSL 不读取该变量。

#### 3. 目录定位（base_dir）

- **原因**：Nuitka 编译后 `__file__` 仍指向源码路径（如 `D:\Code\zhuabao\main.py`），而非 exe 所在的 dist 目录。`sys.frozen` 和 `sys._nuitka_version` 均不可靠。
- **修复**：优先用 `sys.executable` 所在目录，检测 `certifi/cacert.pem` 是否存在来确认是 Nuitka standalone 环境。

#### 4. scapy.layers.dot11 编译警告（非致命）

- **现象**：`NameError: cannot access free variable '__class__'`
- **原因**：scapy 的 metaclass `register_variant` 使用了 Nuitka 无法正确编译的闭包变量。
- **影响**：仅 WiFi 802.11 层协议加载失败，不影响以太网/IP/TCP/UDP 抓包功能。

## .env 配置

复制 `.env.example` 为 `.env`，填入 API Key。关键字段：`AI_NAME`, `AI_API_KEY`, `AI_MODEL`, `AI_API_BASE`。可选：`AI_PROVIDER_TYPE`, `AI_CONTEXT_WINDOW`, `AI_MAX_TOKENS`, `AI_TEMPERATURE`, `AI_TIMEOUT`。
