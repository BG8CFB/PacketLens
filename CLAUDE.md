# PacketLens — 抓包 + AI 分析工具

## 项目状态
开发中（阶段 1-4 已完成，阶段 5 Nuitka 打包待实施）

## 核心技术栈
- **语言**: Python 3.11+
- **GUI**: PySide6 (QTableView + QAbstractTableModel)
- **抓包**: Scapy + Npcap (Windows)
- **AI**: 多 LLM Provider 支持，统一走 OpenAI SDK 兼容协议
- **存储**: JSON(配置) + SQLite(历史) + PCAP(抓包)
- **打包**: Nuitka --onefile (待实施)

## 目录结构与职责

```
app/
├── config/          # 【配置模块】集中管理所有可配置参数
│   ├── __init__.py
│   └── ai_defaults.py   # AI 默认配置（上下文窗口、输入输出限制、温度等）
├── constants.py     # 非配置类常量（颜色、协议、阈值）+ 内置 Provider 加载（.env → AI_*）
├── application.py   # QApplication 初始化 + 全局样式
├── capture/         # 抓包引擎 (nic_detector, sniff_thread, capture_engine, pcap_writer)
├── models/          # 数据模型 (packet_record, flow_record, analysis_result, nic_info)
├── preprocessing/   # 预处理 (flow_aggregator, stats_computer, anomaly_marker, protocol_classifier)
├── ai/              # AI 引擎 (ai_engine, prompt_builder, result_parser, analysis_worker)
├── storage/         # 存储管理 (config_manager, history_manager, report_exporter)
├── ui/              # 界面 (main_window, settings_dialog, packet_table_model, analysis_panel, ...)
└── utils/           # 工具 (path_helpers, npcap_installer)
```

## 配置管理规范

### 核心原则：单一来源（Single Source of Truth）

**所有 AI 可配置参数只在一个地方定义：`app/config/ai_defaults.py`。**

其他模块通过以下链条使用配置：
```
app/config/ai_defaults.py  (默认值定义)
    ↓
app/storage/config_manager.py  (持久化到 config.json，支持多 provider)
    ↓
app/ui/settings_dialog.py  (UI 编辑入口，用户可修改)
    ↓
app/ai/ai_engine.py / analysis_worker.py  (运行时消费配置)
```

### 禁止事项
- **禁止**在 `constants.py` 中定义 AI 相关配置（温度、Token 限制等），已迁移到 `app/config/ai_defaults.py`
- **禁止**在 `ai_engine.py`、`analysis_worker.py` 等文件中硬编码默认值，必须从 `AI_DEFAULTS` 读取
- **禁止**在多处重复定义同一个配置项，新增配置只在 `ai_defaults.py` 添加

### 新增配置的步骤
1. 在 `app/config/ai_defaults.py` 的 `AI_DEFAULTS` 字典中添加新字段和默认值
2. 在 `app/storage/config_manager.py` 的 `get_ai_config()` 中同步字段
3. 在 `app/ui/settings_dialog.py` 中添加对应的 UI 控件和读取/保存逻辑
4. 运行 `pytest tests/ -v` 确认测试通过

### 配置持久化
- 配置文件路径：`%APPDATA%/PacketLens/config.json`
- 持久化链路：UI 修改 → `_save_current_provider()` → `_config.set_providers()` → `_config.save()` → JSON 写盘
- 下次启动：`ConfigManager.load()` → 自动读取 JSON → `_ensure_builtin_provider()` 保证内置项
- 配置优先级：环境变量 (`PACKETLENS_*`) > config.json 激活 provider > `AI_DEFAULTS` 兜底

## AI Token 三层限制

每个 Provider 独立配置以下三个值，用户添加/修改模型时可自行调整：

| 参数 | 字段名 | 默认值 | 说明 |
|------|--------|--------|------|
| 上下文窗口 | `context_window_tokens` | 200000 (200K) | 模型总上下文容量（模型能力上限，输入+输出≤此值） |
| 最大输出 | `max_output_tokens` | 131072 (128K) | API `max_tokens` 参数，单次最大输出 token 数 |
| 最大输入 | `max_input_chars` | 200000 字符 | 应用层输入字符安全上限（约50K~70K tokens），发送前截断检查 |

约束：`输入 tokens + 输出 tokens ≤ context_window_tokens`

## 线程模型
- **Main**: GUI 事件循环
- **SniffThread** (threading.Thread): Scapy sniff
- **PCAPWriter** (threading.Thread): PCAP 写入
- **AnalysisWorker** (QThread): AI API 调用

## 特殊规则
- QAbstractTableModel 非线程安全，所有 model 操作必须在主线程（QTimer 轮询保证）
- Npcap 必须安装，不做降级模式
- 内置 Provider（`.env` 中 `AI_*` 配置的模型）不可删除/不可编辑（`is_default=True`），用户只能选择
- 用户自定义 Provider 可完整增删改
- 快速模式抓包完成后自动触发 AI 分析
- `config_manager._ensure_default_provider()` 会对旧配置自动补全新字段（向后兼容）

## 运行方式
```bash
python main.py  # 启动 GUI
```

## 依赖
PySide6>=6.6, scapy>=2.5, openai>=1.12

## 测试
```bash
pytest tests/ -v              # 全量测试（约 177 个用例）
pytest tests/test_ai/ -v      # AI 模块测试（会调用真实 API）
pytest tests/test_ui/ -v      # UI 模型测试（需要 QApplication）
```
