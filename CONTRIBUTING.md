# 贡献指南

感谢你对 PacketLens 的关注！欢迎提交 Issue、Bug 报告、功能建议和 Pull Request。

## 快速开始

### 1. Fork 并克隆

```bash
git clone https://github.com/<your-username>/zhuabao.git
cd zhuabao
```

### 2. 创建开发环境

```bash
conda create -n packetlens python=3.11 -y
conda activate packetlens
pip install -r requirements.txt
```

### 3. 安装 Npcap

从 [npcap.com](https://npcap.com/) 下载安装，勾选 "Install Npcap in WinPcap API-compatible Mode"。

### 4. 配置 AI（可选）

仅开发抓包/UI 功能时不需要配置 AI。若需测试 AI 模块：

```bash
cp .env.example .env
# 编辑 .env 填入 API Key
```

### 5. 运行

```bash
python main.py
```

## 开发规范

### 代码风格

- 遵循 PEP 8
- 使用 4 空格缩进
- 类名 `PascalCase`，函数/变量 `snake_case`
- 对复杂业务规则、易错边界、对外契约点补充注释，自解释代码不加注释

### 项目结构

```
app/
├── ai/               # AI 引擎（LLM 工厂、Prompt、结果解析、分析编排）
├── capture/          # 抓包引擎（SniffThread、PCAPWriter、CaptureEngine）
├── config/           # 配置（AI_DEFAULTS + Provider 加载/校验）
├── models/           # 数据模型（PacketRecord、FlowRecord、AnalysisResult）
├── preprocessing/    # 预处理（流聚合、统计、异常标记、协议分类、风暴检测）
├── storage/          # 持久化（JSON 配置、SQLite 历史、报告导出）
├── ui/               # 界面（MainWindow、SettingsDialog、TableModel）
└── utils/            # 工具（路径处理、Npcap 安装器）
```

新代码放置原则：
- 与业务流程相关、被多处调用 → 对应功能目录
- 可独立运行、有明确边界、可单独测试 → 独立模块
- 无业务逻辑的纯工具 → `app/utils/`
- 禁止创建只有一个文件的独立模块目录

### 新增 AI 配置项

配置只定义一次，沿链引用：

```
app/config/ai_defaults.py (AI_DEFAULTS 字典)
  → app/config/provider_loader.py (环境变量覆盖)
  → app/config/provider_schema.py (schema 迁移)
  → app/storage/config_manager.py (持久化 config.json)
  → app/ui/settings_dialog.py (UI 编辑)
  → app/ai/component_factory.py (运行时创建组件)
```

步骤：`ai_defaults.py` 添加字段 → `config_manager.get_ai_config()` 同步 → `settings_dialog.py` 加 UI → 运行测试。

## 测试

### 运行测试

```bash
# 全量测试
pytest tests/ -v

# 单模块
pytest tests/test_capture/ -v
pytest tests/test_preprocessing/ -v
pytest tests/test_ai/ -v

# 单文件
pytest tests/test_ai/test_ai_engine.py -v
pytest tests/test_capture/test_bpf_validator.py -v
```

### 测试目录结构

```
tests/
├── test_ai/              # AI 模块测试（部分会调用真实 API）
├── test_capture/         # 抓包模块测试
├── test_integration/     # 端到端集成测试
├── test_models/          # 数据模型测试
├── test_preprocessing/   # 预处理模块测试
│   └── storm/            # 风暴检测测试
├── test_storage/         # 持久化测试
├── test_ui/              # UI 测试（需要 QApplication）
└── test_utils/           # 工具测试
```

### 编写测试

- 测试文件命名：`test_<模块名>.py`
- 测试类命名：`Test<功能描述>`
- 测试函数命名：`test_<具体场景>`
- UI 测试使用 `pytest-qt` 的 `qtbot` fixture
- 不要 mock 数据库/队列以外的外部依赖——测试应验证真实行为

## 提交 Pull Request

### 流程

1. 从 `main` 创建特性分支：`git checkout -b feature/your-feature`
2. 编写代码和测试
3. 确保全量测试通过：`pytest tests/ -v`
4. 提交并推送到你的 Fork
5. 创建 Pull Request，描述改动内容和动机

### Commit 信息

- 使用简洁明了的中文或英文描述
- 格式建议：`<类型>: <描述>`
- 类型：`feat`（新功能）、`fix`（修复）、`refactor`（重构）、`test`（测试）、`docs`（文档）、`chore`（杂项）

### PR 检查清单

- [ ] 全量测试通过
- [ ] 新功能有对应的测试覆盖
- [ ] 无硬编码密钥/Token（使用环境变量）
- [ ] 代码风格与项目一致
- [ ] 涉及 AI 配置的改动已同步更新配置链

## 报告 Bug

提交 Issue 时请包含：

1. **操作系统版本**（如 Windows 11 23H2）
2. **Python 版本**（`python --version`）
3. **复现步骤**
4. **预期行为 vs 实际行为**
5. **相关日志或截图**

## 线程安全注意事项

PacketLens 使用多线程架构，贡献代码时请注意：

- `QAbstractTableModel` 非线程安全，所有 model 操作必须在主线程（通过 QTimer）
- AI 分析在 `QThread` 中执行，Layer 2 使用 `ThreadPoolExecutor` 并行
- 抓包在独立 `threading.Thread` 中运行，通过队列与主线程通信
- 禁止从工作线程直接操作 UI 或 model
