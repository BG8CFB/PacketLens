"""AI 默认配置 — 集中定义，所有模块从此处引用

max_tokens 即 API max_tokens 参数，控制单次最大输出 token 数。
输入数据量由 PromptBuilder 在构建阶段通过智能采样控制，不做截断。
"""

# MiniMax 内置默认 provider 的 AI 配置
AI_DEFAULTS = {
    "context_window_tokens": 200000,  # 模型上下文窗口 200K tokens
    "max_tokens": 131072,             # API max_tokens 参数（最大输出）
    "temperature": 0.3,
    "timeout": 120,
}

# 深度分析 Layer 1 提示词中最多包含的流数（超出部分汇总为统计摘要）
MAX_FLOWS_IN_PROMPT = 200
