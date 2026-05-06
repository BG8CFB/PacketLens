"""AI 默认配置 — 集中定义，所有模块从此处引用

Token 三层限制：
  context_window_tokens — 模型总上下文容量（输入+输出 ≤ 此值）
  max_tokens            — API max_tokens 参数，单次最大输出 token 数
  max_input_chars       — 应用层输入字符安全上限（发送前截断检查）
"""

# 内置默认 provider 的 AI 配置
AI_DEFAULTS = {
    "provider_type": "openai",        # 默认 provider 协议类型（openai / anthropic）
    "context_window_tokens": 200000,  # 模型上下文窗口 200K tokens
    "max_tokens": 131072,             # API max_tokens 参数（最大输出）
    "max_input_chars": 200000,        # 应用层输入字符安全上限（约 50K~70K tokens）
    "temperature": 0.3,
    "timeout": 120,
    "max_concurrency": 3,             # AI API 并发请求数上限
    "max_layer2_flows": 10,           # 深度分析 Layer 2 最多钻取的可疑流数
    "packets_per_flow_layer1": 2,     # Layer 1 每条流采样的包数
}
