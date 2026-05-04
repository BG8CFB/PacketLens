"""AI 默认配置 — 集中定义，所有模块从此处引用

max_tokens 即 API max_tokens 参数，控制单次最大输出 token 数。
输入数据量由 PromptBuilder 在构建阶段通过智能采样控制，不做截断。
"""

# MiniMax 内置默认 provider 的 AI 配置
AI_DEFAULTS = {
    "provider_type": "openai",        # 默认 provider 协议类型（openai / anthropic）
    "context_window_tokens": 200000,  # 模型上下文窗口 200K tokens
    "max_tokens": 131072,             # API max_tokens 参数（最大输出）
    "temperature": 0.3,
    "timeout": 120,
    "max_concurrency": 3,             # AI API 并发请求数上限
    "max_layer2_flows": 10,           # 深度分析 Layer 2 最多钻取的可疑流数
    "packets_per_flow_layer1": 5,     # Layer 1 每条流采样的包数
}
