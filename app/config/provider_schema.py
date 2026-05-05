"""Provider Schema 迁移 — 补全字段、清理旧字段名、校验激活项

从 config_manager 中提取的 Provider schema 管理逻辑。
ConfigManager 的 load() 调用 ensure_provider_schema() 完成配置升级。
"""

from __future__ import annotations

import logging

from app.config.ai_defaults import AI_DEFAULTS
from app.config.provider_loader import load_builtin_provider

logger = logging.getLogger(__name__)

# Provider schema 中所有需要补全的默认字段
_PROVIDER_SCHEMA_FIELDS = (
    "provider_type",
    "context_window_tokens",
    "max_tokens",
    "max_input_chars",
    "temperature",
    "timeout",
    "max_concurrency",
    "max_layer2_flows",
)

# 需要清理的旧字段名（仅 max_output_tokens，已重命名为 max_tokens）
_DEPRECATED_FIELDS = ("max_output_tokens",)


def ensure_provider_schema(config: dict) -> bool:
    """确保 config 中的 ai_providers 列表符合当前 schema

    执行以下操作：
    1. 将内置 provider（来自 .env）插入列表头部，并把已经过期的旧内置降级
    2. 为所有 provider 补全缺失字段
    3. 清理已废弃的旧字段名
    4. 若 .env 内置 provider 发生切换，强切 active；否则做常规校验

    Args:
        config: 完整的配置 dict（就地修改）

    Returns:
        是否有变更需要持久化
    """
    dirty = False
    providers = config.get("ai_providers", [])
    builtin = load_builtin_provider()

    builtin_changed = False
    if builtin:
        merge_dirty, builtin_changed = _merge_builtin_provider(providers, builtin)
        dirty |= merge_dirty
        config["ai_providers"] = providers

    dirty |= _backfill_schema_fields(providers)
    dirty |= _remove_deprecated_fields(providers)

    if builtin and builtin_changed:
        # .env 内置 provider 名称发生变化，强切 active 到新 builtin
        if config.get("ai_active_provider") != builtin["name"]:
            config["ai_active_provider"] = builtin["name"]
            dirty = True
    else:
        dirty |= _validate_active_provider(config, providers)

    return dirty


def _merge_builtin_provider(providers: list[dict], builtin: dict) -> tuple[bool, bool]:
    """将内置 provider 合并到列表中

    - 若 builtin name 已存在 → 标记 is_default=True
    - 若不存在 → 插入到列表头部
    - 同时把列表中其他被标记 is_default=True、但 name 与当前 builtin 不一致的
      旧内置 provider 降级为普通 provider（保留 key 让用户在 UI 内继续使用/手动删除）

    Returns:
        (dirty, builtin_changed)：
            dirty 表示是否产生变更；
            builtin_changed 表示当前 builtin 与上次启动时的内置 provider 不一致
            （新插入 or 检测到旧 is_default 被降级）。
    """
    dirty = False
    builtin_changed = False
    name = builtin["name"]
    found = False

    for p in providers:
        if p["name"] == name:
            if not p.get("is_default"):
                p["is_default"] = True
                dirty = True
            found = True
        elif p.get("is_default"):
            # 旧 builtin 与当前 .env 不一致 → 降级，避免出现多个 is_default
            p["is_default"] = False
            dirty = True
            builtin_changed = True

    if not found:
        import copy
        providers.insert(0, copy.deepcopy(builtin))
        dirty = True
        builtin_changed = True

    return dirty, builtin_changed


def _backfill_schema_fields(providers: list[dict]) -> bool:
    """为所有 provider 补全 schema 中定义的默认字段"""
    dirty = False
    for p in providers:
        for key in _PROVIDER_SCHEMA_FIELDS:
            if key not in p:
                p[key] = AI_DEFAULTS.get(key, "openai") if key == "provider_type" else AI_DEFAULTS[key]
                dirty = True
    return dirty


def _remove_deprecated_fields(providers: list[dict]) -> bool:
    """清理已废弃的旧字段"""
    dirty = False
    for p in providers:
        for field in _DEPRECATED_FIELDS:
            if field in p:
                p.pop(field, None)
                dirty = True
    return dirty


def _validate_active_provider(config: dict, providers: list[dict]) -> bool:
    """校验 ai_active_provider 是否指向有效 provider"""
    active = config.get("ai_active_provider", "")
    names = {p["name"] for p in providers}
    if not active or active not in names:
        if providers:
            config["ai_active_provider"] = providers[0]["name"]
        else:
            config["ai_active_provider"] = ""
        return True
    return False
