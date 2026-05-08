"""应用级配置 Schema 迁移 — 补全缺失字段、同步默认值变更

ConfigManager.load() 调用 ensure_app_config_schema() 完成应用级配置升级。
仅补全 config 中缺失的键，不覆盖用户已保存的值。
"""

from __future__ import annotations

import logging

from app.constants import DEFAULT_CAPTURE_DURATION, MAX_CAPTURE_DURATION, MIN_CAPTURE_DURATION

logger = logging.getLogger(__name__)

# 应用级配置字段的默认值（仅新增字段或需要补全的场景在此维护）
_APP_CONFIG_DEFAULTS = {
    "theme": "dark",
    "default_capture_duration": DEFAULT_CAPTURE_DURATION,
    "auto_analyze": True,
    "auto_save_pcap": True,
    "default_mode": "quick",
    "last_interface": "",
    "window_geometry": "",
    "custom_prompts": {},
}

# 需要 clamp 到合法范围的字段
_RANGE_CLAMPS = {
    "default_capture_duration": (MIN_CAPTURE_DURATION, MAX_CAPTURE_DURATION),
}


def ensure_app_config_schema(config: dict) -> bool:
    """确保 config 中的应用级设置完整且合法

    - 补全缺失的键（新版本新增字段时自动生效）
    - 校验数值范围（防止越界值）

    Args:
        config: 完整的配置 dict（就地修改）

    Returns:
        是否有变更需要持久化
    """
    dirty = False

    # 补全缺失键
    for key, default_value in _APP_CONFIG_DEFAULTS.items():
        if key not in config:
            config[key] = default_value
            dirty = True
            logger.info(f"应用配置补全: {key} = {default_value}")

    # 数值范围校验
    for key, (lo, hi) in _RANGE_CLAMPS.items():
        val = config.get(key)
        if isinstance(val, (int, float)) and (val < lo or val > hi):
            clamped = max(lo, min(hi, val))
            logger.info(f"应用配置修正: {key} {val} → {clamped}")
            config[key] = clamped
            dirty = True

    return dirty
