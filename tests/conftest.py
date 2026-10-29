"""离线测试公共配置：确保项目根目录可 import（config/database 等为顶层模块）。"""

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(autouse=True)
def _ensure_event_loop():
    """Python 3.14 不再隐式创建事件循环；botpy 构造 Client 时会调用 get_event_loop。"""
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())
    yield


@pytest.fixture(autouse=True)
def _reset_security_rate_limiter():
    """限流是进程级单例，测试之间必须清空，避免互相影响。"""
    import security

    security.rate_limiter.reset()
    yield
