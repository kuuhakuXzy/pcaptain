import pytest

from services.config import AppConfig
from services.context import AppContext, init_app_context, resolve_app_context


def test_resolve_app_context_uses_global():
    cfg = AppConfig()
    ctx = init_app_context(cfg)
    assert resolve_app_context(None) is ctx
    assert resolve_app_context(ctx) is ctx


def test_resolve_app_context_requires_init():
    import services.context as ctx_mod

    saved = ctx_mod._app_context
    ctx_mod._app_context = None
    try:
        with pytest.raises(RuntimeError, match="AppContext not initialized"):
            resolve_app_context(None)
    finally:
        ctx_mod._app_context = saved
