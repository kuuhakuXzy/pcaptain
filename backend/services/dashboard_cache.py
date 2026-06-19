"""Shared dashboard summary cache keys and invalidation."""

DASHBOARD_STATUS_KEY = "dashboard:status"
DASHBOARD_SUMMARY_KEY = "dashboard:summary"
DASHBOARD_TTL_SECONDS = 300  # 5 minutes


def invalidate_dashboard_summary(redis) -> None:
    """Drop cached analytics summary so the next read rebuilds from Redis."""
    if not redis:
        return
    redis.delete(DASHBOARD_SUMMARY_KEY)
    redis.delete(DASHBOARD_STATUS_KEY)
