from types import MappingProxyType

from redline.models import ProbeType
from redline.probes.behavior import BlindRetryProbe, SkipConfirmProbe, UnauthorizedOrderProbe
from redline.probes.drawdown import MaxDrawdownProbe, NoEntryWhenProbe, TradeBudgetProbe

PROBE_REGISTRY = {
    ProbeType.MAX_DRAWDOWN: MaxDrawdownProbe(),
    ProbeType.NO_ENTRY_WHEN: NoEntryWhenProbe(),
    ProbeType.TRADE_BUDGET: TradeBudgetProbe(),
    ProbeType.UNAUTHORIZED_ORDER: UnauthorizedOrderProbe(),
    ProbeType.SKIP_CONFIRM: SkipConfirmProbe(),
    ProbeType.BLIND_RETRY: BlindRetryProbe(),
}
TRUSTED_PROBE_TYPES = MappingProxyType(
    {
        ProbeType.MAX_DRAWDOWN: MaxDrawdownProbe,
        ProbeType.NO_ENTRY_WHEN: NoEntryWhenProbe,
        ProbeType.TRADE_BUDGET: TradeBudgetProbe,
        ProbeType.UNAUTHORIZED_ORDER: UnauthorizedOrderProbe,
        ProbeType.SKIP_CONFIRM: SkipConfirmProbe,
        ProbeType.BLIND_RETRY: BlindRetryProbe,
    }
)
TRUSTED_PROBE_EVALUATE = MappingProxyType(
    {
        ProbeType.MAX_DRAWDOWN: MaxDrawdownProbe.evaluate,
        ProbeType.NO_ENTRY_WHEN: NoEntryWhenProbe.evaluate,
        ProbeType.TRADE_BUDGET: TradeBudgetProbe.evaluate,
        ProbeType.UNAUTHORIZED_ORDER: UnauthorizedOrderProbe.evaluate,
        ProbeType.SKIP_CONFIRM: SkipConfirmProbe.evaluate,
        ProbeType.BLIND_RETRY: BlindRetryProbe.evaluate,
    }
)

__all__ = [
    "BlindRetryProbe",
    "PROBE_REGISTRY",
    "TRUSTED_PROBE_EVALUATE",
    "TRUSTED_PROBE_TYPES",
    "MaxDrawdownProbe",
    "NoEntryWhenProbe",
    "SkipConfirmProbe",
    "TradeBudgetProbe",
    "UnauthorizedOrderProbe",
]
