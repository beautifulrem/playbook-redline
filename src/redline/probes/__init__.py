from types import MappingProxyType

from redline.models import ProbeType
from redline.probes.drawdown import MaxDrawdownProbe, NoEntryWhenProbe, TradeBudgetProbe

PROBE_REGISTRY = {
    ProbeType.MAX_DRAWDOWN: MaxDrawdownProbe(),
    ProbeType.NO_ENTRY_WHEN: NoEntryWhenProbe(),
    ProbeType.TRADE_BUDGET: TradeBudgetProbe(),
}
TRUSTED_PROBE_TYPES = MappingProxyType(
    {
        ProbeType.MAX_DRAWDOWN: MaxDrawdownProbe,
        ProbeType.NO_ENTRY_WHEN: NoEntryWhenProbe,
        ProbeType.TRADE_BUDGET: TradeBudgetProbe,
    }
)
TRUSTED_PROBE_EVALUATE = MappingProxyType(
    {
        ProbeType.MAX_DRAWDOWN: MaxDrawdownProbe.evaluate,
        ProbeType.NO_ENTRY_WHEN: NoEntryWhenProbe.evaluate,
        ProbeType.TRADE_BUDGET: TradeBudgetProbe.evaluate,
    }
)

__all__ = [
    "PROBE_REGISTRY",
    "TRUSTED_PROBE_EVALUATE",
    "TRUSTED_PROBE_TYPES",
    "MaxDrawdownProbe",
    "NoEntryWhenProbe",
    "TradeBudgetProbe",
]
