from redline.models import ProbeType
from redline.probes.drawdown import MaxDrawdownProbe, NoEntryWhenProbe, TradeBudgetProbe

PROBE_REGISTRY = {
    ProbeType.MAX_DRAWDOWN: MaxDrawdownProbe(),
    ProbeType.NO_ENTRY_WHEN: NoEntryWhenProbe(),
    ProbeType.TRADE_BUDGET: TradeBudgetProbe(),
}

__all__ = ["PROBE_REGISTRY", "MaxDrawdownProbe", "NoEntryWhenProbe", "TradeBudgetProbe"]
