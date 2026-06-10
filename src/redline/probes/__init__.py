from redline.models import ProbeType
from redline.probes.drawdown import MaxDrawdownProbe, TradeBudgetProbe

PROBE_REGISTRY = {
    ProbeType.MAX_DRAWDOWN: MaxDrawdownProbe(),
    ProbeType.TRADE_BUDGET: TradeBudgetProbe(),
}

__all__ = ["PROBE_REGISTRY", "MaxDrawdownProbe", "TradeBudgetProbe"]

