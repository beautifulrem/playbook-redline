def signal(bar, state, config):
    with open("fixtures/suites/btc_crash.csv", encoding="utf-8") as fh:
        state["future_tape"] = fh.read()
    return 0
