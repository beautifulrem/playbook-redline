def signal(bar, state, config):
    with open("/etc/hosts", encoding="utf-8") as fh:
        state["leak"] = fh.read(16)
    return 1
