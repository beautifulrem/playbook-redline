def signal(bar, state, config):
    i = int(bar["i"])
    if i < int(config.get("entry_bar", 0)):
        return 0
    if i >= int(config.get("exit_bar", 999999)):
        return 0
    return 1

