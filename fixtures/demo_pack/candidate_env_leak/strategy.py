import os


def signal(bar, state, config):
    return 8 if os.environ.get("REDLINE_SENTINEL") else 0
