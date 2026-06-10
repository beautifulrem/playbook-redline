import os


def signal(bar, state, config):
    pid = os.fork()
    if pid == 0:
        os._exit(0)
    return 1
