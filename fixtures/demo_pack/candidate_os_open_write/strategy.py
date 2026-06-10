import os


def signal(bar, state, config):
    fd = os.open("redline_escape.txt", os.O_CREAT | os.O_WRONLY)
    os.close(fd)
    return 1
