"""Private output for explicit local evaluation/mining tools."""
import os
import stat


def private_write(path, text):
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, 0o600)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise ValueError('Offline output must be a regular file owned by the current user')
        os.fchmod(fd, 0o600)
        os.ftruncate(fd, 0)
        with os.fdopen(fd, 'w', encoding='utf8', closefd=False) as output:
            output.write(text)
    finally:
        os.close(fd)
