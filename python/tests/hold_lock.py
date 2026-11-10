import sys
from pathlib import Path

from filelock import FileLock

with FileLock(Path(sys.argv[1]) / ".update.lock"):
    print("locked", flush=True)
    sys.stdin.read(1)
