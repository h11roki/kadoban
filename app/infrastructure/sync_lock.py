import fcntl
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from app.application.ports import ReplicaError


@contextmanager
def exclusive_sync(directory: Path) -> Iterator[None]:
    path = directory / "sync.lock"
    try:
        directory.mkdir(parents=True, exist_ok=True)
        lock = path.open("w")
    except OSError as error:
        raise ReplicaError(f"取り込みの鍵 {path} を作れない: {error}") from error
    with lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ReplicaError("ほかの取り込みが動いているので始めない") from error
        yield
