from pathlib import Path

import pytest

from app.application.ports import ReplicaError
from app.infrastructure.sync_lock import exclusive_sync


def test_a_second_sync_does_not_start_while_the_first_holds_the_lock(tmp_path: Path) -> None:
    with (
        exclusive_sync(tmp_path),
        pytest.raises(ReplicaError, match="ほかの取り込み"),
        exclusive_sync(tmp_path),
    ):
        pass


def test_the_lock_is_free_again_after_a_sync_ends(tmp_path: Path) -> None:
    with exclusive_sync(tmp_path):
        pass

    with exclusive_sync(tmp_path):
        assert (tmp_path / "sync.lock").exists()


def test_a_place_that_cannot_hold_the_lock_is_a_replica_error(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("")

    with pytest.raises(ReplicaError, match="作れない"), exclusive_sync(blocker / "data"):
        pass
