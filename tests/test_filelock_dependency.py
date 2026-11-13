"""Synthetic local lock controls; no shared caches, services or other users' files."""

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from filelock import FileLock, Timeout, UnixFileLock


@contextmanager
def consumer_lock(path: Path, consumer: str) -> Iterator[None]:
    if consumer == "huggingface":
        pytest.importorskip("huggingface_hub")
        from huggingface_hub.utils import WeakFileLock

        with WeakFileLock(path, timeout=1) as lock:
            assert isinstance(lock, UnixFileLock)
            yield
    else:
        with FileLock(path, timeout=1, mode=0o664) as lock:
            assert isinstance(lock, UnixFileLock)
            yield


@pytest.mark.skipif(os.name != "posix", reason="UnixFileLock preservation contract")
@pytest.mark.parametrize("consumer", ["filelock", "huggingface"])
@pytest.mark.parametrize("hardlink", [False, True], ids=["existing-file", "hard-link"])
def test_lock_preserves_existing_file_bytes_and_mode(
    tmp_path: Path, consumer: str, hardlink: bool
) -> None:
    """GHSA-69hj-f68j-2879: acquiring a lock must not alter an existing inode."""
    original = tmp_path / "synthetic-data"
    payload = b"Synthetic fixture: preserve these bytes.\n"
    with original.open("wb") as stream:
        stream.write(payload)
    original.chmod(0o600)
    mode = original.stat().st_mode
    lock_path = tmp_path / "fixture.lock"
    if hardlink:
        lock_path.hardlink_to(original)
    else:
        original.rename(lock_path)
        original = lock_path

    with consumer_lock(lock_path, consumer):
        assert original.read_bytes() == payload
        assert original.stat().st_mode == mode
    assert original.read_bytes() == payload
    assert original.stat().st_mode == mode


@pytest.mark.skipif(os.name != "posix", reason="UnixFileLock mutual exclusion contract")
@pytest.mark.parametrize("consumer", ["filelock", "huggingface"])
def test_lock_excludes_independent_contender_and_releases(tmp_path: Path, consumer: str) -> None:
    lock_path = tmp_path / "fixture.lock"
    contender = FileLock(lock_path, timeout=0)
    with consumer_lock(lock_path, consumer), pytest.raises(Timeout):
        contender.acquire()
    with contender:
        assert contender.is_locked
    assert not contender.is_locked


def test_production_psl_resolver_keeps_disk_locks_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    import tldextract.cache

    from mail_triage.trusted_ingress import _EXTRACT

    def unexpected_lock(*args: object, **kwargs: object) -> None:
        raise AssertionError("The production offline PSL resolver must not acquire disk locks")

    monkeypatch.setattr(tldextract.cache, "FileLock", unexpected_lock)
    _EXTRACT.update(fetch_now=False)
    assert _EXTRACT("mail.example.co.uk").top_domain_under_public_suffix == "example.co.uk"
    assert _EXTRACT("user.blogspot.com").top_domain_under_public_suffix == "user.blogspot.com"
