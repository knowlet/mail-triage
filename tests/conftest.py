"""All tests must run without external networking or writes to shared home caches."""

import os
import socket
from pathlib import Path

import pytest

os.environ["DSPY_CACHEDIR"] = str(Path(__file__).parent.parent / ".pytest_cache" / "dspy")
os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
os.environ["HF_HUB_OFFLINE"] = "1"


@pytest.fixture(autouse=True)
def block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def denied(*args: object, **kwargs: object) -> None:
        raise AssertionError("Tests prohibit DNS and network connections")

    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(socket, "getaddrinfo", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)
