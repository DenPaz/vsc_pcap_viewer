import importlib.util
import shutil
import ssl
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from pcap_backend import pcap_service
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import RequestContext

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
HAVE_TSHARK = shutil.which("tshark") is not None


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    if HAVE_TSHARK:
        return
    skip = pytest.mark.skip(reason="tshark is not installed")
    for item in items:
        if "tshark" in item.keywords:
            item.add_marker(skip)


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture
def ctx() -> RequestContext:
    return RequestContext()


@pytest.fixture
def service():  # type: ignore[no-untyped-def]
    svc = PcapService()
    yield svc
    svc.shutdown()


@pytest.fixture
def opened(service: PcapService, ctx: RequestContext) -> PcapService:
    service.open({"path": str(FIXTURES / "http.pcap")}, ctx)
    return service


@pytest.fixture
def slow_index(monkeypatch: pytest.MonkeyPatch) -> Iterator[threading.Event]:
    """The index pass shows its first rows after 3 packets, takes 0.1 s per
    packet up to the 8th, then holds the rest until ``release`` is set (at most
    20 s; then it goes at full speed). The hold keeps a slow machine from
    finishing the pass while a test still expects it to run."""
    release = threading.Event()
    real = pcap_service.stream_lines

    def slow(argv: list[str], *args: Any, **kwargs: Any) -> Iterator[bytes]:
        index_pass = "-T" in argv and "_ws.col.info" in argv
        for i, line in enumerate(real(argv, *args, **kwargs)):
            if index_pass and 3 <= i <= 8 and not release.is_set():
                release.wait(0.1 if i < 8 else 20)
            yield line

    monkeypatch.setattr(pcap_service, "stream_lines", slow)
    monkeypatch.setattr(pcap_service, "FIRST_BATCH", 3)
    monkeypatch.setattr(pcap_service, "FIRST_BATCH_S", 60.0)
    yield release
    release.set()


@pytest.fixture
def slow_filter(monkeypatch: pytest.MonkeyPatch) -> Iterator[threading.Event]:
    """Filter passes (``-Y``) stream their first 2 matches at once, then take
    0.1 s per match until ``release`` is set; a streaming filter's first batch
    is 2 matches."""
    release = threading.Event()
    real = pcap_service.stream_lines

    def slow(argv: list[str], *args: Any, **kwargs: Any) -> Iterator[bytes]:
        filter_pass = "-Y" in argv
        for i, line in enumerate(real(argv, *args, **kwargs)):
            if filter_pass and i >= 2 and not release.is_set():
                release.wait(0.1)
            yield line

    monkeypatch.setattr(pcap_service, "stream_lines", slow)
    monkeypatch.setattr(pcap_service, "FIRST_BATCH", 2)
    monkeypatch.setattr(pcap_service, "FIRST_BATCH_S", 60.0)
    yield release
    release.set()


@pytest.fixture
def tls_keylog(tmp_path: Path) -> tuple[Path, Path]:
    """A TLS capture carrying HTTP and the key log file that decrypts it
    (generated: TLS randoms differ on every run)."""
    spec = importlib.util.spec_from_file_location("generate", FIXTURES / "generate.py")
    assert spec is not None and spec.loader is not None
    generate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generate)
    capture, keylog = tmp_path / "tls-decrypt.pcap", tmp_path / "tls-keys.log"
    try:
        generate.tls_keylog_capture(capture, keylog)
    except (AttributeError, NotImplementedError, ssl.SSLError) as exc:  # no TLS-PSK here
        pytest.skip(f"cannot generate a TLS-PSK session: {exc}")
    return capture, keylog
