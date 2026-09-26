import shutil
from pathlib import Path

import pytest

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
