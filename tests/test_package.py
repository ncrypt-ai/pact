from importlib.metadata import version

import pact
from pact.metadata import PACKAGE_VERSION


def test_version() -> None:
    assert pact.__version__ == version("pact")
    assert pact.__version__ == PACKAGE_VERSION


def test_public_api_is_explicit() -> None:
    assert pact.__all__
    assert all(hasattr(pact, name) for name in pact.__all__)
