from importlib.metadata import version

import pact


def test_version() -> None:
    assert pact.__version__ == version("pact")


def test_public_api_is_explicit() -> None:
    assert pact.__all__
    assert all(hasattr(pact, name) for name in pact.__all__)
