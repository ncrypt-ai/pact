from importlib.metadata import version

import pact


def test_version() -> None:
    assert pact.__version__ == version("pact")
