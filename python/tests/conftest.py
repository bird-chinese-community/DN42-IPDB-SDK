import pytest
from support import fixture_server


@pytest.fixture
def server():
    with fixture_server() as served:
        yield served
